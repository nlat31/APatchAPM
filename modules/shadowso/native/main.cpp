#include <cstring>
#include <cctype>
#include <string>
#include <vector>
#include <unistd.h>
#include <sys/stat.h>
#include <android/log.h>

#include "zygisk.hpp"
#include "native_hook.h"
#include "java_hook.h"
#include "shadow_loader.h"
#include "maps_hook.h"
#include "phdr_hook.h"
#include "dladdr_hook.h"

#ifndef ZMOD_ID
#define ZMOD_ID "shadowso"
#endif

#define LOG_TAG    "shadowso"
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// ========================================================================
//  Zygisk 模块实现
// ========================================================================

static std::vector<uint8_t> g_dex_data;

struct ModuleConfig {
    bool enabled = false;
    bool hook_native = false;
    bool hook_java = false;
    bool opt_maps_redirect = false;
    bool opt_hook_phdr = false;
    bool opt_hook_dladdr = false;
    std::vector<std::string> packages;
    std::vector<std::string> hide_so;
    time_t mtime = 0;
    bool loaded = false;
};

static std::string config_path() {
    return std::string("/data/adb/modules/") + ZMOD_ID + "/config.json";
}

static bool read_file(const std::string &path, std::string &out) {
    FILE *fp = fopen(path.c_str(), "rb");
    if (!fp) return false;
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (size <= 0) {
        fclose(fp);
        return false;
    }
    out.resize((size_t)size);
    size_t n = fread(out.data(), 1, out.size(), fp);
    fclose(fp);
    if (n != out.size()) return false;
    return true;
}

static void skip_ws(const std::string &s, size_t &i) {
    while (i < s.size() && std::isspace((unsigned char)s[i])) i++;
}

static bool parse_bool_by_key(const std::string &s, const char *key, bool def) {
    std::string pat = std::string("\"") + key + "\"";
    size_t pos = s.find(pat);
    if (pos == std::string::npos) return def;
    pos = s.find(':', pos + pat.size());
    if (pos == std::string::npos) return def;
    pos++;
    while (pos < s.size() && std::isspace((unsigned char)s[pos])) pos++;
    if (s.compare(pos, 4, "true") == 0) return true;
    if (s.compare(pos, 5, "false") == 0) return false;
    return def;
}

static bool parse_json_string(const std::string &s, size_t &i, std::string &out) {
    skip_ws(s, i);
    if (i >= s.size() || s[i] != '"') return false;
    i++; // skip "
    std::string r;
    while (i < s.size()) {
        char c = s[i++];
        if (c == '"') {
            out = std::move(r);
            return true;
        }
        if (c == '\\' && i < s.size()) {
            char e = s[i++];
            switch (e) {
                case '"': r.push_back('"'); break;
                case '\\': r.push_back('\\'); break;
                case '/': r.push_back('/'); break;
                case 'b': r.push_back('\b'); break;
                case 'f': r.push_back('\f'); break;
                case 'n': r.push_back('\n'); break;
                case 'r': r.push_back('\r'); break;
                case 't': r.push_back('\t'); break;
                default:
                    // Keep unknown escape as-is.
                    r.push_back(e);
                    break;
            }
            continue;
        }
        r.push_back(c);
    }
    return false;
}

static std::vector<std::string> parse_string_array_by_key(const std::string &s, const char *key) {
    std::vector<std::string> res;
    std::string pat = std::string("\"") + key + "\"";
    size_t pos = s.find(pat);
    if (pos == std::string::npos) return res;
    pos = s.find('[', pos + pat.size());
    if (pos == std::string::npos) return res;
    pos++; // after [

    while (pos < s.size()) {
        skip_ws(s, pos);
        if (pos < s.size() && s[pos] == ']') break;

        std::string v;
        if (!parse_json_string(s, pos, v)) {
            // Skip until next comma or closing bracket to be tolerant.
            while (pos < s.size() && s[pos] != ',' && s[pos] != ']') pos++;
        } else {
            if (!v.empty()) res.push_back(std::move(v));
        }

        skip_ws(s, pos);
        if (pos < s.size() && s[pos] == ',') pos++;
    }
    return res;
}

static bool matches_any_package(const std::string &process_name, const std::vector<std::string> &pkgs) {
    for (const auto &p : pkgs) {
        if (p.empty()) continue;
        // Prefix match so one package entry can cover its child process names.
        // Typical Android process names:
        // - com.example.app
        // - com.example.app:remote
        // Some ROMs / components may also use dot-suffixed names.
        if (process_name == p) return true;
        if (process_name.size() > p.size() && process_name.compare(0, p.size(), p) == 0) {
            char next = process_name[p.size()];
            if (next == ':' || next == '.') return true;
        }
    }
    return false;
}

static const ModuleConfig &load_config_cached() {
    static ModuleConfig cfg;

    struct stat st {};
    const std::string path = config_path();
    if (stat(path.c_str(), &st) != 0) {
        // After postAppSpecialize the process UID may become the target app UID,
        // which typically cannot access /data/adb. If we already loaded config
        // earlier (while still privileged), keep the cached config instead of
        // falling back to "disabled".
        if (cfg.loaded) return cfg;

        // No config (or can't access it) -> default: disable for all apps.
        cfg = ModuleConfig{};
        cfg.loaded = true;
        return cfg;
    }

    if (cfg.loaded && cfg.mtime == st.st_mtime) {
        return cfg;
    }

    std::string json;
    if (!read_file(path, json)) {
        LOGW("Failed to read config: %s", path.c_str());
        cfg = ModuleConfig{};
        cfg.loaded = true;
        cfg.mtime = st.st_mtime;
        return cfg;
    }

    ModuleConfig next;
    next.loaded = true;
    next.mtime = st.st_mtime;
    next.enabled = parse_bool_by_key(json, "enabled", false);
    // If user didn't write hook_native/hook_java, default to enabled.
    next.hook_native = next.enabled && parse_bool_by_key(json, "hook_native", false);
    next.hook_java = next.enabled && parse_bool_by_key(json, "hook_java", false);
    next.opt_maps_redirect = parse_bool_by_key(json, "opt_maps_redirect", false);
    next.opt_hook_phdr = parse_bool_by_key(json, "opt_hook_phdr", false);
    next.opt_hook_dladdr = parse_bool_by_key(json, "opt_hook_dladdr", false);
    next.packages = parse_string_array_by_key(json, "packages");
    next.hide_so = parse_string_array_by_key(json, "hide_so");

    cfg = std::move(next);
    return cfg;
}

static void load_dex_data() {
    std::vector<std::string> paths;
    paths.emplace_back(std::string("/data/adb/modules/") + ZMOD_ID + "/classes.dex");
    paths.emplace_back(std::string("/data/local/tmp/") + ZMOD_ID + "/classes.dex"); // Dev fallback
    paths.emplace_back("/data/local/tmp/classes.dex"); // Dev fallback

    for (const auto &path : paths) {
        FILE *fp = fopen(path.c_str(), "rb");
        if (fp) {
            fseek(fp, 0, SEEK_END);
            long size = ftell(fp);
            fseek(fp, 0, SEEK_SET);

            if (size > 0) {
                g_dex_data.resize(size);
                fread(g_dex_data.data(), 1, size, fp);
                LOGI("Loaded DEX from %s (size: %ld)", path.c_str(), size);
                fclose(fp);
                return;
            }
            fclose(fp);
        }
    }
    LOGW("Failed to load classes.dex from known paths");
}

class SampleModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api_ = api;
        this->env_ = env;
        LOGI("onLoad(%s): pid=%d uid=%d", ZMOD_ID, getpid(), getuid());

        // Load DEX in Zygote process so it's available to all forked apps
        if (g_dex_data.empty()) {
            load_dex_data();
        }
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        const char *nice_name = env_->GetStringUTFChars(args->nice_name, nullptr);
        std::string proc = nice_name ? nice_name : "";
        LOGI("preAppSpecialize(%s): pid=%d nice_name=%s target_uid=%d",
             ZMOD_ID, getpid(), nice_name ? nice_name : "null", args->uid);

        const auto &cfg = load_config_cached();
        // Respect UI config: allow both user apps and system apps as long as they are selected.
        // (UI can toggle "show system apps" and write them into packages.)
        should_inject_ = matches_any_package(proc, cfg.packages);
        hooks_enabled_ = should_inject_ && cfg.enabled;
        hook_native_ = hooks_enabled_ && cfg.hook_native;
        hook_java_ = hooks_enabled_ && cfg.hook_java;
        LOGI("[%s][core] match=%d enabled=%d hook_native=%d hook_java=%d",
             ZMOD_ID, should_inject_ ? 1 : 0, cfg.enabled ? 1 : 0, hook_native_ ? 1 : 0, hook_java_ ? 1 : 0);

        if (nice_name) {
            env_->ReleaseStringUTFChars(args->nice_name, nice_name);
        }

        if (!should_inject_ || !cfg.enabled) {
            api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (!should_inject_) return;

        LOGI("[%s][core] postAppSpecialize: pid=%d inject ok", ZMOD_ID, getpid());

        const auto &cfg = load_config_cached();
        if (!cfg.enabled) {
            LOGI("[%s][core] hooks disabled by master switch; skip all hooks", ZMOD_ID);
            return;
        }

        if (cfg.opt_maps_redirect) {
            // Hook file open as early as possible (before other code that may read /proc/self/maps).
            const char *data_dir = env_->GetStringUTFChars(args->app_data_dir, nullptr);
            std::string pkg;
            std::string app_data_dir;
            if (data_dir) {
                std::string s = data_dir;
                if (!s.empty() && s.back() == '/') s.pop_back();
                app_data_dir = s;
                size_t slash = s.find_last_of('/');
                if (slash != std::string::npos && slash + 1 < s.size()) {
                    pkg = s.substr(slash + 1);
                }
                env_->ReleaseStringUTFChars(args->app_data_dir, data_dir);
            }
            if (!pkg.empty()) {
                if (!sample::maps_hook::install(pkg, app_data_dir)) {
                    LOGE("[%s][core] maps_hook install failed; stop", ZMOD_ID);
                    return;
                }
            } else {
                LOGE("[%s][core] failed to parse package from app_data_dir; stop", ZMOD_ID);
                return;
            }
        }

        // Must run as early as possible after fork, before app code executes:
        // enumerate already-loaded modules and shadow-load configured targets,
        // then hook do_dlopen for late-loaded targets.
        LOGI("[%s][core] shadow_loader initialize...", ZMOD_ID);
        if (!sample::shadow_loader::initialize(cfg.hide_so)) {
            LOGE("[%s][core] shadow_loader initialize failed; stop", ZMOD_ID);
            return;
        }
        if (cfg.opt_hook_phdr) {
            LOGI("[%s][core] install dl_iterate_phdr hook...", ZMOD_ID);
            if (!sample::phdr_hook::install()) {
                LOGE("[%s][core] phdr_hook install failed; stop", ZMOD_ID);
                return;
            }
        }
        if (cfg.opt_hook_dladdr) {
            LOGI("[%s][core] install dladdr hook...", ZMOD_ID);
            if (!sample::dladdr_hook::install()) {
                LOGE("[%s][core] dladdr_hook install failed; stop", ZMOD_ID);
                return;
            }
        }

        if (hook_native_) {
            LOGI("[%s][core] install native hooks...", ZMOD_ID);
            if (!sample::native_hook::install_hooks(cfg.hide_so)) {
                LOGE("[%s][core] native hooks install failed; stop", ZMOD_ID);
                return;
            }
        }

        if (hook_java_) {
            LOGI("[%s][core] install java hooks...", ZMOD_ID);
            if (!sample::java_hook::initialize(env_)) {
                LOGE("[%s][core] java_hook initialize failed; stop", ZMOD_ID);
                return;
            }
            if (!sample::java_hook::install_hooks(env_, g_dex_data)) {
                LOGE("[%s][core] java_hook install failed; stop", ZMOD_ID);
                return;
            }
        }
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs * /*args*/) override {
        api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

private:
    zygisk::Api *api_ = nullptr;
    JNIEnv      *env_ = nullptr;
    bool         should_inject_ = false;
    bool         hooks_enabled_ = false;
    bool         hook_native_ = false;
    bool         hook_java_ = false;
};

REGISTER_ZYGISK_MODULE(SampleModule)

