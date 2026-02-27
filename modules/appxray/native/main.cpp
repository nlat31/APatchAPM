#include <cstring>
#include <cctype>
#include <string>
#include <vector>
#include <unistd.h>
#include <sys/stat.h>
#include <android/log.h>

#include "zygisk.hpp"
#include "native_hook.h"

#ifndef ZMOD_ID
#define ZMOD_ID "appxray"
#endif

#define LOG_TAG    "appxray"
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// ========================================================================
//  Zygisk 模块实现
// ========================================================================

struct ModuleConfig {
    bool file_monitor_enabled = false;
    bool dl_monitor_enabled = false;
    std::string file_names;
    std::vector<std::string> packages;
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

static std::string parse_string_by_key(const std::string &s, const char *key, const char *def) {
    std::string pat = std::string("\"") + key + "\"";
    size_t pos = s.find(pat);
    if (pos == std::string::npos) return def ? std::string(def) : std::string();
    pos = s.find(':', pos + pat.size());
    if (pos == std::string::npos) return def ? std::string(def) : std::string();
    pos++;
    std::string v;
    size_t i = pos;
    if (parse_json_string(s, i, v)) return v;
    return def ? std::string(def) : std::string();
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
        // No config -> default: disable for all apps.
        cfg = ModuleConfig{};
        cfg.loaded = true;
        return cfg;
    }

    if (cfg.loaded && cfg.mtime == st.st_mtime) {
        return cfg;
    }

    std::string json;
    if (!read_file(path, json)) {
        // Silent on non-target processes: config read failure just disables module.
        cfg = ModuleConfig{};
        cfg.loaded = true;
        cfg.mtime = st.st_mtime;
        return cfg;
    }

    ModuleConfig next;
    next.loaded = true;
    next.mtime = st.st_mtime;
    next.file_monitor_enabled = parse_bool_by_key(json, "file_monitor_enabled", false);
    next.dl_monitor_enabled = parse_bool_by_key(json, "dl_monitor_enabled", false);
    next.file_names = parse_string_by_key(json, "file_names", "");
    next.packages = parse_string_array_by_key(json, "packages");

    cfg = std::move(next);
    return cfg;
}

class AppXrayModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api_ = api;
        this->env_ = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        const char *nice_name = env_->GetStringUTFChars(args->nice_name, nullptr);
        std::string proc = nice_name ? nice_name : "";

        const auto &cfg = load_config_cached();
        // Respect UI config: allow both user apps and system apps as long as they are selected.
        // (UI can toggle "show system apps" and write them into packages.)
        should_inject_ = matches_any_package(proc, cfg.packages);
        file_monitor_enabled_ = should_inject_ && cfg.file_monitor_enabled;
        dl_monitor_enabled_ = should_inject_ && cfg.dl_monitor_enabled;
        file_names_ = cfg.file_names;
        package_name_ = proc;
        auto colon = package_name_.find(':');
        if (colon != std::string::npos) package_name_.resize(colon);
        auto dot = package_name_.find('.');
        if (dot == std::string::npos) package_name_.clear();

        if (nice_name) {
            env_->ReleaseStringUTFChars(args->nice_name, nice_name);
        }

        if (!should_inject_) {
            api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs * /*args*/) override {
        if (!should_inject_) return;

        if (file_monitor_enabled_ || dl_monitor_enabled_) {
            appxray::native_hook::install_hooks(
                package_name_.c_str(),
                file_names_.c_str(),
                file_monitor_enabled_,
                dl_monitor_enabled_
            );
        }
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs * /*args*/) override {
        api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

private:
    zygisk::Api *api_ = nullptr;
    JNIEnv      *env_ = nullptr;
    bool         should_inject_ = false;
    bool         file_monitor_enabled_ = false;
    bool         dl_monitor_enabled_ = false;
    std::string  file_names_;
    std::string  package_name_;
};

REGISTER_ZYGISK_MODULE(AppXrayModule)

