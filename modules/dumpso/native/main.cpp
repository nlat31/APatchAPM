#include <android/log.h>
#include <cctype>
#include <cstring>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include "zygisk.hpp"
#include "dumpso_hook.h"
#include "dumpso_enum.h"

#ifndef ZMOD_ID
#define ZMOD_ID "dumpso"
#endif

#define LOG_TAG    "DumpSo"
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace {

struct DumpSoConfig {
    bool watch = false;
    bool fix = true;
    uint32_t delay_us = 0;
    uint32_t enum_delay_us = 0;
    std::string dump_mode;
    std::string so_name;
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
    return n == out.size();
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
                default: r.push_back(e); break;
            }
            continue;
        }
        r.push_back(c);
    }
    return false;
}

static std::string parse_string_by_key(const std::string &s, const char *key, const std::string &def) {
    std::string pat = std::string("\"") + key + "\"";
    size_t pos = s.find(pat);
    if (pos == std::string::npos) return def;
    pos = s.find(':', pos + pat.size());
    if (pos == std::string::npos) return def;
    pos++;
    size_t i = pos;
    std::string out;
    if (parse_json_string(s, i, out)) return out;
    return def;
}

static uint32_t parse_uint_by_key(const std::string &s, const char *key, uint32_t def) {
    std::string pat = std::string("\"") + key + "\"";
    size_t pos = s.find(pat);
    if (pos == std::string::npos) return def;
    pos = s.find(':', pos + pat.size());
    if (pos == std::string::npos) return def;
    pos++;
    while (pos < s.size() && std::isspace((unsigned char)s[pos])) pos++;
    char *end = nullptr;
    unsigned long v = strtoul(s.c_str() + pos, &end, 10);
    if (end == s.c_str() + pos) return def;
    if (v > 0xFFFFFFFFul) return def;
    return static_cast<uint32_t>(v);
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
        if (process_name == p) return true;
        if (process_name.size() > p.size() && process_name.compare(0, p.size(), p) == 0) {
            char next = process_name[p.size()];
            if (next == ':' || next == '.') return true;
        }
    }
    return false;
}

static std::string base_package_name(std::string proc) {
    size_t pos = proc.find(':');
    if (pos != std::string::npos) proc.resize(pos);
    return proc;
}

static const DumpSoConfig &load_config_cached() {
    static DumpSoConfig cfg;
    struct stat st {};
    const std::string path = config_path();
    if (stat(path.c_str(), &st) != 0) {
        cfg = DumpSoConfig{};
        cfg.loaded = true;
        return cfg;
    }
    if (cfg.loaded && cfg.mtime == st.st_mtime) return cfg;

    std::string json;
    if (!read_file(path, json)) {
        LOGW("Failed to read config: %s", path.c_str());
        cfg = DumpSoConfig{};
        cfg.loaded = true;
        cfg.mtime = st.st_mtime;
        return cfg;
    }

    DumpSoConfig next;
    next.loaded = true;
    next.mtime = st.st_mtime;
    next.packages = parse_string_array_by_key(json, "packages");

    // Optional dumpso params (can be edited manually for now)
    next.dump_mode = parse_string_by_key(json, "dump_mode", "hook");
    next.watch = parse_bool_by_key(json, "watch", false);
    next.fix = parse_bool_by_key(json, "fix", true);
    next.delay_us = parse_uint_by_key(json, "delay_us", 0);
    if (next.delay_us == 0) next.delay_us = parse_uint_by_key(json, "delay", 0);
    next.enum_delay_us = parse_uint_by_key(json, "enum_delay_us", 0);
    if (next.enum_delay_us == 0) next.enum_delay_us = parse_uint_by_key(json, "enum_delay", 0);
    next.so_name = parse_string_by_key(json, "so_name", "");

    cfg = std::move(next);
    return cfg;
}

} // namespace

class DumpSoModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override { api_ = api; env_ = env; }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        if (!args || !args->nice_name) {
            api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        const char *nice_name = env_->GetStringUTFChars(args->nice_name, nullptr);
        std::string proc = nice_name ? nice_name : "";
        if (nice_name) env_->ReleaseStringUTFChars(args->nice_name, nice_name);

        const auto &cfg = load_config_cached();
        should_inject_ = matches_any_package(proc, cfg.packages);
        if (!should_inject_) {
            api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        base_pkg_ = base_package_name(proc);
        cfg_ = cfg;

        // Two independent dump modes:
        // - hook: install do_dlopen hook (delayed dump supported via delay_us)
        // - enumerate: do NOT install hook; enumerate and dump after enum_delay_us
        if (cfg_.dump_mode == "hook" || cfg_.dump_mode.empty()) {
            dumpso::HookOptions opts{
                .watch = cfg_.watch,
                .fix = cfg_.fix,
                .delay_us = cfg_.delay_us,
                .so_name = cfg_.so_name,
            };
            dumpso::install_dlopen_hook(base_pkg_, opts);
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs * /*args*/) override {
        if (!should_inject_) return;
        if (cfg_.dump_mode == "enumerate") {
            dumpso::enumerate_and_dump_after_delay(base_pkg_, cfg_.enum_delay_us, cfg_.fix, cfg_.so_name);
        }
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs * /*args*/) override {
        api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

private:
    zygisk::Api *api_ = nullptr;
    JNIEnv      *env_ = nullptr;
    bool         should_inject_ = false;
    std::string  base_pkg_;
    DumpSoConfig cfg_{};
};

REGISTER_ZYGISK_MODULE(DumpSoModule)
