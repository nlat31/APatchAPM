#include "config.h"

#include <cctype>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

#include <android/log.h>

#define LOG_TAG    "EnvCloak/Config"
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)

namespace envcloak {
namespace config {

static constexpr const char *kModId = "envcloak";
static constexpr const char *kConfigPath = "/data/adb/modules/envcloak/config.json";

static std::string read_text_file(const char *path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return {};

    std::string out;
    char buf[4096];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n == 0) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            out.clear();
            break;
        }
        out.append(buf, buf + n);
        if (out.size() > (1u << 20)) { // 1MB safety cap
            out.clear();
            break;
        }
    }
    close(fd);
    return out;
}

static void skip_ws(const std::string &s, size_t &i) {
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) i++;
}

static bool consume(const std::string &s, size_t &i, const char *lit) {
    size_t n = std::strlen(lit);
    if (i + n > s.size()) return false;
    if (s.compare(i, n, lit) != 0) return false;
    i += n;
    return true;
}

static bool parse_json_string(const std::string &s, size_t &i, std::string &out) {
    skip_ws(s, i);
    if (i >= s.size() || s[i] != '"') return false;
    i++; // "
    std::string r;
    while (i < s.size()) {
        char c = s[i++];
        if (c == '"') {
            out = std::move(r);
            return true;
        }
        if (c == '\\') {
            if (i >= s.size()) return false;
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
                case 'u':
                    // Minimal parser: ignore unicode escapes (treat as failure).
                    return false;
                default:
                    return false;
            }
        } else {
            r.push_back(c);
        }
    }
    return false;
}

static bool parse_json_bool(const std::string &s, size_t &i, bool &out) {
    skip_ws(s, i);
    if (consume(s, i, "true")) {
        out = true;
        return true;
    }
    if (consume(s, i, "false")) {
        out = false;
        return true;
    }
    return false;
}

static bool parse_json_int(const std::string &s, size_t &i, int &out) {
    skip_ws(s, i);
    bool neg = false;
    if (i < s.size() && s[i] == '-') {
        neg = true;
        i++;
    }
    if (i >= s.size() || !std::isdigit(static_cast<unsigned char>(s[i]))) return false;
    long v = 0;
    while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) {
        v = v * 10 + (s[i] - '0');
        if (v > 1000000) break;
        i++;
    }
    out = static_cast<int>(neg ? -v : v);
    return true;
}

static bool find_key(const std::string &s, const char *key, size_t &pos_out) {
    std::string needle = "\"";
    needle += key;
    needle += "\"";
    size_t pos = s.find(needle);
    if (pos == std::string::npos) return false;
    pos += needle.size();
    pos_out = pos;
    return true;
}

static bool parse_value_after_colon(const std::string &s, size_t &i) {
    skip_ws(s, i);
    if (i >= s.size() || s[i] != ':') return false;
    i++;
    return true;
}

static void parse_packages_array(const std::string &s, size_t i, std::unordered_set<std::string> &out) {
    if (!parse_value_after_colon(s, i)) return;
    skip_ws(s, i);
    if (i >= s.size() || s[i] != '[') return;
    i++; // [
    for (;;) {
        skip_ws(s, i);
        if (i >= s.size()) return;
        if (s[i] == ']') {
            i++;
            return;
        }
        std::string v;
        if (!parse_json_string(s, i, v)) return;
        if (!v.empty()) out.insert(v);
        skip_ws(s, i);
        if (i < s.size() && s[i] == ',') {
            i++;
            continue;
        }
        if (i < s.size() && s[i] == ']') {
            i++;
            return;
        }
        return;
    }
}

Config read_config() {
    Config cfg;

    std::string txt = read_text_file(kConfigPath);
    if (txt.empty()) {
        LOGI("Config missing/empty: %s", kConfigPath);
        return cfg;
    }

    // packages
    {
        size_t pos;
        if (find_key(txt, "packages", pos)) {
            parse_packages_array(txt, pos, cfg.packages);
        }
    }
    // version
    {
        size_t pos;
        if (find_key(txt, "version", pos)) {
            size_t i = pos;
            if (parse_value_after_colon(txt, i)) {
                int v = 1;
                if (parse_json_int(txt, i, v)) cfg.version = v;
            }
        }
    }
    // installer_spoof_enabled
    {
        size_t pos;
        if (find_key(txt, "installer_spoof_enabled", pos)) {
            size_t i = pos;
            if (parse_value_after_colon(txt, i)) {
                bool b = false;
                if (parse_json_bool(txt, i, b)) cfg.installer_spoof_enabled = b;
            }
        }
    }
    // installer_package
    {
        size_t pos;
        if (find_key(txt, "installer_package", pos)) {
            size_t i = pos;
            if (parse_value_after_colon(txt, i)) {
                std::string v;
                if (parse_json_string(txt, i, v) && !v.empty()) cfg.installer_package = v;
            }
        }
    }
    // hide_dev_options_enabled
    {
        size_t pos;
        if (find_key(txt, "hide_dev_options_enabled", pos)) {
            size_t i = pos;
            if (parse_value_after_colon(txt, i)) {
                bool b = false;
                if (parse_json_bool(txt, i, b)) cfg.hide_dev_options_enabled = b;
            }
        }
    }

    // temp/ImNotADeveloper split flags
    {
        size_t pos;
        if (find_key(txt, "hide_developer_mode", pos)) {
            size_t i = pos;
            if (parse_value_after_colon(txt, i)) {
                bool b = cfg.hide_developer_mode;
                if (parse_json_bool(txt, i, b)) cfg.hide_developer_mode = b;
            }
        }
    }
    {
        size_t pos;
        if (find_key(txt, "hide_usb_debug", pos)) {
            size_t i = pos;
            if (parse_value_after_colon(txt, i)) {
                bool b = cfg.hide_usb_debug;
                if (parse_json_bool(txt, i, b)) cfg.hide_usb_debug = b;
            }
        }
    }
    {
        size_t pos;
        if (find_key(txt, "hide_wireless_debug", pos)) {
            size_t i = pos;
            if (parse_value_after_colon(txt, i)) {
                bool b = cfg.hide_wireless_debug;
                if (parse_json_bool(txt, i, b)) cfg.hide_wireless_debug = b;
            }
        }
    }
    {
        size_t pos;
        if (find_key(txt, "hide_debug_properties", pos)) {
            size_t i = pos;
            if (parse_value_after_colon(txt, i)) {
                bool b = cfg.hide_debug_properties;
                if (parse_json_bool(txt, i, b)) cfg.hide_debug_properties = b;
            }
        }
    }
    {
        size_t pos;
        if (find_key(txt, "hide_debug_properties_in_native", pos)) {
            size_t i = pos;
            if (parse_value_after_colon(txt, i)) {
                bool b = cfg.hide_debug_properties_in_native;
                if (parse_json_bool(txt, i, b)) cfg.hide_debug_properties_in_native = b;
            }
        }
    }

    // Master switch: when off, disable all split flags (match temp's per-feature early returns).
    if (!cfg.hide_dev_options_enabled) {
        cfg.hide_developer_mode = false;
        cfg.hide_usb_debug = false;
        cfg.hide_wireless_debug = false;
        cfg.hide_debug_properties = false;
        cfg.hide_debug_properties_in_native = false;
    }

    LOGI("Config loaded: pkgs=%zu installer_spoof=%d hide_dev=%d installer_pkg=%s",
         cfg.packages.size(),
         cfg.installer_spoof_enabled ? 1 : 0,
         cfg.hide_dev_options_enabled ? 1 : 0,
         cfg.installer_package.c_str());
    return cfg;
}

std::string process_name_to_package(const char *nice_name) {
    if (!nice_name) return {};
    std::string n{nice_name};
    if (n.empty()) return {};
    // Trim trailing '\0' artifacts if any
    while (!n.empty() && n.back() == '\0') n.pop_back();
    if (n.empty()) return {};
    size_t colon = n.find(':');
    if (colon != std::string::npos) n.resize(colon);
    return n;
}

} // namespace config
} // namespace envcloak

