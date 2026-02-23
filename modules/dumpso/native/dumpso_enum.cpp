#include "dumpso_enum.h"

#include <android/log.h>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

#include "frida-gum.h"

#include "dumpso_dump.h"

#ifndef ZMOD_ID
#define ZMOD_ID "dumpso"
#endif

#define LOG_TAG    "DumpSo/Enum"
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace dumpso {
namespace {

struct ModuleInfo {
    std::string path;
    uintptr_t base = 0;
    size_t size = 0;
};

static bool ends_with_so(const std::string& s) {
    if (s.size() < 3) return false;
    auto lower = [](unsigned char c) { return static_cast<char>(std::tolower(c)); };
    char a = lower(static_cast<unsigned char>(s[s.size() - 3]));
    char b = lower(static_cast<unsigned char>(s[s.size() - 2]));
    char c = lower(static_cast<unsigned char>(s[s.size() - 1]));
    return a == '.' && b == 's' && c == 'o';
}

static bool should_skip_path(const std::string& path) {
    if (path.empty()) return true;
    // Avoid dumping our own module and other Magisk module libs.
    if (path.find("/data/adb/modules/") != std::string::npos) return true;
    return false;
}

static gboolean collect_module(GumModule* module, gpointer user_data) {
    auto* out = reinterpret_cast<std::vector<ModuleInfo>*>(user_data);
    if (!out || !module) return true;

    const gchar* path_c = gum_module_get_path(module);
    if (!path_c || path_c[0] == '\0') return true;
    std::string path(path_c);
    if (should_skip_path(path)) return true;
    if (!ends_with_so(path)) return true;

    const GumMemoryRange* range = gum_module_get_range(module);
    if (!range || range->base_address == 0 || range->size == 0) return true;

    out->push_back(ModuleInfo{
        .path = std::move(path),
        .base = range->base_address,
        .size = range->size,
    });
    return true;
}

static void enumerate_and_dump_now(const std::string& package_name, bool fix) {
    gum_init_embedded();

    std::vector<ModuleInfo> mods;
    mods.reserve(128);
    gum_process_enumerate_modules(collect_module, &mods);

    // Deduplicate by base address.
    std::sort(mods.begin(), mods.end(), [](const ModuleInfo& a, const ModuleInfo& b) {
        return a.base < b.base;
    });
    mods.erase(std::unique(mods.begin(), mods.end(), [](const ModuleInfo& a, const ModuleInfo& b) {
        return a.base == b.base;
    }), mods.end());

    LOGI("Enumerated %zu .so modules to dump", mods.size());

    for (const auto& m : mods) {
        dumpso::dump_module(package_name, m.path.c_str(), m.base, m.size, fix);
    }
}

} // namespace

void enumerate_and_dump_after_delay(const std::string& package_name,
                                    uint32_t delay_us,
                                    bool fix) {
    std::thread([package_name, delay_us, fix]() {
        if (delay_us > 0) usleep(delay_us);
        enumerate_and_dump_now(package_name, fix);
    }).detach();
}

} // namespace dumpso

