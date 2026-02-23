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
    std::string name;
    uintptr_t base = 0;
    size_t size = 0;
};

static gboolean collect_module(GumModule* module, gpointer user_data) {
    auto* out = reinterpret_cast<std::vector<ModuleInfo>*>(user_data);
    if (!out || !module) return true;

    const GumMemoryRange* range = gum_module_get_range(module);
    if (!range || range->base_address == 0 || range->size == 0) return true;

    std::string path;
    if (const gchar* path_c = gum_module_get_path(module); path_c && path_c[0] != '\0') {
        path = path_c;
    }
    std::string name;
    if (const gchar* name_c = gum_module_get_name(module); name_c && name_c[0] != '\0') {
        name = name_c;
    }

    out->push_back(ModuleInfo{
        .path = std::move(path),
        .name = std::move(name),
        .base = range->base_address,
        .size = range->size,
    });
    return true;
}

static void enumerate_and_dump_now(const std::string& package_name,
                                   bool fix,
                                   const std::string& so_name) {
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

    size_t selected = 0;

    for (const auto& m : mods) {
        const char* id = nullptr;
        if (!m.path.empty()) id = m.path.c_str();
        else if (!m.name.empty()) id = m.name.c_str();
        if (!so_name.empty()) {
            bool ok = false;
            if (!m.path.empty() && m.path.find(so_name) != std::string::npos) ok = true;
            if (!ok && !m.name.empty() && m.name.find(so_name) != std::string::npos) ok = true;
            if (!ok) continue;
        }
        selected++;
        dumpso::dump_module(package_name, id, m.base, m.size, fix);
    }
    LOGI("Enumerated %zu modules, selected %zu to dump", mods.size(), selected);
}

} // namespace

void enumerate_and_dump_after_delay(const std::string& package_name,
                                    uint32_t delay_us,
                                    bool fix,
                                    const std::string& so_name) {
    std::thread([package_name, delay_us, fix, so_name]() {
        if (delay_us > 0) usleep(delay_us);
        enumerate_and_dump_now(package_name, fix, so_name);
    }).detach();
}

} // namespace dumpso

