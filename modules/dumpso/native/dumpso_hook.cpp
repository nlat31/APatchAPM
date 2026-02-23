#include "dumpso_hook.h"

#include <android/dlext.h>
#include <android/log.h>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <unistd.h>
#include <unordered_set>

#include "frida-gum.h"

#include "dumpso_dump.h"

#ifndef ZMOD_ID
#define ZMOD_ID "dumpso"
#endif

#define LOG_TAG    "DumpSo/Hook"
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

namespace dumpso {
namespace {

#define HOOK_DEF(ret, func, ...)         \
    ret (*old_##func)(__VA_ARGS__) = nullptr; \
    ret new_##func(__VA_ARGS__)

struct HookState {
    std::string package;
    HookOptions opts;
    std::mutex mu;
    std::unordered_set<uintptr_t> dumped_bases;
};

static HookState g_state;

static bool should_dump_name(const char* name) {
    if (!g_state.opts.so_name.empty()) {
        if (!name) return false;
        return strstr(name, g_state.opts.so_name.c_str()) != nullptr;
    }
    // Empty so_name means dump all libraries triggered by do_dlopen.
    return true;
}

static void do_dump_for_name(const char* name) {
    if (g_state.opts.watch) {
        LOGI("loaded library: %s", name ? name : "null");
    }

    if (!should_dump_name(name)) return;

    const char* module_name = name;
    if (!module_name || module_name[0] == '\0') return;
    if (const char* slash = strrchr(name, '/'); slash != nullptr && slash[1] != '\0') {
        module_name = slash + 1;
    }

    GumModule* module = gum_process_find_module_by_name(module_name);
    if (!module && module_name != name) {
        module = gum_process_find_module_by_name(name);
    }
    if (!module) return;

    const GumMemoryRange* range = gum_module_get_range(module);
    if (!range) {
        g_object_unref(module);
        return;
    }

    // Copy values out of the GumModule object. We may dump much later (delay_us),
    // so we must not capture pointers owned by GumModule/range.
    const uintptr_t base = range->base_address;
    const size_t size = range->size;
    const gchar* path = gum_module_get_path(module);
    const std::string dump_path = (path != nullptr) ? std::string(path) : std::string(module_name);
    const std::string package = g_state.package;
    const bool fix = g_state.opts.fix;
    const uint32_t delay_us = g_state.opts.delay_us;

    {
        std::lock_guard<std::mutex> lk(g_state.mu);
        if (g_state.dumped_bases.find(base) != g_state.dumped_bases.end()) {
            g_object_unref(module);
            return;
        }
        g_state.dumped_bases.insert(base);
    }
    g_object_unref(module);

    auto dump_once = [package, dump_path, base, size, fix]() {
        dumpso::dump_module(package, dump_path.c_str(), base, size, fix);
    };

    if (delay_us > 0) {
        std::thread([dump_once, delay_us]() {
            usleep(delay_us);
            dump_once();
        }).detach();
    } else {
        dump_once();
    }
}

HOOK_DEF(void*, do_dlopen, const char* name, int flags, const android_dlextinfo* extinfo, const void* caller_addr)
{
    void* handle = old_do_dlopen ? old_do_dlopen(name, flags, extinfo, caller_addr) : nullptr;
    if (handle != nullptr) {
        do_dump_for_name(name);
    }
    return handle;
}

static bool replace_fast(GumAddress target_addr, const char* what) {
    GumInterceptor* interceptor = gum_interceptor_obtain();
    gum_interceptor_begin_transaction(interceptor);

    GumReplaceReturn ret = gum_interceptor_replace_fast(
        interceptor,
        GSIZE_TO_POINTER(target_addr),
        GSIZE_TO_POINTER(new_do_dlopen),
        reinterpret_cast<void**>(&old_do_dlopen)
    );

    gum_interceptor_end_transaction(interceptor);
    if (ret == GUM_REPLACE_OK) {
        LOGI("%s replaced @ %p", what, reinterpret_cast<void*>(static_cast<uintptr_t>(target_addr)));
        return true;
    }
    LOGE("%s replace failed (%d) @ %p", what, static_cast<int>(ret),
         reinterpret_cast<void*>(static_cast<uintptr_t>(target_addr)));
    return false;
}

} // namespace

void install_dlopen_hook(const std::string& package_name, const HookOptions& opts) {
    g_state.package = package_name;
    g_state.opts = opts;
    {
        std::lock_guard<std::mutex> lk(g_state.mu);
        g_state.dumped_bases.clear();
    }

    gum_init_embedded();

#if defined(__LP64__)
    const char* linker = "linker64";
#else
    const char* linker = "linker";
#endif
    const std::string do_dlopen_sym = "__dl__Z9do_dlopenPKciPK17android_dlextinfoPKv";
    GumModule* linker_module = gum_process_find_module_by_name(linker);
    if (!linker_module) {
        LOGE("linker module not found: %s", linker);
        return;
    }
    GumAddress addr = gum_module_find_symbol_by_name(linker_module, do_dlopen_sym.c_str());
    g_object_unref(linker_module);
    if (addr == 0) {
        LOGE("do_dlopen symbol not found in %s", linker);
        return;
    }
    (void) replace_fast(addr, "do_dlopen");
}

} // namespace dumpso

