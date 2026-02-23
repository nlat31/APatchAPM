#include "dumpso_hook.h"

#include <android/dlext.h>
#include <android/log.h>
#include <cstring>
#include <regex.h>
#include <string>
#include <thread>
#include <unistd.h>

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
    bool did_dump = false;
    bool regex_ok = false;
    bool regex_inited = false;
    regex_t regex{};
};

static HookState g_state;

static bool should_dump_name(const char* name) {
    if (!name) return false;
    if (g_state.regex_ok) {
        // Use EXTENDED regex syntax; full match semantics: ^...$ can be provided by user.
        return regexec(&g_state.regex, name, 0, nullptr, 0) == 0;
    }
    if (!g_state.opts.so_name.empty()) {
        return strstr(name, g_state.opts.so_name.c_str()) != nullptr;
    }
    return false;
}

static void do_dump_for_name(const char* name, bool onload) {
    if (g_state.opts.watch) {
        LOGI("%s library: %s", onload ? "onload" : "loaded", name ? name : "null");
    }

    if (!should_dump_name(name) || g_state.did_dump) return;

    const char* module_name = name;
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

    g_state.did_dump = true;
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
    if (g_state.opts.on_load) {
        do_dump_for_name(name, true);
    }

    void* handle = old_do_dlopen ? old_do_dlopen(name, flags, extinfo, caller_addr) : nullptr;
    if (handle != nullptr) {
        // Attempt again after dlopen returns to avoid missing cases where the
        // module isn't discoverable yet during the on_load phase.
        do_dump_for_name(name, false);
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
    if (!g_state.opts.regex.empty()) {
        g_state.opts.so_name.clear(); // match behavior of temp/zygisk-memdump
    }
    g_state.did_dump = false;

    if (g_state.regex_inited) {
        regfree(&g_state.regex);
        g_state.regex_inited = false;
    }
    g_state.regex_ok = false;
    if (!g_state.opts.regex.empty()) {
        std::string full_pat = "^(" + g_state.opts.regex + ")$";
        g_state.regex_inited = true;
        int rc = regcomp(&g_state.regex, full_pat.c_str(), REG_EXTENDED | REG_NOSUB);
        if (rc == 0) {
            g_state.regex_ok = true;
        } else {
            char buf[256];
            regerror(rc, &g_state.regex, buf, sizeof(buf));
            LOGE("Bad regex: %s (%s)", g_state.opts.regex.c_str(), buf);
            g_state.opts.regex.clear();
        }
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

