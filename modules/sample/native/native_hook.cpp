#include "native_hook.h"

#include <cstdint>
#include <dlfcn.h>
#include <android/log.h>
#include <dobby.h>

#ifndef ZMOD_ID
#define ZMOD_ID "sample"
#endif

#define LOG_TAG    "Sample/NativeHook"
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

template <typename T>
static inline void *to_void_ptr(T fn_or_ptr) {
    // Dobby expects void* for both target address and replacement.
    // Converting function pointer -> void* is not strictly standard, but is
    // supported on Android/Clang for hooking use-cases.
    return reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(fn_or_ptr));
}

namespace sample {
namespace native_hook {

using loader_dlopen_t = void *(*)(const char *filename, int flags, const void *caller_addr);
static loader_dlopen_t orig___loader_dlopen = nullptr;

static void *hooked___loader_dlopen(const char *filename, int flags, const void *caller_addr) {
    LOGI("[%s] __loader_dlopen(filename=%s, flags=0x%x, caller=%p)",
         ZMOD_ID,
         filename ? filename : "null",
         flags,
         caller_addr);
    return orig___loader_dlopen ? orig___loader_dlopen(filename, flags, caller_addr) : nullptr;
}

static void *resolve_loader_dlopen() {
    void *sym = dlsym(RTLD_DEFAULT, "__loader_dlopen");
    if (sym) return sym;

    void *libdl = dlopen("libdl.so", RTLD_NOW);
    if (libdl) {
        sym = dlsym(libdl, "__loader_dlopen");
        // Keep libdl loaded (do not dlclose) – safe for template module.
        if (sym) return sym;
    }
    return nullptr;
}

void install_hooks() {
    LOGI("[%s] Installing native hooks...", ZMOD_ID);

    void *target = resolve_loader_dlopen();
    if (!target) {
        LOGW("[%s] Symbol not found: __loader_dlopen (Android version/linker may hide it)", ZMOD_ID);
        return;
    }

    void *orig = nullptr;
    if (DobbyHook(target, to_void_ptr(hooked___loader_dlopen), &orig) == 0 && orig) {
        orig___loader_dlopen = reinterpret_cast<loader_dlopen_t>(orig);
        LOGI("[%s] Hooked __loader_dlopen @ %p", ZMOD_ID, target);
    } else {
        LOGE("[%s] Failed to hook __loader_dlopen @ %p", ZMOD_ID, target);
    }
}

} // namespace native_hook
} // namespace sample

