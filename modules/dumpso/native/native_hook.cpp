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

// Prefer hooking android_dlopen_ext which is a stable, exported libdl API on Android.
// Signature: void* android_dlopen_ext(const char* filename, int flags, const android_dlextinfo* extinfo);
// We keep the third parameter as void* to avoid depending on platform headers.
using android_dlopen_ext_t = void *(*)(const char *filename, int flags, const void *extinfo);
static android_dlopen_ext_t orig_android_dlopen_ext = nullptr;

static void *hooked_android_dlopen_ext(const char *filename, int flags, const void *extinfo) {
    LOGI("[%s] android_dlopen_ext(filename=%s, flags=0x%x, extinfo=%p)",
         ZMOD_ID,
         filename ? filename : "null",
         flags,
         extinfo);
    return orig_android_dlopen_ext ? orig_android_dlopen_ext(filename, flags, extinfo) : nullptr;
}

static void *resolve_android_dlopen_ext() {
    void *sym = dlsym(RTLD_DEFAULT, "android_dlopen_ext");
    if (sym) return sym;

    void *libdl = dlopen("libdl.so", RTLD_NOW);
    if (libdl) {
        sym = dlsym(libdl, "android_dlopen_ext");
        // Keep libdl loaded (do not dlclose) – safe for template module.
        if (sym) return sym;
    }
    return nullptr;
}

void install_hooks() {
    LOGI("[%s] Installing native hooks...", ZMOD_ID);

    void *target = resolve_android_dlopen_ext();
    if (!target) {
        LOGW("[%s] Symbol not found: android_dlopen_ext", ZMOD_ID);
        return;
    }

    void *orig = nullptr;
    if (DobbyHook(target, to_void_ptr(hooked_android_dlopen_ext), &orig) == 0 && orig) {
        orig_android_dlopen_ext = reinterpret_cast<android_dlopen_ext_t>(orig);
        LOGI("[%s] Hooked android_dlopen_ext @ %p", ZMOD_ID, target);
    } else {
        LOGE("[%s] Failed to hook android_dlopen_ext @ %p", ZMOD_ID, target);
    }
}

} // namespace native_hook
} // namespace sample

