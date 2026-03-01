#include "native_hook.h"

#include <cstdint>
#include <cctype>
#include <cstring>
#include <dlfcn.h>
#include <android/log.h>
#include <dobby.h>

#ifndef ZMOD_ID
#define ZMOD_ID "shadowso"
#endif

#define LOG_TAG    "shadowso"
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
// Promote debug logs to INFO to make shadow behavior observable in release logcat.
#define LOGD(...)  __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)

template <typename T>
static inline void *to_void_ptr(T fn_or_ptr) {
    // Dobby expects void* for both target address and replacement.
    // Converting function pointer -> void* is not strictly standard, but is
    // supported on Android/Clang for hooking use-cases.
    return reinterpret_cast<void *>(reinterpret_cast<uintptr_t>(fn_or_ptr));
}

namespace sample {
namespace native_hook {

static std::vector<std::string> g_hide_so;

static std::string to_lower_copy(const std::string &in) {
    std::string out;
    out.reserve(in.size());
    for (unsigned char c : in) out.push_back((char)std::tolower(c));
    return out;
}

static std::string basename_of(const char *path) {
    if (!path) return {};
    const char *p = std::strrchr(path, '/');
    return p ? std::string(p + 1) : std::string(path);
}

static bool should_hide_filename(const char *filename) {
    if (!filename || g_hide_so.empty()) return false;
    std::string base = to_lower_copy(basename_of(filename));
    for (const auto &s : g_hide_so) {
        if (s.empty()) continue;
        if (base == s) return true;
    }
    return false;
}

// Prefer hooking android_dlopen_ext which is a stable, exported libdl API on Android.
// Signature: void* android_dlopen_ext(const char* filename, int flags, const android_dlextinfo* extinfo);
// We keep the third parameter as void* to avoid depending on platform headers.
using android_dlopen_ext_t = void *(*)(const char *filename, int flags, const void *extinfo);
static android_dlopen_ext_t orig_android_dlopen_ext = nullptr;

static void *hooked_android_dlopen_ext(const char *filename, int flags, const void *extinfo) {
    if (!should_hide_filename(filename)) {
        LOGI("[%s] android_dlopen_ext(filename=%s, flags=0x%x, extinfo=%p)",
             ZMOD_ID,
             filename ? filename : "null",
             flags,
             extinfo);
    }
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

bool install_hooks(const std::vector<std::string> &hide_so) {
    LOGI("[%s][native] installing hooks...", ZMOD_ID);
    g_hide_so.clear();
    g_hide_so.reserve(hide_so.size());
    for (const auto &s : hide_so) {
        if (s.empty()) continue;
        g_hide_so.emplace_back(to_lower_copy(s));
    }

    void *target = resolve_android_dlopen_ext();
    if (!target) {
        LOGE("[%s][native] symbol not found: android_dlopen_ext", ZMOD_ID);
        return false;
    }

    void *orig = nullptr;
    if (DobbyHook(target, to_void_ptr(hooked_android_dlopen_ext), &orig) == 0 && orig) {
        orig_android_dlopen_ext = reinterpret_cast<android_dlopen_ext_t>(orig);
        LOGI("[%s][native] hooked android_dlopen_ext @ %p", ZMOD_ID, target);
        return true;
    } else {
        LOGE("[%s][native] failed to hook android_dlopen_ext @ %p", ZMOD_ID, target);
        return false;
    }
}

} // namespace native_hook
} // namespace sample

