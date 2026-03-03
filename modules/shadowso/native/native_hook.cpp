#include "native_hook.h"

#include <cstdint>
#include <cctype>
#include <cstring>
#include <dlfcn.h>
#include <atomic>
#include <android/log.h>
#include <dobby.h>

#ifndef ZMOD_ID
#define ZMOD_ID "shadowso"
#endif

#include "shadow_loader.h"

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

// ---------------- dlsym hook (shadow-lookup + logging) ----------------
using dlsym_t = void *(*)(void *handle, const char *symbol);
static dlsym_t orig_dlsym = nullptr;

static const char *range_tag_for_addr(uintptr_t addr, const sample::shadow_loader::ShadowModuleInfo &m) {
    if (m.orig_base != 0 && m.orig_size != 0) {
        const uintptr_t ob = m.orig_base;
        const uintptr_t oe = ob + (uintptr_t)m.orig_size;
        if (addr >= ob && addr < oe) return "orig";
    }
    if (m.shadow_base != 0 && m.shadow_size != 0) {
        const uintptr_t sb = m.shadow_base;
        const uintptr_t se = sb + (uintptr_t)m.shadow_size;
        if (addr >= sb && addr < se) return "shadow";
    }
    return nullptr;
}

static void *hooked_dlsym(void *handle, const char *symbol) {
    if (!orig_dlsym) return nullptr;

    if (symbol) {
        void *shadow_ret = sample::shadow_loader::get_shadow_symbol(symbol);
        if (shadow_ret) {
            // Shadow-hit path used to early-return without enough context. Add diagnostics:
            // caller module, returned addr range tag, and rate-limit to avoid log spam.
            static std::atomic<uint64_t> g_shadow_hits{0};
            static std::atomic<int> g_shadow_log_budget{300};
            const uint64_t hn = g_shadow_hits.fetch_add(1, std::memory_order_relaxed) + 1;
            int left = g_shadow_log_budget.fetch_sub(1, std::memory_order_relaxed);

            const void *caller = __builtin_return_address(0);
            const uintptr_t a = reinterpret_cast<uintptr_t>(shadow_ret);
            const auto mods = sample::shadow_loader::snapshot_modules();
            const sample::shadow_loader::ShadowModuleInfo *hit = nullptr;
            const char *which = nullptr;
            for (const auto &m : mods) {
                const char *tag = range_tag_for_addr(a, m);
                if (tag) {
                    hit = &m;
                    which = tag;
                    break;
                }
            }

            Dl_info di_ret{};
            Dl_info di_caller{};
            (void)dladdr(shadow_ret, &di_ret);
            (void)dladdr(caller, &di_caller);

            if (left > 0) {
                LOGI("[%s][dlsym][shadow] #%llu handle=%p symbol=%s -> %p hit=%s/%s caller=%p (%s/%s) ret_dladdr=(%s/%s base=%p saddr=%p)",
                     ZMOD_ID,
                     (unsigned long long)hn,
                     handle,
                     symbol ? symbol : "<null>",
                     shadow_ret,
                     hit ? hit->name_lower.c_str() : "no",
                     which ? which : "-",
                     caller,
                     di_caller.dli_fname ? di_caller.dli_fname : "?",
                     di_caller.dli_sname ? di_caller.dli_sname : "?",
                     di_ret.dli_fname ? di_ret.dli_fname : "?",
                     di_ret.dli_sname ? di_ret.dli_sname : "?",
                     di_ret.dli_fbase,
                     di_ret.dli_saddr);
            } else if ((hn % 1000) == 0) {
                LOGI("[%s][dlsym][shadow] hits=%llu (log_budget exhausted)", ZMOD_ID, (unsigned long long)hn);
            }
            return shadow_ret;
        }
    }

    void *ret = orig_dlsym(handle, symbol);

    // Avoid unbounded spam; log first N calls only.
    static std::atomic<uint64_t> g_calls{0};
    static std::atomic<int> g_log_budget{500};
    const uint64_t n = g_calls.fetch_add(1, std::memory_order_relaxed) + 1;
    int left = g_log_budget.fetch_sub(1, std::memory_order_relaxed);
    if (left <= 0) return ret;

    const void *caller = __builtin_return_address(0);

    const uintptr_t a = reinterpret_cast<uintptr_t>(ret);
    const auto mods = sample::shadow_loader::snapshot_modules();
    const sample::shadow_loader::ShadowModuleInfo *hit = nullptr;
    const char *which = nullptr;
    for (const auto &m : mods) {
        const char *tag = range_tag_for_addr(a, m);
        if (tag) {
            hit = &m;
            which = tag;
            break;
        }
    }

    Dl_info di_ret{};
    Dl_info di_caller{};
    (void)dladdr(ret, &di_ret);
    (void)dladdr(caller, &di_caller);

    LOGI("[%s][dlsym] #%llu handle=%p symbol=%s -> %p shadow_hit=%s/%s caller=%p (%s/%s)",
         ZMOD_ID,
         (unsigned long long)n,
         handle,
         symbol ? symbol : "<null>",
         ret,
         hit ? hit->name_lower.c_str() : "no",
         which ? which : "-",
         caller,
         di_caller.dli_fname ? di_caller.dli_fname : "?",
         di_caller.dli_sname ? di_caller.dli_sname : "?");

    if (ret && (di_ret.dli_fname || di_ret.dli_sname)) {
        LOGI("[%s][dlsym]    ret_dladdr: fname=%s sname=%s fbase=%p saddr=%p",
             ZMOD_ID,
             di_ret.dli_fname ? di_ret.dli_fname : "?",
             di_ret.dli_sname ? di_ret.dli_sname : "?",
             di_ret.dli_fbase,
             di_ret.dli_saddr);
    }
    return ret;
}

static void *resolve_dlsym() {
    // Called before installing the hook; dlsym is still original here.
    void *sym = dlsym(RTLD_DEFAULT, "dlsym");
    if (sym) return sym;
    void *libdl = dlopen("libdl.so", RTLD_NOW);
    if (libdl) {
        sym = dlsym(libdl, "dlsym");
        if (sym) return sym;
    }
    return nullptr;
}

void *get_real_dlsym(void *handle, const char *symbol) {
    // If we've hooked dlsym, prefer calling the original (unhooked) implementation.
    if (orig_dlsym) return orig_dlsym(handle, symbol);
    return dlsym(handle, symbol);
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
    } else {
        LOGE("[%s][native] failed to hook android_dlopen_ext @ %p", ZMOD_ID, target);
        return false;
    }

    // dlsym hook: attempt shadow lookup, otherwise logging-only.
    void *dlsym_target = resolve_dlsym();
    if (!dlsym_target) {
        LOGW("[%s][native] symbol not found: dlsym (skip dlsym hook)", ZMOD_ID);
        return true;
    }
    void *dlsym_orig = nullptr;
    if (DobbyHook(dlsym_target, to_void_ptr(hooked_dlsym), &dlsym_orig) == 0 && dlsym_orig) {
        orig_dlsym = reinterpret_cast<dlsym_t>(dlsym_orig);
        LOGI("[%s][native] hooked dlsym @ %p (shadow-lookup + logging, budget=500)", ZMOD_ID, dlsym_target);
    } else {
        LOGW("[%s][native] failed to hook dlsym @ %p (skip dlsym hook)", ZMOD_ID, dlsym_target);
    }
    return true;
}

} // namespace native_hook
} // namespace sample

