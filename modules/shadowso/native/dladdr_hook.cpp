#include "dladdr_hook.h"
#include "native_hook.h"

#include <android/log.h>
#include <cstdint>
#include <dlfcn.h>
#include <mutex>
#include <vector>

#include <dobby.h>

#include "shadow_loader.h"

#ifndef ZMOD_ID
#define ZMOD_ID "shadowso"
#endif

#define LOG_TAG    "shadowso"
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace sample {
namespace dladdr_hook {
namespace {

using dladdr_t = int (*)(const void *, Dl_info *);
static dladdr_t old_dladdr = nullptr;
static bool g_installed = false;

static std::mutex g_cache_mu;
static std::vector<sample::shadow_loader::ShadowModuleInfo> g_cache;

static void refresh_cache_locked() {
    g_cache = sample::shadow_loader::snapshot_modules();
}

static bool translate_if_shadow(const void *addr,
                                void **out_orig_addr,
                                const sample::shadow_loader::ShadowModuleInfo **out_match,
                                uintptr_t *out_rva) {
    if (!addr || !out_orig_addr) return false;
    const uintptr_t a = reinterpret_cast<uintptr_t>(addr);

    std::lock_guard<std::mutex> lk(g_cache_mu);
    // Snapshot on demand (simple; safe when new shadows appear later).
    refresh_cache_locked();

    for (const auto &m : g_cache) {
        if (m.shadow_base == 0 || m.shadow_size == 0) continue;
        if (m.orig_base == 0 || m.orig_size == 0) continue;

        const uintptr_t sb = m.shadow_base;
        if (a < sb) continue;
        const uintptr_t rva = a - sb;
        if (rva >= (uintptr_t)m.shadow_size) continue;
        if (rva >= (uintptr_t)m.orig_size) continue;

        const uintptr_t oa = m.orig_base + rva;
        *out_orig_addr = reinterpret_cast<void *>(oa);
        if (out_match) *out_match = &m;
        if (out_rva) *out_rva = rva;
        return true;
    }
    return false;
}

static int new_dladdr(const void *addr, Dl_info *info) {
    if (!old_dladdr) return 0;

    void *orig_addr = nullptr;
    const sample::shadow_loader::ShadowModuleInfo *m = nullptr;
    uintptr_t rva = 0;
    if (translate_if_shadow(addr, &orig_addr, &m, &rva) && orig_addr != nullptr) {
        if (m) {
            LOGI("[%s][dladdr] translate shadow addr=%p rva=0x%lx -> orig=%p (%s)",
                 ZMOD_ID,
                 addr,
                 (unsigned long)rva,
                 orig_addr,
                 m->name_lower.c_str());
        }
        return old_dladdr(orig_addr, info);
    }
    return old_dladdr(addr, info);
}

static void *resolve_sym(const char *sym) {
    void *p = sample::native_hook::get_real_dlsym(RTLD_DEFAULT, sym);
    if (p) return p;
    void *libc = dlopen("libc.so", RTLD_NOW);
    if (libc) p = sample::native_hook::get_real_dlsym(libc, sym);
    return p;
}

} // namespace

bool install() {
    if (g_installed) {
        LOGI("[%s][dladdr] already installed", ZMOD_ID);
        return true;
    }
    void *target = resolve_sym("dladdr");
    if (!target) {
        LOGE("[%s][dladdr] dladdr not found", ZMOD_ID);
        return false;
    }

    void *orig = nullptr;
    if (DobbyHook(target, (void *)new_dladdr, &orig) == 0 && orig) {
        old_dladdr = reinterpret_cast<dladdr_t>(orig);
        g_installed = true;
        LOGI("[%s][dladdr] Hooked dladdr @ %p", ZMOD_ID, target);
        return true;
    } else {
        LOGE("[%s][dladdr] Failed to hook dladdr @ %p", ZMOD_ID, target);
        return false;
    }
}

} // namespace dladdr_hook
} // namespace sample

