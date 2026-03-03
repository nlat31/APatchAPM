#include "dladdr_hook.h"

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
static std::atomic<int> g_rewrite_log_budget{64};

static std::mutex g_cache_mu;
static std::vector<sample::shadow_loader::ShadowModuleInfo> g_cache;

static void refresh_cache_locked() {
    g_cache = sample::shadow_loader::snapshot_modules();
}

static bool match_by_orig_addr(const void *addr,
                               const sample::shadow_loader::ShadowModuleInfo **out_match,
                               uintptr_t *out_rva) {
    if (!addr) return false;
    const uintptr_t a = reinterpret_cast<uintptr_t>(addr);

    std::lock_guard<std::mutex> lk(g_cache_mu);
    // Snapshot on demand (simple; safe when new shadows appear later).
    refresh_cache_locked();

    for (const auto &m : g_cache) {
        if (m.shadow_base == 0 || m.shadow_size == 0) continue;
        if (m.orig_base == 0 || m.orig_size == 0) continue;

        const uintptr_t ob = m.orig_base;
        if (a < ob) continue;
        const uintptr_t rva = a - ob;
        if (rva >= (uintptr_t)m.orig_size) continue;
        if (rva >= (uintptr_t)m.shadow_size) continue;
        if (out_match) *out_match = &m;
        if (out_rva) *out_rva = rva;
        return true;
    }
    return false;
}

static bool match_by_shadow_addr(const void *addr,
                                 const sample::shadow_loader::ShadowModuleInfo **out_match,
                                 uintptr_t *out_rva) {
    if (!addr) return false;
    const uintptr_t a = reinterpret_cast<uintptr_t>(addr);

    std::lock_guard<std::mutex> lk(g_cache_mu);
    refresh_cache_locked();

    for (const auto &m : g_cache) {
        if (m.shadow_base == 0 || m.shadow_size == 0) continue;
        if (m.orig_base == 0 || m.orig_size == 0) continue;

        const uintptr_t sb = m.shadow_base;
        if (a < sb) continue;
        const uintptr_t rva = a - sb;
        if (rva >= (uintptr_t)m.shadow_size) continue;
        if (rva >= (uintptr_t)m.orig_size) continue;
        if (out_match) *out_match = &m;
        if (out_rva) *out_rva = rva;
        return true;
    }
    return false;
}

static void rewrite_info_to_shadow(const sample::shadow_loader::ShadowModuleInfo *m, Dl_info *info) {
    if (!m || !info) return;
    if (m->shadow_base == 0 || m->shadow_size == 0) return;
    if (m->orig_base == 0 || m->orig_size == 0) return;

    // Make dladdr report the shadow module base. Keep dli_fname as-is to avoid lifetime issues.
    info->dli_fbase = reinterpret_cast<void *>(m->shadow_base);

    // If dladdr resolved a symbol address inside the original module, translate it to shadow view.
    if (info->dli_saddr) {
        const uintptr_t s = reinterpret_cast<uintptr_t>(info->dli_saddr);
        if (s >= m->orig_base && s < (m->orig_base + (uintptr_t)m->orig_size)) {
            const uintptr_t srva = s - m->orig_base;
            if (srva < (uintptr_t)m->shadow_size) {
                info->dli_saddr = reinterpret_cast<void *>(m->shadow_base + srva);
            }
        }
    }
}

static int new_dladdr(const void *addr, Dl_info *info) {
    if (!old_dladdr) return 0;

    const sample::shadow_loader::ShadowModuleInfo *m = nullptr;
    uintptr_t rva = 0;

    // Normal path: resolve with real linker dladdr, then rewrite results to shadow view if needed.
    int ret = old_dladdr(addr, info);
    if (ret != 0) {
        if (match_by_orig_addr(addr, &m, &rva)) {
            rewrite_info_to_shadow(m, info);
            int left = g_rewrite_log_budget.fetch_sub(1, std::memory_order_relaxed);
            if (left > 0) {
                LOGI("[%s][dladdr] rewrite orig addr=%p rva=0x%lx -> shadow_base=0x%lx (%s)",
                     ZMOD_ID,
                     addr,
                     (unsigned long)rva,
                     (unsigned long)(m ? m->shadow_base : 0),
                     m ? m->name_lower.c_str() : "?");
            }
        }
        return ret;
    }

    // If caller passed a shadow-view address (e.g. derived from dl_iterate_phdr),
    // translate it back to orig for resolution, then rewrite output back to shadow.
    if (match_by_shadow_addr(addr, &m, &rva) && m != nullptr) {
        const uintptr_t orig_addr = m->orig_base + rva;
        ret = old_dladdr(reinterpret_cast<void *>(orig_addr), info);
        if (ret != 0) {
            rewrite_info_to_shadow(m, info);
            int left = g_rewrite_log_budget.fetch_sub(1, std::memory_order_relaxed);
            if (left > 0) {
                LOGI("[%s][dladdr] resolve shadow addr=%p rva=0x%lx via orig=%p -> shadow view (%s)",
                     ZMOD_ID,
                     addr,
                     (unsigned long)rva,
                     (void *)orig_addr,
                     m->name_lower.c_str());
            }
        }
        return ret;
    }

    return 0;
}

static void *resolve_sym(const char *sym) {
    void *p = dlsym(RTLD_DEFAULT, sym);
    if (p) return p;
    void *libc = dlopen("libc.so", RTLD_NOW);
    if (libc) p = dlsym(libc, sym);
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

