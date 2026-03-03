#include "phdr_hook.h"

#include <android/log.h>
#include <atomic>
#include <cctype>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include <dlfcn.h>
#include <link.h>

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
namespace phdr_hook {
namespace {

using dl_iterate_phdr_t = int (*)(int (*)(struct dl_phdr_info *, size_t, void *), void *);
static dl_iterate_phdr_t old_dl_iterate_phdr = nullptr;
static bool g_installed = false;
static std::atomic<int> g_rewrite_log_budget{32};

static std::string to_lower_copy(const char *s) {
    if (!s) return {};
    std::string out;
    out.reserve(std::strlen(s));
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p) out.push_back((char)std::tolower(*p));
    return out;
}

static std::string basename_lower_of(const std::string &path_lower) {
    if (path_lower.empty()) return {};
    size_t slash = path_lower.find_last_of('/');
    if (slash == std::string::npos) return path_lower;
    if (slash + 1 >= path_lower.size()) return path_lower;
    return path_lower.substr(slash + 1);
}

struct Ctx {
    int (*user_cb)(struct dl_phdr_info *, size_t, void *);
    void *user_data;
    std::unordered_map<std::string, sample::shadow_loader::ShadowModuleInfo> by_basename;
    std::unordered_map<std::string, sample::shadow_loader::ShadowModuleInfo> by_name_substr;
};

static int wrapper_cb(struct dl_phdr_info *info, size_t size, void *data) {
    auto *ctx = reinterpret_cast<Ctx *>(data);
    if (!ctx || !ctx->user_cb) return 0;
    if (!info) return ctx->user_cb(info, size, ctx->user_data);

    const char *name = info->dlpi_name;
    if (!name || name[0] == '\0') {
        return ctx->user_cb(info, size, ctx->user_data);
    }

    std::string name_lower = to_lower_copy(name);
    std::string bn = basename_lower_of(name_lower);

    const sample::shadow_loader::ShadowModuleInfo *match = nullptr;
    auto itb = ctx->by_basename.find(bn);
    if (itb != ctx->by_basename.end()) {
        match = &itb->second;
    } else {
        // Fallback: substring match by configured name (libxxx.so).
        for (const auto &kv : ctx->by_name_substr) {
            if (kv.first.empty()) continue;
            if (name_lower.find(kv.first) != std::string::npos) {
                match = &kv.second;
                break;
            }
        }
    }

    if (!match || match->shadow_base == 0) {
        return ctx->user_cb(info, size, ctx->user_data);
    }

    // Copy and rewrite to shadow module view.
    dl_phdr_info mod = *info;
    mod.dlpi_addr = (ElfW(Addr))match->shadow_base;
    if (!match->shadow_path.empty()) {
        mod.dlpi_name = match->shadow_path.c_str();
    }
    if (match->shadow_phdr && match->shadow_phnum) {
        mod.dlpi_phdr = match->shadow_phdr;
        mod.dlpi_phnum = match->shadow_phnum;
    }

    int left = g_rewrite_log_budget.fetch_sub(1, std::memory_order_relaxed);
    if (left > 0) {
        LOGI("[%s][phdr] rewrite entry: orig_name=%s orig_base=0x%lx -> shadow_name=%s shadow_base=0x%lx",
             ZMOD_ID,
             name,
             (unsigned long)info->dlpi_addr,
             mod.dlpi_name ? mod.dlpi_name : "null",
             (unsigned long)match->shadow_base);
    }
    return ctx->user_cb(&mod, size, ctx->user_data);
}

static int new_dl_iterate_phdr(int (*callback)(struct dl_phdr_info *, size_t, void *), void *data) {
    if (!old_dl_iterate_phdr || !callback) {
        return old_dl_iterate_phdr ? old_dl_iterate_phdr(callback, data) : 0;
    }

    Ctx ctx{};
    ctx.user_cb = callback;
    ctx.user_data = data;

    auto mods = sample::shadow_loader::snapshot_modules();
    LOGI("[%s][phdr] dl_iterate_phdr called: shadow_modules=%zu (log_budget_left=%d)",
         ZMOD_ID, mods.size(), g_rewrite_log_budget.load(std::memory_order_relaxed));
    ctx.by_basename.reserve(mods.size());
    ctx.by_name_substr.reserve(mods.size());
    for (auto &m : mods) {
        if (m.shadow_base == 0) continue;
        if (!m.shadow_path.empty()) {
            std::string bn = basename_lower_of(to_lower_copy(m.shadow_path.c_str()));
            if (!bn.empty()) ctx.by_basename.emplace(bn, m);
        }
        if (!m.name_lower.empty()) {
            ctx.by_name_substr.emplace(m.name_lower, m);
        }
    }

    return old_dl_iterate_phdr(wrapper_cb, &ctx);
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
        LOGI("[%s][phdr] already installed", ZMOD_ID);
        return true;
    }
    void *target = resolve_sym("dl_iterate_phdr");
    if (!target) {
        LOGE("[%s][phdr] dl_iterate_phdr not found", ZMOD_ID);
        return false;
    }

    void *orig = nullptr;
    if (DobbyHook(target, (void *)new_dl_iterate_phdr, &orig) == 0 && orig) {
        old_dl_iterate_phdr = reinterpret_cast<dl_iterate_phdr_t>(orig);
        g_installed = true;
        LOGI("[%s][phdr] Hooked dl_iterate_phdr @ %p", ZMOD_ID, target);
        return true;
    } else {
        LOGE("[%s][phdr] Failed to hook dl_iterate_phdr @ %p", ZMOD_ID, target);
        return false;
    }
}

} // namespace phdr_hook
} // namespace sample

