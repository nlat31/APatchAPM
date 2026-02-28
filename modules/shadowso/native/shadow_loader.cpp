#include "shadow_loader.h"

#include <android/dlext.h>
#include <android/log.h>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <cerrno>
#include <link.h>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <dobby.h>

#include <csoloader.h>

#include "elf_util.h"

#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef ZMOD_ID
#define ZMOD_ID "shadowso"
#endif

#define LOG_TAG    "shadowso"
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace sample {
namespace shadow_loader {
namespace {

static std::mutex g_mu;
static bool g_inited = false;
static bool g_dlopen_hook_installed = false;
static void *g_do_dlopen_target = nullptr;

// Name -> full path (best-effort) for libraries we want to shadow-load.
static std::unordered_set<std::string> g_targets;
static std::unordered_set<std::string> g_loaded_targets;
static std::unordered_map<std::string, uintptr_t> g_shadow_base_by_target;
static std::unordered_map<std::string, ShadowModuleInfo> g_info_by_target;

struct OrigModuleInfo {
    std::string path;
    uintptr_t base = 0;
    size_t size = 0;
    const ElfW(Phdr) *phdr = nullptr;
    ElfW(Half) phnum = 0;
};
static std::unordered_map<std::string, OrigModuleInfo> g_orig_by_basename;

static std::string g_linker_path;
static uintptr_t g_linker_base = 0;

// Keep CSOLoader instances alive for the entire process lifetime.
static std::vector<csoloader *> g_shadow_libs;

static std::string to_lower(std::string s) {
    for (auto &ch : s) ch = (char)std::tolower((unsigned char)ch);
    return s;
}

static std::string basename_lower_of(const std::string &path_or_name_lower) {
    if (path_or_name_lower.empty()) return {};
    size_t slash = path_or_name_lower.find_last_of('/');
    if (slash == std::string::npos) return path_or_name_lower;
    if (slash + 1 >= path_or_name_lower.size()) return path_or_name_lower;
    return path_or_name_lower.substr(slash + 1);
}

static bool snapshot_targets_from_dl_iterate_phdr_locked() {
    // Enumerate loaded modules once. Do not depend on /proc/self/maps (it may be redirected later).
    struct Ctx {
        std::unordered_set<std::string> targets;
    } ctx{g_targets};

    auto cb = [](struct dl_phdr_info *info, size_t /*size*/, void *data) -> int {
        if (!info || !data) return 0;
        auto *c = reinterpret_cast<Ctx *>(data);
        const char *name = info->dlpi_name;
        if (!name || name[0] == '\0') return 0;

        std::string path(name);
        std::string path_lower = to_lower(path);
        std::string bn = basename_lower_of(path_lower);

        // Cache original module info by basename for later queries (no more enumeration/maps).
        if (!bn.empty() && g_orig_by_basename.find(bn) == g_orig_by_basename.end()) {
            OrigModuleInfo omi;
            omi.path = path;
            omi.phdr = info->dlpi_phdr;
            omi.phnum = info->dlpi_phnum;
            uintptr_t min_vaddr = (uintptr_t)-1;
            uintptr_t max_vaddr = 0;
            for (ElfW(Half) i = 0; i < info->dlpi_phnum; i++) {
                const ElfW(Phdr) &p = info->dlpi_phdr[i];
                if (p.p_type != PT_LOAD) continue;
                uintptr_t seg_start = (uintptr_t)p.p_vaddr & ~(uintptr_t)0xFFF;
                uintptr_t seg_end = ((uintptr_t)p.p_vaddr + (uintptr_t)p.p_memsz + (uintptr_t)0xFFF) & ~(uintptr_t)0xFFF;
                if (seg_start < min_vaddr) min_vaddr = seg_start;
                if (seg_end > max_vaddr) max_vaddr = seg_end;
            }
            if (min_vaddr != (uintptr_t)-1 && max_vaddr > min_vaddr) {
                omi.base = (uintptr_t)info->dlpi_addr + min_vaddr;
                omi.size = (size_t)(max_vaddr - min_vaddr);
            }
            g_orig_by_basename.emplace(bn, std::move(omi));
        }

        // Cache linker path/base for installing do_dlopen hook later, without reading maps.
#if defined(__LP64__)
        constexpr const char *k_linker_bn = "linker64";
#else
        constexpr const char *k_linker_bn = "linker";
#endif
        if (bn == k_linker_bn) {
            uintptr_t min_vaddr = (uintptr_t)-1;
            for (ElfW(Half) i = 0; i < info->dlpi_phnum; i++) {
                const ElfW(Phdr) &p = info->dlpi_phdr[i];
                if (p.p_type != PT_LOAD) continue;
                uintptr_t seg_start = (uintptr_t)p.p_vaddr & ~(uintptr_t)0xFFF;
                if (seg_start < min_vaddr) min_vaddr = seg_start;
            }
            if (min_vaddr != (uintptr_t)-1) {
                g_linker_path = path;
                g_linker_base = (uintptr_t)info->dlpi_addr + min_vaddr;
            }
        }

        for (const auto &t : c->targets) {
            if (t.empty()) continue;
            if (bn != t) continue;

            auto &mi = g_info_by_target[t];
            mi.name_lower = t;
            mi.orig_path = path;
            mi.orig_phdr = info->dlpi_phdr;
            mi.orig_phnum = info->dlpi_phnum;

            // Compute orig_base/orig_size from PT_LOAD range.
            uintptr_t min_vaddr = (uintptr_t)-1;
            uintptr_t max_vaddr = 0;
            for (ElfW(Half) i = 0; i < info->dlpi_phnum; i++) {
                const ElfW(Phdr) &p = info->dlpi_phdr[i];
                if (p.p_type != PT_LOAD) continue;
                uintptr_t seg_start = (uintptr_t)p.p_vaddr & ~(uintptr_t)0xFFF;
                uintptr_t seg_end = ((uintptr_t)p.p_vaddr + (uintptr_t)p.p_memsz + (uintptr_t)0xFFF) & ~(uintptr_t)0xFFF;
                if (seg_start < min_vaddr) min_vaddr = seg_start;
                if (seg_end > max_vaddr) max_vaddr = seg_end;
            }
            if (min_vaddr != (uintptr_t)-1 && max_vaddr > min_vaddr) {
                // dlpi_addr is the load bias; maps usually show mappings starting at (dlpi_addr + min_vaddr).
                mi.orig_base = (uintptr_t)info->dlpi_addr + min_vaddr;
                mi.orig_size = (size_t)(max_vaddr - min_vaddr);
            }
            break;
        }
        return 0;
    };

    dl_iterate_phdr(cb, &ctx);

    // Return true if at least one target was found.
    for (const auto &t : g_targets) {
        auto it = g_info_by_target.find(t);
        if (it != g_info_by_target.end() && !it->second.orig_path.empty()) return true;
    }
    return false;
}

static bool shadow_load_path_locked(const std::string &target_lower, const std::string &path) {
    if (path.empty()) return false;
    if (g_loaded_targets.find(target_lower) != g_loaded_targets.end()) return true;

    // Use CSOLoader for all targets (libc, libart, app libs). It handles relocations and linking.
    // Ensure CSOLoader can resolve DT_NEEDED from the same directory (e.g. /apex/.../lib64/).
    {
        const size_t slash = path.find_last_of('/');
        if (slash != std::string::npos && slash > 0) {
            const std::string dir = path.substr(0, slash);
            (void)linker_add_library_search_path(dir.c_str());
        }
    }

    auto *lib = new csoloader();
    std::memset(lib, 0, sizeof(*lib));
    if (!csoloader_load(lib, path.c_str())) {
        LOGE("[%s][shadow] csoloader_load failed for %s (path=%s)", ZMOD_ID, target_lower.c_str(), path.c_str());
        delete lib;
        return false;
    }

    g_shadow_libs.push_back(lib);
    g_loaded_targets.insert(target_lower);
    uintptr_t base = 0;
    if (lib->img && lib->img->base) {
        base = reinterpret_cast<uintptr_t>(lib->img->base);
    }
    if (base != 0) {
        g_shadow_base_by_target[target_lower] = base;
    }

    auto &info = g_info_by_target[target_lower];
    info.name_lower = target_lower;
    info.shadow_path = lib->lib_path ? std::string(lib->lib_path) : path;
    info.shadow_base = base;
    info.shadow_size = lib->linker.main_map_size;
    if (lib->img && lib->img->header) {
        info.shadow_phdr = (const ElfW(Phdr) *)((uintptr_t)lib->img->header + lib->img->header->e_phoff);
        info.shadow_phnum = (ElfW(Half))lib->img->header->e_phnum;
    }

    // Fill original info if missing.
    if (info.orig_path.empty()) {
        info.orig_path = path;
    }

    LOGI("[%s][shadow] loaded %s (orig=%s base=0x%lx size=0x%zx, shadow=%s base=0x%lx size=0x%zx)",
         ZMOD_ID,
         target_lower.c_str(),
         info.orig_path.c_str(),
         (unsigned long)info.orig_base,
         info.orig_size,
         info.shadow_path.c_str(),
         (unsigned long)info.shadow_base,
         info.shadow_size);
    return true;
}

// ---------------- do_dlopen hook ----------------
using do_dlopen_t = void *(*)(const char *name, int flags, const android_dlextinfo *extinfo, const void *caller_addr);
static do_dlopen_t old_do_dlopen = nullptr;

static bool try_shadow_load_for_name_locked(const char *name) {
    if (!name) return false;

    // Determine which target this matches.
    std::string name_lower = to_lower(std::string(name));
    std::string matched_target;
    for (const auto &t : g_targets) {
        if (t.empty()) continue;
        if (name_lower.find(t) != std::string::npos) {
            matched_target = t;
            break;
        }
    }
    if (matched_target.empty()) return false;
    if (g_loaded_targets.find(matched_target) != g_loaded_targets.end()) return true;

    // Do not enumerate modules or read maps here. Use the argument string as best-effort path.
    std::string path = name;
    if (path.empty()) return false;

    return shadow_load_path_locked(matched_target, path);
}

static void maybe_uninstall_do_dlopen_hook_locked() {
    if (!g_dlopen_hook_installed) return;
    if (g_targets.empty()) return;
    if (g_loaded_targets.size() < g_targets.size()) return;
    if (!g_do_dlopen_target) return;

    if (DobbyDestroy(g_do_dlopen_target) == 0) {
        g_dlopen_hook_installed = false;
        g_do_dlopen_target = nullptr;
        LOGI("[%s][shadow] unhooked do_dlopen (all targets resolved)", ZMOD_ID);
    } else {
        LOGE("[%s][shadow] failed to unhook do_dlopen (keep hook)", ZMOD_ID);
    }
}

static void *new_do_dlopen(const char *name, int flags, const android_dlextinfo *extinfo, const void *caller_addr) {
    void *handle = old_do_dlopen ? old_do_dlopen(name, flags, extinfo, caller_addr) : nullptr;
    if (handle != nullptr) {
        std::lock_guard<std::mutex> lk(g_mu);
        if (!try_shadow_load_for_name_locked(name)) {
            LOGE("[%s][shadow] shadow-load on do_dlopen failed (name=%s)", ZMOD_ID, name ? name : "null");
        }
        maybe_uninstall_do_dlopen_hook_locked();
    }
    return handle;
}

static bool install_do_dlopen_hook_locked() {
    if (g_dlopen_hook_installed) return true;

    const std::string sym = "__dl__Z9do_dlopenPKciPK17android_dlextinfoPKv";

    if (g_linker_path.empty() || g_linker_base == 0) {
        LOGE("[%s][shadow] linker path/base missing; cannot hook do_dlopen safely", ZMOD_ID);
        return false;
    }
    SandHook::ElfImg linker_img(g_linker_path, reinterpret_cast<void *>(g_linker_base));
    if (!linker_img.isValid()) {
        LOGE("[%s][shadow] linker module not valid: %s", ZMOD_ID, g_linker_path.c_str());
        return false;
    }
    void *target = linker_img.getSymbAddress<void *>(sym);
    if (!target) {
        LOGE("[%s][shadow] do_dlopen symbol not found in %s", ZMOD_ID, g_linker_path.c_str());
        return false;
    }

    void *orig = nullptr;
    if (DobbyHook(target, (void *)new_do_dlopen, &orig) != 0 || !orig) {
        LOGE("[%s][shadow] failed to hook do_dlopen @ %p", ZMOD_ID, target);
        return false;
    }

    old_do_dlopen = reinterpret_cast<do_dlopen_t>(orig);
    g_dlopen_hook_installed = true;
    g_do_dlopen_target = target;
    LOGI("[%s][shadow] hooked do_dlopen @ %p", ZMOD_ID, target);
    return true;
}

} // namespace

bool initialize(const std::vector<std::string> &so_names) {
    std::lock_guard<std::mutex> lk(g_mu);
    if (!g_inited) {
        g_inited = true;
    }

    g_targets.clear();
    g_loaded_targets.clear();
    g_shadow_base_by_target.clear();
    g_info_by_target.clear();
    g_orig_by_basename.clear();
    g_linker_path.clear();
    g_linker_base = 0;

    // Normalize to lowercase for case-insensitive substring match.
    for (const auto &s : so_names) {
        if (s.empty()) continue;
        std::string t = to_lower(s);
        // Trim spaces (defensive, UI already splits).
        while (!t.empty() && std::isspace((unsigned char)t.front())) t.erase(t.begin());
        while (!t.empty() && std::isspace((unsigned char)t.back())) t.pop_back();
        if (!t.empty()) {
            g_targets.insert(t);
            ShadowModuleInfo info;
            info.name_lower = t;
            g_info_by_target[t] = std::move(info);
        }
    }

    if (g_targets.empty()) {
        LOGI("[%s][shadow] no targets configured; skip", ZMOD_ID);
        return true;
    }
    LOGI("[%s][shadow] initialize: targets=%zu", ZMOD_ID, g_targets.size());

    // Snapshot loaded modules once, right after fork. Do not read /proc/self/maps.
    (void)snapshot_targets_from_dl_iterate_phdr_locked();

    // Shadow-load all targets we enumerated in the snapshot.
    std::unordered_set<std::string> pending = g_targets;
    for (const auto &t : g_targets) {
        auto it = g_info_by_target.find(t);
        if (it == g_info_by_target.end()) continue;
        const std::string &path = it->second.orig_path;
        if (path.empty()) continue;
        if (!shadow_load_path_locked(t, path)) {
            LOGE("[%s][shadow] shadow-load failed for %s; stop", ZMOD_ID, t.c_str());
            return false;
        }
        pending.erase(t);
    }

    // If something is still missing, hook do_dlopen so we can shadow-load it immediately
    // after it gets loaded by the app/runtime.
    if (!pending.empty()) {
        LOGW("[%s][shadow] pending targets=%zu; install do_dlopen hook for late-load", ZMOD_ID, pending.size());
        (void)install_do_dlopen_hook_locked();
    } else {
        LOGI("[%s][shadow] all targets shadow-loaded in first pass (%zu)", ZMOD_ID, g_loaded_targets.size());
    }
    return true;
}

std::vector<ShadowModuleInfo> snapshot_modules() {
    std::lock_guard<std::mutex> lk(g_mu);
    std::vector<ShadowModuleInfo> out;
    out.reserve(g_info_by_target.size());
    for (const auto &kv : g_info_by_target) {
        const auto &info = kv.second;
        if (info.name_lower.empty()) continue;
        if (info.shadow_base == 0) continue;
        out.push_back(info);
    }
    return out;
}

bool get_orig_module_info(const std::string &basename_lower, std::string &out_path, uintptr_t &out_base) {
    out_path.clear();
    out_base = 0;
    if (basename_lower.empty()) return false;

    std::lock_guard<std::mutex> lk(g_mu);
    auto it = g_orig_by_basename.find(basename_lower);
    if (it == g_orig_by_basename.end()) return false;
    out_path = it->second.path;
    out_base = it->second.base;
    return !out_path.empty() && out_base != 0;
}

} // namespace shadow_loader
} // namespace sample

