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

static bool has_substr_case_insensitive(const char *haystack, const std::string &needle_lower) {
    if (!haystack) return false;
    std::string h = to_lower(std::string(haystack));
    return h.find(needle_lower) != std::string::npos;
}

static inline int raw_openat(int dirfd, const char *path, int flags, mode_t mode) {
    return (int)syscall(SYS_openat, dirfd, path, flags, mode);
}
static inline int raw_close(int fd) {
    return (int)syscall(SYS_close, fd);
}
static inline ssize_t raw_read(int fd, void *buf, size_t n) {
    return (ssize_t)syscall(SYS_read, fd, buf, n);
}

static bool collect_maps_stats_for_basename(const std::string &basename_lower,
                                            uintptr_t &out_base,
                                            size_t &out_sum_size) {
    out_base = 0;
    out_sum_size = 0;
    if (basename_lower.empty()) return false;

    int fd = raw_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return false;

    std::string content;
    char buf[8192];
    for (;;) {
        ssize_t n = raw_read(fd, buf, sizeof(buf));
        if (n == 0) break;
        if (n < 0) {
            raw_close(fd);
            return false;
        }
        content.append(buf, buf + n);
        if (content.size() > (8u * 1024u * 1024u)) break; // sanity cap
    }
    raw_close(fd);

    auto parse_range = [](const std::string &line, uintptr_t &start, uintptr_t &end) -> bool {
        size_t dash = line.find('-');
        if (dash == std::string::npos) return false;
        size_t sp = line.find(' ', dash + 1);
        if (sp == std::string::npos) return false;
        std::string a = line.substr(0, dash);
        std::string b = line.substr(dash + 1, sp - (dash + 1));
        if (a.empty() || b.empty()) return false;
        char *e1 = nullptr;
        char *e2 = nullptr;
        errno = 0;
        unsigned long long va = std::strtoull(a.c_str(), &e1, 16);
        unsigned long long vb = std::strtoull(b.c_str(), &e2, 16);
        if (errno != 0 || !e1 || *e1 != '\0' || !e2 || *e2 != '\0') return false;
        start = (uintptr_t)va;
        end = (uintptr_t)vb;
        return end > start;
    };

    auto extract_path = [](const std::string &line) -> std::string {
        size_t slash = line.find('/');
        if (slash == std::string::npos) return {};
        return line.substr(slash);
    };

    size_t pos = 0;
    while (pos < content.size()) {
        size_t nl = content.find('\n', pos);
        std::string line = (nl == std::string::npos) ? content.substr(pos) : content.substr(pos, nl - pos);
        pos = (nl == std::string::npos) ? content.size() : (nl + 1);

        uintptr_t start = 0, end = 0;
        if (!parse_range(line, start, end)) continue;

        std::string path = extract_path(line);
        if (path.empty()) continue;
        std::string path_lower = to_lower(path);
        std::string bn = basename_lower_of(path_lower);
        if (bn != basename_lower) continue;

        if (out_base == 0 || start < out_base) out_base = start;
        out_sum_size += (size_t)(end - start);
    }

    return out_base != 0 && out_sum_size != 0;
}

static std::string find_loaded_path_by_target_locked(const std::string &target_lower) {
    std::string found;
    auto cb = [](struct dl_phdr_info *info, size_t /*size*/, void *data) -> int {
        auto *ctx = reinterpret_cast<std::pair<const std::string *, std::string *> *>(data);
        const std::string &needle_lower = *ctx->first;
        std::string &out = *ctx->second;

        const char *name = info ? info->dlpi_name : nullptr;
        if (!name || name[0] == '\0') return 0;
        if (has_substr_case_insensitive(name, needle_lower)) {
            out = name;
            return 1; // stop
        }
        return 0;
    };

    std::pair<const std::string *, std::string *> ctx{&target_lower, &found};
    dl_iterate_phdr(cb, &ctx);
    return found;
}

static bool shadow_load_path_locked(const std::string &target_lower, const std::string &path) {
    if (path.empty()) return false;
    if (g_loaded_targets.find(target_lower) != g_loaded_targets.end()) return true;

    // CSOLoader may abort/crash on some core/runtime libraries (e.g. /apex/libc.so, /apex/libart.so)
    // depending on device/linker implementation. Shadow-loading is an optional hardening step for
    // "hide" and should never prevent the rest of hooks from working.
    auto starts_with = [](const std::string &s, const char *p) -> bool {
        const size_t n = std::strlen(p);
        return s.size() >= n && std::memcmp(s.data(), p, n) == 0;
    };
    if (starts_with(path, "/apex/") || starts_with(path, "/system/") || starts_with(path, "/vendor/") ||
        starts_with(path, "/product/") || starts_with(path, "/odm/") || starts_with(path, "/system_ext/")) {
        LOGW("[%s][shadow] skip shadow-load for %s (path=%s)", ZMOD_ID, target_lower.c_str(), path.c_str());
        g_loaded_targets.insert(target_lower);
        auto &info = g_info_by_target[target_lower];
        info.name_lower = target_lower;
        info.orig_path = path;
        return true;
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
    if (info.orig_base == 0 || info.orig_size == 0) {
        const std::string bn = basename_lower_of(to_lower(info.orig_path.empty() ? target_lower : info.orig_path));
        uintptr_t ob = 0;
        size_t osz = 0;
        if (collect_maps_stats_for_basename(bn, ob, osz)) {
            info.orig_base = ob;
            info.orig_size = osz;
        }
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

    // Best effort: prefer real loaded path (dl_iterate_phdr) over argument string.
    std::string path = find_loaded_path_by_target_locked(matched_target);
    if (path.empty() && std::strchr(name, '/') != nullptr) path = name;
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

#if defined(__LP64__)
    const char *linker_name = "linker64";
#else
    const char *linker_name = "linker";
#endif
    const std::string sym = "__dl__Z9do_dlopenPKciPK17android_dlextinfoPKv";

    SandHook::ElfImg linker_img(linker_name);
    if (!linker_img.isValid()) {
        LOGE("[%s][shadow] linker module not found: %s", ZMOD_ID, linker_name);
        return false;
    }
    void *target = linker_img.getSymbAddress<void *>(sym);
    if (!target) {
        LOGE("[%s][shadow] do_dlopen symbol not found in %s", ZMOD_ID, linker_name);
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

    // First pass: enumerate currently loaded modules and shadow-load those we can find.
    std::unordered_set<std::string> pending = g_targets;
    for (const auto &t : g_targets) {
        std::string path = find_loaded_path_by_target_locked(t);
        if (!path.empty()) {
            auto &info = g_info_by_target[t];
            info.orig_path = path;
            if (info.orig_base == 0 || info.orig_size == 0) {
                const std::string bn = basename_lower_of(to_lower(path));
                uintptr_t ob = 0;
                size_t osz = 0;
                if (collect_maps_stats_for_basename(bn, ob, osz)) {
                    info.orig_base = ob;
                    info.orig_size = osz;
                }
            }
            if (!shadow_load_path_locked(t, path)) {
                LOGE("[%s][shadow] shadow-load failed for %s; stop", ZMOD_ID, t.c_str());
                return false;
            }
            pending.erase(t);
        }
    }

    // If something is still missing, hook do_dlopen so we can shadow-load it immediately
    // after it gets loaded by the app/runtime.
    if (!pending.empty()) {
        // Some ROMs/Android versions have fragile linker symbol resolution; installing
        // a do_dlopen hook can crash the process. Shadow-loading is an optional feature
        // for hiding, so prefer continuing without late-load support.
        LOGW("[%s][shadow] pending targets=%zu; skip do_dlopen hook and continue", ZMOD_ID, pending.size());
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

} // namespace shadow_loader
} // namespace sample

