#include "maps_hook.h"

#include <android/log.h>
#include <cctype>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>

#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <unistd.h>

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
namespace maps_hook {
namespace {

static std::string g_pkg;

using openat_real_t = int (*)(int, const char *, int, mode_t);
using open_real_t = int (*)(const char *, int, mode_t);
using fopen_real_t = FILE *(*)(const char *, const char *);

static openat_real_t old_openat = nullptr;
static open_real_t old_open = nullptr;
static fopen_real_t old_fopen = nullptr;
static fopen_real_t old_fopen64 = nullptr;

static inline int raw_openat(int dirfd, const char *path, int flags, mode_t mode) {
    return (int)syscall(SYS_openat, dirfd, path, flags, mode);
}
static inline int raw_close(int fd) {
    return (int)syscall(SYS_close, fd);
}
static inline ssize_t raw_read(int fd, void *buf, size_t n) {
    return (ssize_t)syscall(SYS_read, fd, buf, n);
}
static inline ssize_t raw_write(int fd, const void *buf, size_t n) {
    return (ssize_t)syscall(SYS_write, fd, buf, n);
}
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

static inline int raw_memfd_create(const char *name, unsigned int flags) {
#ifdef SYS_memfd_create
    return (int)syscall(SYS_memfd_create, name, flags);
#else
    (void)name;
    (void)flags;
    errno = ENOSYS;
    return -1;
#endif
}

static inline off_t raw_lseek(int fd, off_t off, int whence) {
#ifdef SYS_lseek
    return (off_t)syscall(SYS_lseek, fd, off, whence);
#elif defined(SYS__llseek)
    // Fallback for some 32-bit archs; not expected on arm64.
    (void)fd;
    (void)off;
    (void)whence;
    errno = ENOSYS;
    return (off_t)-1;
#else
    return lseek(fd, off, whence);
#endif
}

static bool read_text_file_raw(const char *path, std::string &out) {
    out.clear();
    if (!path || path[0] == '\0') return false;
    int fd = raw_openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return false;

    char buf[8192];
    for (;;) {
        ssize_t n = raw_read(fd, buf, sizeof(buf));
        if (n == 0) break;
        if (n < 0) {
            raw_close(fd);
            return false;
        }
        out.append(buf, buf + n);
        if (out.size() > (8u * 1024u * 1024u)) break; // sanity cap
    }
    raw_close(fd);
    return !out.empty();
}

static bool rewrite_maps_for_shadow_modules(const std::string &content, std::string &out) {
    const auto shadows = sample::shadow_loader::snapshot_modules();
    if (shadows.empty()) {
        out = content;
        return true; // nothing to rewrite
    }

    // Determine original base for each module from the first matching line.
    std::unordered_map<std::string, uintptr_t> orig_base;

    auto find_path_start = [](const std::string &line) -> size_t {
        size_t slash = line.find('/');
        if (slash != std::string::npos) return slash;
        // Some maps lines may use "[vdso]" etc; we only rewrite file-backed mappings.
        return std::string::npos;
    };

    auto parse_range = [](const std::string &line, uintptr_t &start, uintptr_t &end, int &w1, int &w2) -> bool {
        // Parse "<hex>-<hex> " at the beginning.
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
        w1 = (int)a.size();
        w2 = (int)b.size();
        return true;
    };

    auto to_lower_copy = [](const std::string &s) -> std::string {
        std::string o;
        o.reserve(s.size());
        for (unsigned char c : s) o.push_back((char)std::tolower(c));
        return o;
    };

    // First pass: collect original base per module.
    {
        size_t pos = 0;
        while (pos < content.size()) {
            size_t nl = content.find('\n', pos);
            std::string line = (nl == std::string::npos) ? content.substr(pos) : content.substr(pos, nl - pos);
            pos = (nl == std::string::npos) ? content.size() : (nl + 1);

            uintptr_t start = 0, end = 0;
            int w1 = 0, w2 = 0;
            if (!parse_range(line, start, end, w1, w2)) continue;

            size_t pstart = find_path_start(line);
            if (pstart == std::string::npos) continue;

            std::string path_lower = to_lower_copy(line.substr(pstart));
            for (const auto &s : shadows) {
                if (s.name_lower.empty() || s.shadow_base == 0) continue;
                if (orig_base.find(s.name_lower) != orig_base.end()) continue;
                if (path_lower.find(s.name_lower) != std::string::npos) {
                    orig_base[s.name_lower] = start;
                }
            }
            if (orig_base.size() == shadows.size()) break;
        }
    }

    // Second pass: rewrite addresses using delta = shadow_base - orig_base.
    out.clear();
    out.reserve(content.size());
    size_t pos = 0;
    while (pos < content.size()) {
        size_t nl = content.find('\n', pos);
        bool has_nl = (nl != std::string::npos);
        std::string line = has_nl ? content.substr(pos, nl - pos) : content.substr(pos);
        pos = has_nl ? (nl + 1) : content.size();

        uintptr_t start = 0, end = 0;
        int w1 = 0, w2 = 0;
        if (!parse_range(line, start, end, w1, w2)) {
            out.append(line);
            if (has_nl) out.push_back('\n');
            continue;
        }

        size_t pstart = line.find('/');
        if (pstart == std::string::npos) {
            out.append(line);
            if (has_nl) out.push_back('\n');
            continue;
        }

        std::string path_lower = to_lower_copy(line.substr(pstart));
        const sample::shadow_loader::ShadowModuleInfo *match = nullptr;
        for (const auto &s : shadows) {
            if (s.name_lower.empty() || s.shadow_base == 0) continue;
            if (path_lower.find(s.name_lower) != std::string::npos) {
                match = &s;
                break;
            }
        }

        if (!match) {
            out.append(line);
            if (has_nl) out.push_back('\n');
            continue;
        }

        auto it = orig_base.find(match->name_lower);
        if (it == orig_base.end()) {
            out.append(line);
            if (has_nl) out.push_back('\n');
            continue;
        }

        uintptr_t ob = it->second;
        intptr_t delta = (intptr_t)match->shadow_base - (intptr_t)ob;
        uintptr_t ns = (uintptr_t)((intptr_t)start + delta);
        uintptr_t ne = (uintptr_t)((intptr_t)end + delta);

        // Replace the leading range with padded hex of the same width.
        char range_buf[64];
        std::snprintf(range_buf, sizeof(range_buf), "%0*lx-%0*lx", w1, (unsigned long)ns, w2, (unsigned long)ne);

        size_t dash = line.find('-');
        size_t sp = line.find(' ', dash + 1);
        std::string rewritten = std::string(range_buf) + line.substr(sp);

        out.append(rewritten);
        if (has_nl) out.push_back('\n');
    }

    return true;
}

static bool build_rewritten_maps_for_path(const char *maps_path, std::string &out) {
    std::string content;
    if (!read_text_file_raw(maps_path, content)) return false;
    if (!rewrite_maps_for_shadow_modules(content, out)) return false;
    return true;
}

static int create_memfd_with_content(const char *tag, const std::string &content, bool cloexec) {
    unsigned int mfd_flags = cloexec ? MFD_CLOEXEC : 0U;
    int fd = raw_memfd_create(tag ? tag : "maps", mfd_flags);
    if (fd < 0) return -1;

    size_t off = 0;
    while (off < content.size()) {
        ssize_t n = raw_write(fd, content.data() + off, content.size() - off);
        if (n <= 0) {
            raw_close(fd);
            return -1;
        }
        off += (size_t)n;
    }
    (void)raw_lseek(fd, 0, SEEK_SET);
    return fd;
}

static bool is_current_maps_path(const char *path) {
    if (!path) return false;
    // Exact /proc/self/maps
    if (std::strcmp(path, "/proc/self/maps") == 0) return true;

    // /proc/<pid>/maps
    constexpr const char *prefix = "/proc/";
    constexpr const char *suffix = "/maps";
    const size_t len = std::strlen(path);
    const size_t pre_len = std::strlen(prefix);
    const size_t suf_len = std::strlen(suffix);
    if (len <= pre_len + suf_len) return false;
    if (std::strncmp(path, prefix, pre_len) != 0) return false;
    if (std::strcmp(path + (len - suf_len), suffix) != 0) return false;

    // parse pid in between
    size_t i = pre_len;
    long pid = 0;
    for (; i < len - suf_len; i++) {
        char c = path[i];
        if (!std::isdigit((unsigned char)c)) return false;
        pid = pid * 10 + (c - '0');
        if (pid > 1'000'000) return false;
    }
    return pid == (long)getpid();
}

static mode_t extract_mode_if_needed(int flags, va_list ap) {
    // open/openat require mode when O_CREAT (and O_TMPFILE behaves similarly).
    if (flags & O_CREAT) {
        return (mode_t)va_arg(ap, int);
    }
#ifdef O_TMPFILE
    if ((flags & O_TMPFILE) == O_TMPFILE) {
        return (mode_t)va_arg(ap, int);
    }
#endif
    return 0;
}

static int new_openat(int dirfd, const char *pathname, int flags, ...) {
    va_list ap;
    va_start(ap, flags);
    mode_t mode = extract_mode_if_needed(flags, ap);
    va_end(ap);

    if (is_current_maps_path(pathname) && old_openat) {
        // Only handle read-only opens for /proc/*/maps.
        if ((flags & (O_WRONLY | O_RDWR)) == 0 && (flags & O_CREAT) == 0 && (flags & O_TRUNC) == 0) {
            std::string rewritten;
            if (build_rewritten_maps_for_path(pathname, rewritten)) {
                bool cloexec = (flags & O_CLOEXEC) != 0;
                int mfd = create_memfd_with_content("maps", rewritten, cloexec);
                if (mfd >= 0) return mfd;
            }
        }
        return old_openat(dirfd, pathname, flags, mode);
    }
    return old_openat ? old_openat(dirfd, pathname, flags, mode) : -1;
}

static int new_open(const char *pathname, int flags, ...) {
    va_list ap;
    va_start(ap, flags);
    mode_t mode = extract_mode_if_needed(flags, ap);
    va_end(ap);

    if (is_current_maps_path(pathname) && old_open) {
        if ((flags & (O_WRONLY | O_RDWR)) == 0 && (flags & O_CREAT) == 0 && (flags & O_TRUNC) == 0) {
            std::string rewritten;
            if (build_rewritten_maps_for_path(pathname, rewritten)) {
                bool cloexec = (flags & O_CLOEXEC) != 0;
                int mfd = create_memfd_with_content("maps", rewritten, cloexec);
                if (mfd >= 0) return mfd;
            }
        }
        return old_open(pathname, flags, mode);
    }
    return old_open ? old_open(pathname, flags, mode) : -1;
}

static FILE *new_fopen(const char *pathname, const char *mode) {
    if (is_current_maps_path(pathname) && old_fopen) {
        // Only replace for pure read modes.
        if (mode && mode[0] == 'r' && std::strchr(mode, '+') == nullptr) {
            std::string rewritten;
            if (build_rewritten_maps_for_path(pathname, rewritten)) {
                int mfd = create_memfd_with_content("maps", rewritten, false);
                if (mfd >= 0) {
                    FILE *fp = fdopen(mfd, "r");
                    if (fp) return fp;
                    raw_close(mfd);
                }
            }
        }
        return old_fopen(pathname, mode);
    }
    return old_fopen ? old_fopen(pathname, mode) : nullptr;
}

static FILE *new_fopen64(const char *pathname, const char *mode) {
    if (is_current_maps_path(pathname) && old_fopen64) {
        if (mode && mode[0] == 'r' && std::strchr(mode, '+') == nullptr) {
            std::string rewritten;
            if (build_rewritten_maps_for_path(pathname, rewritten)) {
                int mfd = create_memfd_with_content("maps", rewritten, false);
                if (mfd >= 0) {
                    FILE *fp = fdopen(mfd, "r");
                    if (fp) return fp;
                    raw_close(mfd);
                }
            }
        }
        return old_fopen64(pathname, mode);
    }
    return old_fopen64 ? old_fopen64(pathname, mode) : nullptr;
}

static void *resolve_sym(const char *sym) {
    void *p = dlsym(RTLD_DEFAULT, sym);
    if (p) return p;
    void *libc = dlopen("libc.so", RTLD_NOW);
    if (libc) {
        p = dlsym(libc, sym);
    }
    return p;
}

template <typename T>
static bool hook_func(const char *sym, void *replacement, T *orig_out) {
    void *target = resolve_sym(sym);
    if (!target) {
        LOGE("[%s][maps] symbol not found: %s", ZMOD_ID, sym);
        return false;
    }
    void *orig = nullptr;
    if (DobbyHook(target, replacement, &orig) == 0 && orig) {
        *orig_out = reinterpret_cast<T>(orig);
        LOGI("[%s][maps] hooked %s @ %p", ZMOD_ID, sym, target);
        return true;
    }
    LOGE("[%s][maps] failed to hook %s @ %p", ZMOD_ID, sym, target);
    return false;
}

} // namespace

bool install(const std::string &package_name, const std::string &app_data_dir) {
    if (package_name.empty()) {
        LOGE("[%s][maps] install failed: empty package", ZMOD_ID);
        return false;
    }
    (void)app_data_dir; // no longer used (memfd-based)
    if (!g_pkg.empty()) {
        LOGI("[%s][maps] already installed", ZMOD_ID);
        return true;
    }

    g_pkg = package_name;

    LOGI("[%s][maps] installing open/openat/fopen hooks (pkg=%s)", ZMOD_ID, g_pkg.c_str());
    bool ok = true;
    ok &= hook_func("openat", (void *)new_openat, &old_openat);
    ok &= hook_func("open", (void *)new_open, &old_open);
    ok &= hook_func("fopen", (void *)new_fopen, &old_fopen);
    if (!ok) {
        LOGE("[%s][maps] install failed; abort maps hook", ZMOD_ID);
        return false;
    }

    // fopen64 is optional on modern Android (often an alias of fopen).
    void *fopen_target = resolve_sym("fopen");
    void *fopen64_target = resolve_sym("fopen64");
    if (!fopen64_target || fopen64_target == fopen_target) {
        old_fopen64 = old_fopen;
        LOGI("[%s][maps] fopen64 is missing/alias; using fopen instead", ZMOD_ID);
    } else {
        if (!hook_func("fopen64", (void *)new_fopen64, &old_fopen64)) {
            old_fopen64 = old_fopen;
            LOGW("[%s][maps] fopen64 hook failed; fallback to fopen", ZMOD_ID);
        }
    }

    LOGI("[%s][maps] install ok (memfd)", ZMOD_ID);
    return true;
}

} // namespace maps_hook
} // namespace sample

