#include "native_hook.h"

#include <cstdint>
#include <cstdarg>
#include <cstring>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <ctime>

#include <fcntl.h>
#include <dlfcn.h>
#include <android/log.h>
#include <dobby.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/stat.h>

#ifndef ZMOD_ID
#define ZMOD_ID "appxray"
#endif

#define LOG_TAG    "appxray"
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

namespace appxray {
namespace native_hook {

static std::mutex g_mu;
static std::unordered_map<int, std::string> g_fd_path;
static std::vector<std::string> g_patterns;
static int g_log_fd = -1;

static inline bool is_ws(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

static int raw_openat(int dirfd, const char *path, int flags, mode_t mode) {
#if defined(__NR_openat)
    return (int)syscall(__NR_openat, dirfd, path, flags, mode);
#else
    (void)dirfd; (void)path; (void)flags; (void)mode;
    return -1;
#endif
}

static ssize_t raw_write(int fd, const void *buf, size_t count) {
#if defined(__NR_write)
    return (ssize_t)syscall(__NR_write, fd, buf, count);
#else
    (void)fd; (void)buf; (void)count;
    return -1;
#endif
}

static int raw_fdatasync(int fd) {
#if defined(__NR_fdatasync)
    return (int)syscall(__NR_fdatasync, fd);
#elif defined(__NR_fsync)
    return (int)syscall(__NR_fsync, fd);
#else
    (void)fd;
    return -1;
#endif
}

static int raw_mkdirat(int dirfd, const char *path, mode_t mode) {
#if defined(__NR_mkdirat)
    return (int)syscall(__NR_mkdirat, dirfd, path, mode);
#elif defined(__NR_mkdir)
    (void)dirfd;
    return (int)syscall(__NR_mkdir, path, mode);
#else
    (void)dirfd; (void)path; (void)mode;
    return -1;
#endif
}

static void log_line(const char *fmt, ...) {
    int fd = g_log_fd;
    if (fd < 0) return;

    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n <= 0) return;

    size_t to_write = (size_t)n;
    if (to_write >= sizeof(buf)) to_write = sizeof(buf) - 1;
    buf[to_write++] = '\n';

    raw_write(fd, buf, to_write);
    raw_fdatasync(fd);
}

static void ensure_logger(const char *package_name) {
    if (g_log_fd >= 0) return;
    if (!package_name || !*package_name) return;

    // mkdir -p /data/data/<pkg>/log
    char dir[512];
    int dn = snprintf(dir, sizeof(dir), "/data/data/%s/log", package_name);
    if (dn <= 0 || (size_t)dn >= sizeof(dir)) return;

    // Try create intermediate dirs (ignore errors if already exists)
    // /data/data/<pkg> should exist; but be tolerant.
    char base[512];
    int bn = snprintf(base, sizeof(base), "/data/data/%s", package_name);
    if (bn > 0 && (size_t)bn < sizeof(base)) {
        raw_mkdirat(AT_FDCWD, base, 0700);
    }
    raw_mkdirat(AT_FDCWD, dir, 0700);

    // file: <timestamp>-<pid>.log (timestamp uses unix seconds)
    long ts = (long)time(nullptr);
    int pid = (int)getpid();
    char path[640];
    int pn = snprintf(path, sizeof(path), "%s/%ld-%d.log", dir, ts, pid);
    if (pn <= 0 || (size_t)pn >= sizeof(path)) return;

    int fd = raw_openat(AT_FDCWD, path, O_CREAT | O_WRONLY | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) {
        return;
    }
    g_log_fd = fd;
    log_line("AppXray log start: pid=%d package=%s", pid, package_name);
}

static void set_patterns(const char *file_names) {
    std::vector<std::string> out;
    std::string s = file_names ? file_names : "";
    size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && is_ws(s[i])) i++;
        if (i >= s.size()) break;
        size_t j = i;
        while (j < s.size() && !is_ws(s[j])) j++;
        std::string tok = s.substr(i, j - i);
        if (!tok.empty()) out.push_back(std::move(tok));
        i = j;
    }
    std::lock_guard lk(g_mu);
    g_patterns = std::move(out);
    g_fd_path.clear();
}

static bool match_path(const char *path) {
    if (!path) return false;
    std::lock_guard lk(g_mu);
    if (g_patterns.empty()) return true; // monitor all
    std::string_view p{path};
    for (const auto &pat : g_patterns) {
        if (pat.empty()) continue;
        if (p.find(pat) != std::string_view::npos) return true;
    }
    return false;
}

static void record_open_fd(int fd, const char *path) {
    if (fd < 0 || !path) return;
    if (fd == g_log_fd) return;
    if (!match_path(path)) return;
    std::lock_guard lk(g_mu);
    g_fd_path[fd] = path;
}

static const char *path_of_fd(int fd, std::string &tmp) {
    if (fd == g_log_fd) return nullptr;
    std::lock_guard lk(g_mu);
    auto it = g_fd_path.find(fd);
    if (it == g_fd_path.end()) return nullptr;
    tmp = it->second;
    return tmp.c_str();
}

static void erase_fd(int fd) {
    std::lock_guard lk(g_mu);
    g_fd_path.erase(fd);
}

// ---- libc function pointers ----
static int (*orig_open)(const char *pathname, int flags, ...) = nullptr;
static int (*orig_openat)(int dirfd, const char *pathname, int flags, ...) = nullptr;
static ssize_t (*orig_read)(int fd, void *buf, size_t count) = nullptr;
static ssize_t (*orig_write)(int fd, const void *buf, size_t count) = nullptr;
static off_t (*orig_lseek)(int fd, off_t offset, int whence) = nullptr;
static int (*orig_close)(int fd) = nullptr;

static int hooked_open(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    int fd = -1;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = static_cast<mode_t>(va_arg(ap, int));
        va_end(ap);
        fd = orig_open ? orig_open(pathname, flags, mode) : -1;
    } else {
        fd = orig_open ? orig_open(pathname, flags) : -1;
    }

    if (fd >= 0) {
        record_open_fd(fd, pathname);
        if (match_path(pathname)) {
            log_line("open(path=%s, flags=0x%x, mode=%o) => fd=%d",
                 pathname ? pathname : "null", flags, (unsigned)mode, fd);
        }
    }
    return fd;
}

static int hooked_openat(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    int fd = -1;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = static_cast<mode_t>(va_arg(ap, int));
        va_end(ap);
        fd = orig_openat ? orig_openat(dirfd, pathname, flags, mode) : -1;
    } else {
        fd = orig_openat ? orig_openat(dirfd, pathname, flags) : -1;
    }

    if (fd >= 0) {
        record_open_fd(fd, pathname);
        if (match_path(pathname)) {
            log_line("openat(dirfd=%d, path=%s, flags=0x%x, mode=%o) => fd=%d",
                 dirfd, pathname ? pathname : "null", flags, (unsigned)mode, fd);
        }
    }
    return fd;
}

static off_t hooked_lseek(int fd, off_t offset, int whence) {
    off_t r = orig_lseek ? orig_lseek(fd, offset, whence) : (off_t)-1;
    std::string p;
    const char *path = path_of_fd(fd, p);
    if (path) {
        log_line("lseek(fd=%d, path=%s, offset=%lld, whence=%d) => %lld",
             fd, path, (long long)offset, whence, (long long)r);
    }
    return r;
}

static ssize_t hooked_read(int fd, void *buf, size_t count) {
    ssize_t r = orig_read ? orig_read(fd, buf, count) : -1;
    std::string p;
    const char *path = path_of_fd(fd, p);
    if (path) {
        log_line("read(fd=%d, path=%s, count=%zu) => %zd", fd, path, count, r);
    }
    return r;
}

static ssize_t hooked_write(int fd, const void *buf, size_t count) {
    ssize_t r = orig_write ? orig_write(fd, buf, count) : -1;
    std::string p;
    const char *path = path_of_fd(fd, p);
    if (path) {
        log_line("write(fd=%d, path=%s, count=%zu) => %zd", fd, path, count, r);
    }
    return r;
}

static int hooked_close(int fd) {
    std::string p;
    const char *path = path_of_fd(fd, p);
    if (path) {
        log_line("close(fd=%d, path=%s)", fd, path);
    }
    int r = orig_close ? orig_close(fd) : -1;
    if (path) erase_fd(fd);
    return r;
}

static void *sym(void *handle, const char *name) {
    void *p = dlsym(handle, name);
    if (!p) p = dlsym(RTLD_DEFAULT, name);
    return p;
}

static void hook_one(void *handle, const char *name, void *replace, void **backup) {
    void *target = sym(handle, name);
    if (!target) {
        log_line("Symbol not found: %s", name);
        return;
    }
    void *orig = nullptr;
    if (DobbyHook(target, replace, &orig) == 0 && orig) {
        *backup = orig;
        log_line("Hooked %s @ %p", name, target);
    } else {
        log_line("Failed to hook %s @ %p", name, target);
    }
}

void install_hooks(const char *package_name, const char *file_names) {
    ensure_logger(package_name);
    log_line("Installing file hooks (patterns=%s)", file_names ? file_names : "");
    set_patterns(file_names);

    void *libc = dlopen("libc.so", RTLD_NOW);
    if (!libc) {
        log_line("dlopen(libc.so) failed: %s", dlerror());
        return;
    }

    hook_one(libc, "open", to_void_ptr(hooked_open), reinterpret_cast<void **>(&orig_open));
    hook_one(libc, "openat", to_void_ptr(hooked_openat), reinterpret_cast<void **>(&orig_openat));
    hook_one(libc, "read", to_void_ptr(hooked_read), reinterpret_cast<void **>(&orig_read));
    hook_one(libc, "write", to_void_ptr(hooked_write), reinterpret_cast<void **>(&orig_write));
    hook_one(libc, "lseek", to_void_ptr(hooked_lseek), reinterpret_cast<void **>(&orig_lseek));
    hook_one(libc, "close", to_void_ptr(hooked_close), reinterpret_cast<void **>(&orig_close));
}

} // namespace native_hook
} // namespace appxray

