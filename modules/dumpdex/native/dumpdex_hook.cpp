#include "dumpdex_hook.h"

#include <android/log.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

#include <dobby.h>

#ifndef ZMOD_ID
#define ZMOD_ID "dumpdex"
#endif

#define LOG_TAG    ZMOD_ID
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace dumpdex {
namespace {

constexpr const char* kLibDexfile = "libdexfile.so";
constexpr const char* kOpenCommonSym =
    "_ZN3art13DexFileLoader10OpenCommonENSt3__110shared_ptrINS_16DexFileContainerEEEPKhmRKNS1_12basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEENS1_8optionalIjEEPKNS_10OatDexFileEbbPSC_PNS_22DexFileLoaderErrorCodeE";

static std::string g_pkg;
static std::once_flag g_mkdir_once;
static std::atomic<bool> g_dumpdir_ok{false};
static std::atomic<uint32_t> g_index{1};
static std::atomic<bool> g_opencommon_hooked{false};
static std::atomic<bool> g_dlopen_hooked{false};
static std::mutex g_hook_mu;

static const char* dlerr() {
    const char* e = dlerror();
    return (e && e[0] != '\0') ? e : "unknown";
}

static bool mkdir_if_needed(const char* path, mode_t mode) {
    if (!path || path[0] == '\0') return false;
    if (mkdir(path, mode) == 0) return true;
    if (errno == EEXIST) return true;
    return false;
}

static bool ensure_dump_dir() {
    if (g_pkg.empty()) {
        LOGE("ensure_dump_dir: package name is empty");
        return false;
    }
    std::call_once(g_mkdir_once, []() {
        std::string dir = std::string("/data/data/") + g_pkg + "/dumpdex";
        if (mkdir_if_needed(dir.c_str(), 0700)) {
            g_dumpdir_ok.store(true, std::memory_order_release);
            return;
        }
        int e = errno;
        LOGE("mkdir failed: %s (errno=%d: %s)", dir.c_str(), e, strerror(e));
        g_dumpdir_ok.store(false, std::memory_order_release);
    });
    if (!g_dumpdir_ok.load(std::memory_order_acquire)) {
        LOGE("dump dir is not available, skip dumping");
        return false;
    }
    return true;
}

static bool write_all(int fd, const uint8_t* p, size_t n) {
    while (n > 0) {
        ssize_t r = TEMP_FAILURE_RETRY(write(fd, p, n));
        if (r < 0) return false;
        p += static_cast<size_t>(r);
        n -= static_cast<size_t>(r);
    }
    return true;
}

static void dump_dex_if_possible(const uint8_t* base, size_t size) {
    if (!base) {
        LOGE("dump_dex_if_possible: base is null");
        return;
    }
    if (size == 0) {
        LOGE("dump_dex_if_possible: size is 0");
        return;
    }
    if (!ensure_dump_dir()) {
        LOGE("dump_dex_if_possible: ensure_dump_dir failed");
        return;
    }

    uint32_t idx = g_index.fetch_add(1, std::memory_order_relaxed);
    char path[512];
    int n = snprintf(path, sizeof(path), "/data/data/%s/dumpdex/%u-classes.dex", g_pkg.c_str(), idx);
    if (n <= 0 || static_cast<size_t>(n) >= sizeof(path)) {
        LOGE("path too long for package=%s", g_pkg.c_str());
        return;
    }

    int fd = TEMP_FAILURE_RETRY(open(path, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0644));
    if (fd < 0) {
        int e = errno;
        LOGE("open failed: %s (errno=%d: %s)", path, e, strerror(e));
        return;
    }

    bool ok = write_all(fd, base, size);
    if (!ok) {
        int e = errno;
        LOGE("write failed: %s (errno=%d: %s)", path, e, strerror(e));
    }
    close(fd);
    if (ok) {
        LOGI("dumped dex: %s (base=%p size=%zu)", path, base, size);
    }
}

// `OpenCommon` returns `std::unique_ptr<art::DexFile>` by value.
// On AArch64 this is returned via a hidden sret pointer (X8).
//
// We cannot use `std::unique_ptr<void>` here because libc++ forbids deleting incomplete types,
// and we'd end up instantiating `default_delete<void>`. Also, we must preserve the ABI:
// `std::unique_ptr<T>` with default deleter is a single pointer (empty deleter is EBO),
// and it's non-trivial -> sret.
//
// This small wrapper matches that ABI sufficiently for pass-through:
// - size/alignment: 8 bytes
// - non-trivial (has dtor/move)
// - first word is the managed pointer
struct UniquePtrLike {
    void* p = nullptr;
    UniquePtrLike() = default;
    ~UniquePtrLike() = default; // do NOT delete here; caller owns real unique_ptr semantics
    UniquePtrLike(UniquePtrLike&& o) noexcept : p(o.p) { o.p = nullptr; }
    UniquePtrLike& operator=(UniquePtrLike&& o) noexcept {
        if (this != &o) {
            p = o.p;
            o.p = nullptr;
        }
        return *this;
    }
    UniquePtrLike(const UniquePtrLike&) = delete;
    UniquePtrLike& operator=(const UniquePtrLike&) = delete;
    explicit operator bool() const { return p != nullptr; }
};

using OpenCommonFn = UniquePtrLike (*)(
    std::shared_ptr<void> /*container*/,
    const uint8_t* /*base*/,
    size_t /*app_compat_size*/,
    const std::string& /*location*/,
    std::optional<uint32_t> /*location_checksum*/,
    const void* /*oat_dex_file*/,
    bool /*verify*/,
    bool /*verify_checksum*/,
    std::string* /*error_msg*/,
    void* /*error_code*/);

static OpenCommonFn g_orig_opencommon = nullptr;

static UniquePtrLike hooked_OpenCommon(std::shared_ptr<void> container,
                                       const uint8_t* base,
                                       size_t app_compat_size,
                                       const std::string& location,
                                       std::optional<uint32_t> location_checksum,
                                       const void* oat_dex_file,
                                       bool verify,
                                       bool verify_checksum,
                                       std::string* error_msg,
                                       void* error_code) {
    (void)location;
    (void)location_checksum;

    OpenCommonFn orig = g_orig_opencommon;
    if (!orig) return {};

    UniquePtrLike ret = orig(std::move(container),
                             base,
                             app_compat_size,
                             location,
                             location_checksum,
                             oat_dex_file,
                             verify,
                             verify_checksum,
                             error_msg,
                             error_code);

    if (ret) {
        dump_dex_if_possible(base, app_compat_size);
    }
    return ret;
}

template <typename T>
static inline void* to_void_ptr(T fn_or_ptr) {
    return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(fn_or_ptr));
}

static bool hook_opencommon_locked() {
    if (g_opencommon_hooked.load(std::memory_order_acquire)) return true;

    // Ensure libdexfile is loaded, but avoid forcing load if possible.
    void* handle = nullptr;
#if defined(RTLD_NOLOAD)
    dlerror(); // clear
    handle = dlopen(kLibDexfile, RTLD_NOW | RTLD_NOLOAD);
#endif
    if (!handle) {
        dlerror(); // clear
        handle = dlopen(kLibDexfile, RTLD_NOW);
    }
    if (!handle) {
        LOGE("dlopen failed: %s (%s)", kLibDexfile, dlerr());
        return false;
    }

    dlerror(); // clear
    void* sym = dlsym(RTLD_DEFAULT, kOpenCommonSym);
    if (!sym) {
        // try from explicit handle
        dlerror(); // clear
        sym = dlsym(handle, kOpenCommonSym);
    }
    if (!sym) {
        LOGE("dlsym failed: %s (%s)", kOpenCommonSym, dlerr());
        return false;
    }

    void* orig = nullptr;
    int rc = DobbyHook(sym, to_void_ptr(hooked_OpenCommon), &orig);
    if (rc == 0 && orig) {
        g_orig_opencommon = reinterpret_cast<OpenCommonFn>(orig);
        g_opencommon_hooked.store(true, std::memory_order_release);
        LOGI("Hooked OpenCommon @ %p", sym);
        return true;
    }
    LOGE("Failed to hook OpenCommon @ %p (rc=%d orig=%p)", sym, rc, orig);
    return false;
}

using android_dlopen_ext_t = void* (*)(const char* filename, int flags, const void* extinfo);
static android_dlopen_ext_t g_orig_android_dlopen_ext = nullptr;

static void* hooked_android_dlopen_ext(const char* filename, int flags, const void* extinfo) {
    void* handle = g_orig_android_dlopen_ext ? g_orig_android_dlopen_ext(filename, flags, extinfo) : nullptr;
    if (filename && strstr(filename, kLibDexfile) != nullptr) {
        if (!handle) {
            LOGE("android_dlopen_ext loaded %s failed (flags=0x%x)", filename, flags);
            return nullptr;
        }
        std::lock_guard<std::mutex> lk(g_hook_mu);
        if (!hook_opencommon_locked()) {
            LOGE("OpenCommon hook not installed after loading %s", filename);
        }
    }
    return handle;
}

static void* resolve_android_dlopen_ext() {
    void* sym = dlsym(RTLD_DEFAULT, "android_dlopen_ext");
    if (sym) return sym;
    void* libdl = dlopen("libdl.so", RTLD_NOW);
    if (libdl) {
        sym = dlsym(libdl, "android_dlopen_ext");
        if (sym) return sym;
    }
    return nullptr;
}

static void hook_android_dlopen_ext_once() {
    if (g_dlopen_hooked.load(std::memory_order_acquire)) return;

    void* target = resolve_android_dlopen_ext();
    if (!target) {
        LOGE("Symbol not found: android_dlopen_ext");
        return;
    }

    void* orig = nullptr;
    int rc = DobbyHook(target, to_void_ptr(hooked_android_dlopen_ext), &orig);
    if (rc == 0 && orig) {
        g_orig_android_dlopen_ext = reinterpret_cast<android_dlopen_ext_t>(orig);
        g_dlopen_hooked.store(true, std::memory_order_release);
        LOGI("Hooked android_dlopen_ext @ %p", target);
    } else {
        LOGE("Failed to hook android_dlopen_ext @ %p (rc=%d orig=%p)", target, rc, orig);
    }
}

} // namespace

void install(const std::string& package_name) {
    if (package_name.empty()) {
        LOGE("install: empty package name");
    }
    g_pkg = package_name;
    hook_android_dlopen_ext_once();

    // If libdexfile is already loaded, hook immediately.
    std::lock_guard<std::mutex> lk(g_hook_mu);
    if (!hook_opencommon_locked()) {
        LOGE("OpenCommon hook not installed (libdexfile not loaded yet or symbol missing)");
    }
}

} // namespace dumpdex

