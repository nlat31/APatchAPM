#include "dumpdex_hook.h"

#include <android/log.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <elf.h>
#include <link.h>
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
constexpr const char* kOpenCommonNeedle1 = "_ZN3art13DexFileLoader10OpenCommonE";
constexpr const char* kOpenCommonNeedle2 = "DexFileLoader10OpenCommon";
// Extra constraint to pick the intended overload:
// OpenCommon(std::shared_ptr<DexFileContainer>, ...)
constexpr const char* kOpenCommonNeedleSharedPtrContainer = "NSt3__110shared_ptrINS_16DexFileContainerEEE";
constexpr const char* kNeedleSharedPtr = "shared_ptr";
constexpr const char* kNeedleDexFileContainer = "DexFileContainer";

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

static bool ends_with(const char* s, const char* suffix) {
    if (!s || !suffix) return false;
    const size_t ls = strlen(s);
    const size_t lf = strlen(suffix);
    if (lf > ls) return false;
    return memcmp(s + (ls - lf), suffix, lf) == 0;
}

static bool contains(const char* haystack, const char* needle) {
    if (!haystack || !needle) return false;
    return strstr(haystack, needle) != nullptr;
}

static unsigned elf_st_type(unsigned char st_info) {
#if defined(__LP64__)
    return ELF64_ST_TYPE(st_info);
#else
    return ELF32_ST_TYPE(st_info);
#endif
}

static bool is_opencommon_shared_ptr_container_overload(const char* sym_name) {
    if (!sym_name) return false;
    // Prefer strict mangled encoding when present, but allow more relaxed matching
    // to tolerate libc++ inline namespace differences (e.g. __1 vs __ndk1).
    if (contains(sym_name, kOpenCommonNeedleSharedPtrContainer)) return true;
    return contains(sym_name, kNeedleSharedPtr) && contains(sym_name, kNeedleDexFileContainer);
}

static size_t symcount_from_gnu_hash(const void* gnu_hash) {
    if (!gnu_hash) return 0;

    const uint8_t* p = reinterpret_cast<const uint8_t*>(gnu_hash);
    const uint32_t nbuckets = *reinterpret_cast<const uint32_t*>(p + 0);
    const uint32_t symoffset = *reinterpret_cast<const uint32_t*>(p + 4);
    const uint32_t bloom_size = *reinterpret_cast<const uint32_t*>(p + 8);
    // bloom_shift at +12 (unused here)

    if (nbuckets == 0) return symoffset;

    // Layout:
    // u32 nbuckets; u32 symoffset; u32 bloom_size; u32 bloom_shift;
    // ElfW(Addr) bloom[bloom_size];
    // u32 buckets[nbuckets];
    // u32 chain[];
    const size_t hdr_sz = 16;
    const size_t bloom_sz_bytes = static_cast<size_t>(bloom_size) * sizeof(ElfW(Addr));
    const uint32_t* buckets = reinterpret_cast<const uint32_t*>(p + hdr_sz + bloom_sz_bytes);
    const uint32_t* chain = buckets + nbuckets;

    uint32_t max_sym = 0;
    for (uint32_t i = 0; i < nbuckets; i++) {
        if (buckets[i] > max_sym) max_sym = buckets[i];
    }
    if (max_sym < symoffset) return symoffset;

    // Walk the chain table until we hit an entry with LSB=1 (end of chain).
    uint32_t idx = max_sym;
    while (true) {
        const uint32_t c = chain[idx - symoffset];
        idx++;
        if ((c & 1u) != 0) break;
        // safety bound (shouldn't happen unless corrupt)
        if (idx - max_sym > 1'000'000u) return 0;
    }
    return static_cast<size_t>(idx);
}

struct DynSymView {
    const ElfW(Sym)* symtab = nullptr;
    const char* strtab = nullptr;
    size_t strsz = 0;
    size_t symcount = 0;
};

static bool build_dynsym_view(const dl_phdr_info* info, DynSymView& out) {
    if (!info || !info->dlpi_phdr) return false;
    const ElfW(Addr) base = static_cast<ElfW(Addr)>(info->dlpi_addr);

    const ElfW(Phdr)* phdr = info->dlpi_phdr;
    const ElfW(Dyn)* dyn = nullptr;
    for (ElfW(Half) i = 0; i < info->dlpi_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = reinterpret_cast<const ElfW(Dyn)*>(base + phdr[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return false;

    const void* hash = nullptr;
    const void* gnu_hash = nullptr;
    const ElfW(Sym)* symtab = nullptr;
    const char* strtab = nullptr;
    size_t strsz = 0;

    for (const ElfW(Dyn)* d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
            case DT_SYMTAB:
                symtab = reinterpret_cast<const ElfW(Sym)*>(d->d_un.d_ptr);
                break;
            case DT_STRTAB:
                strtab = reinterpret_cast<const char*>(d->d_un.d_ptr);
                break;
            case DT_STRSZ:
                strsz = static_cast<size_t>(d->d_un.d_val);
                break;
            case DT_HASH:
                hash = reinterpret_cast<const void*>(d->d_un.d_ptr);
                break;
            case DT_GNU_HASH:
                gnu_hash = reinterpret_cast<const void*>(d->d_un.d_ptr);
                break;
            default:
                break;
        }
    }

    if (!symtab || !strtab) return false;

    size_t symcount = 0;
    if (hash) {
        // DT_HASH: u32 nbucket; u32 nchain; ...
        const uint32_t* h = reinterpret_cast<const uint32_t*>(hash);
        symcount = static_cast<size_t>(h[1]);
    } else if (gnu_hash) {
        symcount = symcount_from_gnu_hash(gnu_hash);
    }
    if (symcount == 0) return false;

    out.symtab = symtab;
    out.strtab = strtab;
    out.strsz = strsz;
    out.symcount = symcount;
    return true;
}

static void* resolve_opencommon_by_exports() {
    struct Ctx {
        void* addr = nullptr;
        char best_name[512] = {0};
        size_t best_score = 0;
        int matches = 0;
        int shared_ptr_matches = 0;
        int logged = 0;
    } ctx;

    auto cb = [](dl_phdr_info* info, size_t /*size*/, void* data) -> int {
        Ctx* c = reinterpret_cast<Ctx*>(data);
        if (!info || !c) return 0;

        const char* name = info->dlpi_name;
        // dlpi_name may be empty for main executable.
        if (!name || name[0] == '\0') return 0;
        if (!ends_with(name, kLibDexfile) && !contains(name, "/libdexfile.so")) return 0;

        DynSymView view;
        if (!build_dynsym_view(info, view)) {
            LOGE("failed to parse dynsym for %s", name);
            return 0;
        }

        for (size_t i = 0; i < view.symcount; i++) {
            const ElfW(Sym)& s = view.symtab[i];
            if (s.st_name == 0) continue;
            if (view.strsz != 0 && s.st_name >= view.strsz) continue;

            const char* sym_name = view.strtab + s.st_name;
            if (!sym_name || sym_name[0] == '\0') continue;

            if (!contains(sym_name, kOpenCommonNeedle2) && !contains(sym_name, kOpenCommonNeedle1)) {
                continue;
            }

            // Prefer the overload whose first parameter is std::shared_ptr<DexFileContainer>.
            // If a lib version only exports one OpenCommon, we still allow other candidates as fallback.
            const bool has_shared_ptr_container = is_opencommon_shared_ptr_container_overload(sym_name);
            if (has_shared_ptr_container) c->shared_ptr_matches++;

            const unsigned type = elf_st_type(s.st_info);
            if (type != STT_FUNC && type != STT_NOTYPE) {
                // Some Android builds mark as NOTYPE; accept both.
                // Anything else is unlikely to be callable.
                continue;
            }
            if (s.st_shndx == SHN_UNDEF) continue;

            const ElfW(Addr) base = static_cast<ElfW(Addr)>(info->dlpi_addr);
            void* addr = reinterpret_cast<void*>(base + s.st_value);
            if (!addr) continue;

            c->matches++;
            const size_t len = strlen(sym_name);
            // Log candidates (bounded).
            if (c->logged < 8) {
                LOGI("OpenCommon candidate[%d]: shared_ptr_container=%d %s @ %p",
                     c->logged,
                     has_shared_ptr_container ? 1 : 0,
                     sym_name,
                     addr);
                c->logged++;
            }

            // Scoring:
            // - Strongly prefer the intended overload (shared_ptr<DexFileContainer> first arg)
            // - Then prefer longer names (more specific template encoding)
            const size_t score = (has_shared_ptr_container ? 1'000'000u : 0u) + len;
            if (score > c->best_score) {
                c->best_score = score;
                c->addr = addr;
                snprintf(c->best_name, sizeof(c->best_name), "%s", sym_name);
            }
        }

        // Continue iterating in case there are multiple mappings; but for a single module this is enough.
        return 0;
    };

    dl_iterate_phdr(cb, &ctx);

    if (!ctx.addr) {
        LOGE("OpenCommon export fuzzy match failed (matches=%d shared_ptr_matches=%d)", ctx.matches, ctx.shared_ptr_matches);
        return nullptr;
    }
    if (ctx.shared_ptr_matches == 0) {
        LOGE("OpenCommon fuzzy match rejected: no shared_ptr<DexFileContainer> overload found (matches=%d)", ctx.matches);
        return nullptr;
    }
    if (ctx.matches > ctx.logged) {
        LOGI("OpenCommon candidates truncated: logged=%d total=%d", ctx.logged, ctx.matches);
    }
    LOGI("OpenCommon fuzzy matched (matches=%d shared_ptr_matches=%d) => %s @ %p",
         ctx.matches,
         ctx.shared_ptr_matches,
         ctx.best_name,
         ctx.addr);
    return ctx.addr;
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
        // Fuzzy search for different libdexfile versions.
        sym = resolve_opencommon_by_exports();
    }
    if (!sym) {
        LOGE("OpenCommon symbol not found (exact + fuzzy failed). last dlerror=%s", dlerr());
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

