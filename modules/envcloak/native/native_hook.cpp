#include "native_hook.h"

#include <cstdint>
#include <cstring>
#include <string_view>
#include <unordered_map>
#include <dlfcn.h>
#include <android/log.h>
#include <dobby.h>
#include <unistd.h>
#include <sys/system_properties.h>

#define LOG_TAG    "EnvCloak/NativeHook"
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

/**
 * 便捷宏: 声明并安装一个 Dobby inline hook
 *
 * 用法:
 *   // 1. 声明原始函数指针和替换函数
 *   static int (*orig_targetFunc)(int arg);
 *   static int hook_targetFunc(int arg) {
 *       LOGI("targetFunc called with arg=%d", arg);
 *       return orig_targetFunc(arg);  // 调用原函数
 *   }
 *
 *   // 2. 使用宏安装 hook (在 install_hooks 中调用)
 *   HOOK_FUNC(handle, "targetFunc", hook_targetFunc, orig_targetFunc);
 */
#define HOOK_FUNC(handle, symbol, hook_func, orig_func)                     \
    do {                                                                     \
        void *addr = dlsym(handle, symbol);                                  \
        if (addr != nullptr) {                                               \
            void *orig_ = nullptr;                                           \
            if (DobbyHook(addr,                                              \
                          to_void_ptr(hook_func),                            \
                          &orig_)                                            \
                == 0) {                                                      \
                orig_func = reinterpret_cast<decltype(orig_func)>(orig_);    \
                LOGI("Hooked: %s @ %p", symbol, addr);                       \
            } else {                                                         \
                LOGE("Failed to hook: %s @ %p", symbol, addr);               \
            }                                                                \
        } else {                                                             \
            LOGW("Symbol not found: %s", symbol);                            \
        }                                                                    \
    } while (0)

/**
 * 便捷宏: 通过绝对地址安装 hook (用于没有符号的函数)
 */
#define HOOK_ADDR(address, hook_func, orig_func)                            \
    do {                                                                     \
        void *orig_ = nullptr;                                               \
        if (DobbyHook(reinterpret_cast<void*>(address),                      \
                      to_void_ptr(hook_func),                                \
                      &orig_)                                                \
            == 0) {                                                          \
            orig_func = reinterpret_cast<decltype(orig_func)>(orig_);        \
            LOGI("Hooked address: %p", reinterpret_cast<void*>(address));    \
        } else {                                                             \
            LOGE("Failed to hook address: %p",                               \
                 reinterpret_cast<void*>(address));                           \
        }                                                                    \
    } while (0)

namespace envcloak {
namespace native_hook {

// ========================================================================
//  ImNotADeveloper: hide debug/usb related system properties (native)
// ========================================================================

static bool is_app_uid() {
    return getuid() >= 10000;
}

static const std::unordered_map<std::string_view, std::string_view> &prop_overrides() {
    static const std::unordered_map<std::string_view, std::string_view> k = {
        // From ImNotADeveloper
        {"sys.usb.ffs.ready", "0"},
        {"sys.usb.config", "mtp"},
        {"persist.sys.usb.config", "mtp"},
        {"sys.usb.state", "mtp"},
        {"init.svc.adbd", "stopped"},
    };
    return k;
}

static int (*orig___system_property_get)(const char *name, char *value) = nullptr;
static const prop_info *(*orig___system_property_find)(const char *name) = nullptr;

static int hooked___system_property_get(const char *name, char *value) {
    if (name && value && is_app_uid()) {
        auto it = prop_overrides().find(std::string_view{name});
        if (it != prop_overrides().end()) {
#if defined(__BIONIC__)
            strlcpy(value, it->second.data(), PROP_VALUE_MAX);
#else
            std::strncpy(value, it->second.data(), PROP_VALUE_MAX - 1);
            value[PROP_VALUE_MAX - 1] = '\0';
#endif
            return static_cast<int>(std::strlen(value));
        }
    }
    return orig___system_property_get ? orig___system_property_get(name, value) : 0;
}

static const prop_info *hooked___system_property_find(const char *name) {
    if (name && is_app_uid()) {
        auto it = prop_overrides().find(std::string_view{name});
        if (it != prop_overrides().end()) {
            // Hide existence for these keys.
            return nullptr;
        }
    }
    return orig___system_property_find ? orig___system_property_find(name) : nullptr;
}

bool initialize() {
    LOGI("Initializing native hook module (Dobby)...");
    return true;
}

void install_early_hooks() {
    // Designed to be called in Zygote as early as possible.
    // Hooking libc symbols is safe to inherit across fork.
    LOGI("Installing early native hooks (system properties) ...");

    void *libc = dlopen("libc.so", RTLD_NOW);
    if (!libc) {
        LOGE("dlopen(libc.so) failed: %s", dlerror());
        return;
    }

    void *p_get = dlsym(libc, "__system_property_get");
    void *p_find = dlsym(libc, "__system_property_find");

    if (!p_get) {
        LOGE("Symbol not found: __system_property_get");
    } else {
        void *orig = nullptr;
        if (DobbyHook(p_get, to_void_ptr(hooked___system_property_get), &orig) == 0) {
            orig___system_property_get = reinterpret_cast<decltype(orig___system_property_get)>(orig);
            LOGI("Hooked __system_property_get @ %p", p_get);
        } else {
            LOGE("Failed to hook __system_property_get @ %p", p_get);
        }
    }

    if (!p_find) {
        LOGE("Symbol not found: __system_property_find");
    } else {
        void *orig = nullptr;
        if (DobbyHook(p_find, to_void_ptr(hooked___system_property_find), &orig) == 0) {
            orig___system_property_find = reinterpret_cast<decltype(orig___system_property_find)>(orig);
            LOGI("Hooked __system_property_find @ %p", p_find);
        } else {
            LOGE("Failed to hook __system_property_find @ %p", p_find);
        }
    }
}

void install_hooks() {
    LOGI("Installing native hooks...");
    LOGI("Native hooks installation complete");
}

} // namespace native_hook
} // namespace envcloak

