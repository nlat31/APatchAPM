#include "java_hook.h"
#include "elf_util.h"

#include <android/log.h>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include <dobby.h>
#include <lsplant.hpp>

#ifndef ZMOD_ID
#define ZMOD_ID "shadowso"
#endif

#ifndef ZMOD_HOOKER_CLASS
#define ZMOD_HOOKER_CLASS "shadowso.Hooker"
#endif

#define LOG_TAG    "shadowso"
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static std::unique_ptr<const SandHook::ElfImg> &GetArt() {
    static std::unique_ptr<const SandHook::ElfImg> kArtImg = nullptr;
    if (!kArtImg) {
        kArtImg = std::make_unique<SandHook::ElfImg>("libart.so");
    }
    return kArtImg;
}

static jclass find_class(JNIEnv *env, const char *name) {
    jclass cls = env->FindClass(name);
    if (cls) return cls;

    env->ExceptionClear();
    return nullptr;
}

static jmethodID find_method(JNIEnv *env, jclass cls, const char *name, const char *sig, bool is_static) {
    jmethodID mid = is_static ? env->GetStaticMethodID(cls, name, sig) : env->GetMethodID(cls, name, sig);
    if (!mid) {
        env->ExceptionClear();
        LOGE("[%s] Method not found: %s%s", ZMOD_ID, name, sig);
    }
    return mid;
}

static jobject to_reflected_method(JNIEnv *env, jclass cls, jmethodID mid, bool is_static) {
    if (!mid) return nullptr;
    return env->ToReflectedMethod(cls, mid, is_static ? JNI_TRUE : JNI_FALSE);
}

namespace sample {
namespace java_hook {

static jclass g_hooker_cls = nullptr;
static jobject g_hooker_inst = nullptr;

bool initialize(JNIEnv *env) {
    lsplant::InitInfo initInfo{
        .inline_hooker = [](void *target, void *hooker) -> void * {
            void *orig = nullptr;
            return (DobbyHook(target, hooker, &orig) == 0) ? orig : nullptr;
        },
        .inline_unhooker = [](void *target) -> bool {
            return DobbyDestroy(target) == 0;
        },
        .art_symbol_resolver = [](auto symbol) -> void * {
            return GetArt()->getSymbAddress(symbol);
        },
        .art_symbol_prefix_resolver = [](auto symbol) -> void * {
            return GetArt()->getSymbPrefixFirstAddress(symbol);
        },
    };

    bool ok = lsplant::Init(env, initInfo);
    if (!ok) {
        LOGE("[%s] lsplant::Init failed (collect logcat tag: LSPlant)", ZMOD_ID);
    }
    return ok;
}

static bool hook_and_save_backup(JNIEnv *env,
                                 jobject target_method,
                                 const char *hook_method_name,
                                 const char *hook_method_sig,
                                 const char *backup_field_name) {
    if (!target_method || !g_hooker_cls || !g_hooker_inst) return false;

    jmethodID hook_mid = env->GetMethodID(g_hooker_cls, hook_method_name, hook_method_sig);
    if (!hook_mid) {
        env->ExceptionClear();
        LOGE("[%s] Hook method not found: Hooker.%s%s", ZMOD_ID, hook_method_name, hook_method_sig);
        return false;
    }
    jobject hook_method = env->ToReflectedMethod(g_hooker_cls, hook_mid, JNI_FALSE);
    if (!hook_method) {
        env->ExceptionClear();
        return false;
    }

    jobject backup = lsplant::Hook(env, target_method, g_hooker_inst, hook_method);
    if (!backup) {
        LOGE("[%s] lsplant::Hook failed for %s", ZMOD_ID, hook_method_name);
        return false;
    }

    jfieldID backup_fid = env->GetStaticFieldID(g_hooker_cls, backup_field_name, "Ljava/lang/reflect/Method;");
    if (!backup_fid) {
        env->ExceptionClear();
        LOGE("[%s] Backup field not found: Hooker.%s", ZMOD_ID, backup_field_name);
        return false;
    }
    env->SetStaticObjectField(g_hooker_cls, backup_fid, backup);
    return true;
}

bool install_hooks(JNIEnv *env, const std::vector<uint8_t> &dex_data) {
    if (dex_data.empty()) {
        LOGE("[%s][java] classes.dex is empty", ZMOD_ID);
        return false;
    }

    jclass loader_cls = find_class(env, "dalvik/system/InMemoryDexClassLoader");
    if (!loader_cls) {
        LOGE("[%s][java] InMemoryDexClassLoader not found", ZMOD_ID);
        return false;
    }

    jmethodID ctor = env->GetMethodID(loader_cls, "<init>", "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    jmethodID load_class = env->GetMethodID(loader_cls, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    if (!ctor || !load_class) {
        env->ExceptionClear();
        LOGE("[%s][java] InMemoryDexClassLoader methods not found", ZMOD_ID);
        return false;
    }

    jobject buf = env->NewDirectByteBuffer((void *)dex_data.data(), dex_data.size());
    if (!buf) {
        env->ExceptionClear();
        LOGE("[%s][java] NewDirectByteBuffer failed", ZMOD_ID);
        return false;
    }

    jobject loader = env->NewObject(loader_cls, ctor, buf, nullptr);
    if (!loader || env->ExceptionCheck()) {
        env->ExceptionClear();
        LOGE("[%s][java] Failed to create InMemoryDexClassLoader", ZMOD_ID);
        return false;
    }

    jstring hooker_name = env->NewStringUTF(ZMOD_HOOKER_CLASS);
    jclass hooker_cls = (jclass)env->CallObjectMethod(loader, load_class, hooker_name);
    if (env->ExceptionCheck() || !hooker_cls) {
        env->ExceptionClear();
        LOGE("[%s][java] Failed to load Hooker class: %s", ZMOD_ID, ZMOD_HOOKER_CLASS);
        return false;
    }

    g_hooker_cls = (jclass)env->NewGlobalRef(hooker_cls);
    jmethodID hooker_ctor = env->GetMethodID(g_hooker_cls, "<init>", "()V");
    if (!hooker_ctor) {
        env->ExceptionClear();
        LOGE("[%s][java] Hooker.<init>() not found", ZMOD_ID);
        return false;
    }
    jobject inst = env->NewObject(g_hooker_cls, hooker_ctor);
    if (!inst || env->ExceptionCheck()) {
        env->ExceptionClear();
        LOGE("[%s][java] Failed to instantiate Hooker", ZMOD_ID);
        return false;
    }
    g_hooker_inst = env->NewGlobalRef(inst);

    // Demo: hook ActivityThread.main(String[]) which is the app process entrypoint (static).
    jclass at_cls = find_class(env, "android/app/ActivityThread");
    if (!at_cls) {
        LOGE("[%s][java] android/app/ActivityThread not found", ZMOD_ID);
        return false;
    }

    jmethodID target_mid = find_method(env, at_cls, "main", "([Ljava/lang/String;)V", true);
    jobject target_method = to_reflected_method(env, at_cls, target_mid, true);
    if (!target_method) {
        LOGE("[%s][java] Failed to reflect ActivityThread.main", ZMOD_ID);
        return false;
    }

    if (hook_and_save_backup(env, target_method,
                             "hookActivityThreadMain",
                             "([Ljava/lang/Object;)Ljava/lang/Object;",
                             "backupActivityThreadMain")) {
        LOGI("[%s][java] Hooked ActivityThread.main", ZMOD_ID);
    } else {
        LOGE("[%s][java] Failed to hook ActivityThread.main", ZMOD_ID);
        return false;
    }
    return true;
}

} // namespace java_hook
} // namespace sample

