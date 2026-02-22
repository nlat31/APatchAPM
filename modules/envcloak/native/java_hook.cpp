#include "java_hook.h"
#include "elf_util.h"

#include <android/log.h>
#include <cstring>
#include <string>
#include <vector>
#include <memory>
#include <dobby.h>
#include <lsplant.hpp>

#ifndef ZMOD_HOOKER_CLASS
#define ZMOD_HOOKER_CLASS "envcloak.Hooker"
#endif

#define LOG_TAG    "EnvCloak/JavaHook"
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// ========================================================================
//  ART 符号解析 (基于 LSPosed ElfImg)
// ========================================================================

static std::unique_ptr<const SandHook::ElfImg> &GetArt(bool release = false) {
    static std::unique_ptr<const SandHook::ElfImg> kArtImg = nullptr;
    if (release) {
        kArtImg.reset();
    } else if (!kArtImg) {
        kArtImg = std::make_unique<SandHook::ElfImg>("libart.so");
    }
    return kArtImg;
}

// ========================================================================
//  JNI 工具函数
// ========================================================================

static jclass find_class(JNIEnv *env, const char *name) {
    jclass cls = env->FindClass(name);
    if (cls != nullptr) return cls;

    env->ExceptionClear();

    // Fallback: Class.forName(dotted, false, null)
    std::string dotted{name ? name : ""};
    for (char &c : dotted) {
        if (c == '/') c = '.';
    }

    jclass class_cls = env->FindClass("java/lang/Class");
    if (!class_cls) {
        env->ExceptionClear();
        LOGE("Class not found: %s", name);
        return nullptr;
    }
    jmethodID for_name = env->GetStaticMethodID(
        class_cls, "forName", "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;");
    if (!for_name) {
        env->ExceptionClear();
        LOGE("Class not found: %s", name);
        return nullptr;
    }

    jstring jname = env->NewStringUTF(dotted.c_str());
    if (!jname) {
        env->ExceptionClear();
        LOGE("Class not found: %s", name);
        return nullptr;
    }

    jobject cls_obj = env->CallStaticObjectMethod(class_cls, for_name, jname, JNI_FALSE, nullptr);
    if (env->ExceptionCheck() || !cls_obj) {
        env->ExceptionClear();
        LOGE("Class not found: %s", name);
        return nullptr;
    }
    return (jclass)cls_obj;
}

static jmethodID find_method(JNIEnv *env, jclass cls, const char *name,
                             const char *sig, bool is_static = false) {
    jmethodID method;
    if (is_static) {
        method = env->GetStaticMethodID(cls, name, sig);
    } else {
        method = env->GetMethodID(cls, name, sig);
    }
    if (method == nullptr) {
        env->ExceptionClear();
        LOGE("Method not found: %s%s", name, sig);
    }
    return method;
}

static jobject to_reflected_method(JNIEnv *env, jclass cls, jmethodID method_id,
                                   bool is_static = false) {
    if (method_id == nullptr) return nullptr;
    return env->ToReflectedMethod(cls, method_id, is_static ? JNI_TRUE : JNI_FALSE);
}

// ========================================================================
//  Hook Logic
// ========================================================================

static jclass hooker_class_ref = nullptr;
static jobject hooker_inst_ref = nullptr;

namespace envcloak {
namespace java_hook {

bool initialize(JNIEnv *env) {
    LOGI("Initializing Java hook module (lsplant)...");
    lsplant::InitInfo initInfo{
        .inline_hooker = [](void *target, void *hooker) -> void* {
            void *orig = nullptr;
            if (DobbyHook(target, hooker, &orig) == 0) return orig;
            return nullptr;
        },
        .inline_unhooker = [](void *target) -> bool {
            return DobbyDestroy(target) == 0;
        },
        .art_symbol_resolver = [](auto symbol) -> void* {
            return GetArt()->getSymbAddress(symbol);
        },
        .art_symbol_prefix_resolver = [](auto symbol) -> void* {
            return GetArt()->getSymbPrefixFirstAddress(symbol);
        },
    };
    bool ok = lsplant::Init(env, initInfo);
    if (!ok) {
        LOGE("lsplant::Init failed. Please collect logcat tags: EnvCloak, EnvCloak/JavaHook, LSPlant");
    }
    return ok;
}

static void JNICALL hooker_onClassLoaded(JNIEnv *env, jclass /*hooker_cls*/, jclass loaded_class) {
    (void)env;
    LOGI("Target class loaded via hook: %p", loaded_class);
}

static void register_natives(JNIEnv *env, jclass hooker_cls) {
    JNINativeMethod methods[] = {
        {"onClassLoaded", "(Ljava/lang/Class;)V", (void*)hooker_onClassLoaded}
    };
    if (env->RegisterNatives(hooker_cls, methods, 1) < 0) {
        LOGE("Failed to register natives for Hooker class");
        env->ExceptionClear();
    }
}

void install_hooks(JNIEnv *env, const std::vector<uint8_t>& dex_data) {
    LOGI("Installing Java hooks...");

    if (dex_data.empty()) {
        LOGE("DEX data is empty! Cannot load Hooker class.");
        return;
    }

    // 1. Load Hooker class using InMemoryDexClassLoader
    jclass base_loader_cls = env->FindClass("dalvik/system/InMemoryDexClassLoader");
    if (!base_loader_cls) {
        LOGE("dalvik/system/InMemoryDexClassLoader not found");
        env->ExceptionClear();
        return;
    }

    jmethodID loader_ctor = env->GetMethodID(base_loader_cls, "<init>", "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    if (!loader_ctor) {
        LOGE("InMemoryDexClassLoader constructor not found");
        env->ExceptionClear();
        return;
    }

    jobject byte_buffer = env->NewDirectByteBuffer((void*)dex_data.data(), dex_data.size());
    if (!byte_buffer) {
        LOGE("Failed to create ByteBuffer");
        env->ExceptionClear();
        return;
    }

    jobject parent_loader = nullptr;

    jobject loader = env->NewObject(base_loader_cls, loader_ctor, byte_buffer, parent_loader);
    if (!loader || env->ExceptionCheck()) {
        LOGE("Failed to create InMemoryDexClassLoader object");
        env->ExceptionDescribe();
        env->ExceptionClear();
        return;
    }

    jmethodID load_class_method = env->GetMethodID(base_loader_cls, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    if (!load_class_method) {
        LOGE("loadClass method not found");
        env->ExceptionClear();
        return;
    }

    jstring hooker_cls_name = env->NewStringUTF(ZMOD_HOOKER_CLASS);
    jclass hooker_cls = (jclass)env->CallObjectMethod(loader, load_class_method, hooker_cls_name);

    if (env->ExceptionCheck()) {
        LOGE("Exception during loading %s", ZMOD_HOOKER_CLASS);
        env->ExceptionDescribe();
        env->ExceptionClear();
        return;
    }

    if (!hooker_cls) {
        LOGE("Failed to load %s", ZMOD_HOOKER_CLASS);
        return;
    }
    hooker_class_ref = (jclass)env->NewGlobalRef(hooker_cls);

    register_natives(env, hooker_class_ref);

    // Create Hooker instance
    jmethodID ctor = env->GetMethodID(hooker_class_ref, "<init>", "()V");
    if (!ctor) {
        LOGE("Hooker constructor not found");
        env->ExceptionClear();
        return;
    }
    jobject hooker_inst = env->NewObject(hooker_class_ref, ctor);
    if (!hooker_inst || env->ExceptionCheck()) {
        LOGE("Failed to instantiate Hooker");
        env->ExceptionClear();
        return;
    }
    hooker_inst_ref = env->NewGlobalRef(hooker_inst);

    // Small helper: hook a target Method and stash backup into Hooker.<field>
    auto hook_and_save_backup = [&](jobject target_method,
                                    const char *hook_method_name,
                                    const char *hook_method_sig,
                                    const char *backup_field_name) -> bool {
        if (!target_method) return false;
        jmethodID hook_mid = find_method(env, hooker_class_ref, hook_method_name, hook_method_sig, false);
        jobject hook_method = to_reflected_method(env, hooker_class_ref, hook_mid, false);
        if (!hook_method) return false;

        jobject backup = lsplant::Hook(env, target_method, hooker_inst_ref, hook_method);
        if (!backup) {
            LOGE("lsplant::Hook failed for hook_method=%s", hook_method_name);
            return false;
        }

        jfieldID backup_fid = env->GetStaticFieldID(hooker_class_ref, backup_field_name, "Ljava/lang/reflect/Method;");
        if (!backup_fid) {
            env->ExceptionClear();
            LOGW("Backup field not found: %s", backup_field_name);
            return false;
        }
        env->SetStaticObjectField(hooker_class_ref, backup_fid, backup);
        return true;
    };

    // ================================================================
    // ImNotADeveloper: Settings.*.getStringForUser -> hide dev/adb keys
    // ================================================================
    struct SettingsHookItem {
        const char *cls;
        const char *hook_name;
        const char *backup_field;
        bool is_static;
    };

    const SettingsHookItem settings_items[] = {
        {"android/provider/Settings$Secure", "hookSecureGetStringForUser", "backupSecureGetStringForUser", true},
        {"android/provider/Settings$System", "hookSystemGetStringForUser", "backupSystemGetStringForUser", true},
        {"android/provider/Settings$Global", "hookGlobalGetStringForUser", "backupGlobalGetStringForUser", true},
        {"android/provider/Settings$NameValueCache", "hookNameValueCacheGetStringForUser", "backupNameValueCacheGetStringForUser", false},
    };

    for (const auto &it : settings_items) {
        jclass cls = find_class(env, it.cls);
        if (!cls) {
            LOGW("Settings class not found: %s", it.cls);
            continue;
        }
        const char *sig = "(Landroid/content/ContentResolver;Ljava/lang/String;I)Ljava/lang/String;";
        jmethodID mid = it.is_static
            ? env->GetStaticMethodID(cls, "getStringForUser", sig)
            : env->GetMethodID(cls, "getStringForUser", sig);
        if (!mid) {
            env->ExceptionClear();
            LOGW("Method not found: %s.getStringForUser%s", it.cls, sig);
            continue;
        }

        jobject target_method = env->ToReflectedMethod(cls, mid, it.is_static ? JNI_TRUE : JNI_FALSE);
        if (target_method) {
            if (hook_and_save_backup(target_method, it.hook_name, "([Ljava/lang/Object;)Ljava/lang/Object;", it.backup_field)) {
                LOGI("Hooked %s.getStringForUser", it.cls);
            }
        }
    }

    // ================================================================
    // ImNotADeveloper: android.os.SystemProperties native_get* -> override props
    // ================================================================
    jclass sp_cls = find_class(env, "android/os/SystemProperties");
    if (sp_cls) {
        struct SPItem {
            const char *name;
            const char *sig;
            const char *hook_name;
            const char *backup_field;
        };
        const SPItem sp_items[] = {
            {"native_get", "(Ljava/lang/String;)Ljava/lang/String;", "hookSystemPropertiesNativeGet1", "backupSystemPropertiesNativeGet1"},
            {"native_get", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", "hookSystemPropertiesNativeGet2", "backupSystemPropertiesNativeGet2"},
            {"native_get_int", "(Ljava/lang/String;I)I", "hookSystemPropertiesNativeGetInt", "backupSystemPropertiesNativeGetInt"},
            {"native_get_long", "(Ljava/lang/String;J)J", "hookSystemPropertiesNativeGetLong", "backupSystemPropertiesNativeGetLong"},
            {"native_get_boolean", "(Ljava/lang/String;Z)Z", "hookSystemPropertiesNativeGetBoolean", "backupSystemPropertiesNativeGetBoolean"},
        };

        for (const auto &it : sp_items) {
            jmethodID mid = env->GetStaticMethodID(sp_cls, it.name, it.sig);
            if (!mid) {
                env->ExceptionClear();
                LOGW("SystemProperties method not found: %s%s", it.name, it.sig);
                continue;
            }
            jobject target_method = env->ToReflectedMethod(sp_cls, mid, JNI_TRUE);
            if (target_method) {
                if (hook_and_save_backup(target_method, it.hook_name, "([Ljava/lang/Object;)Ljava/lang/Object;", it.backup_field)) {
                    LOGI("Hooked SystemProperties.%s%s", it.name, it.sig);
                }
            }
        }
    } else {
        env->ExceptionClear();
        LOGW("android/os/SystemProperties not found");
    }

    // ================================================================
    // ImNotADeveloper: ProcessImpl.start / ProcessManager.exec -> mask getprop keys
    // ================================================================
    auto hook_all_methods_by_name_and_store = [&](jclass target_cls,
                                                 const char *target_cls_name,
                                                 const char *target_method_name,
                                                 const char *hook_method_name,
                                                 const char *single_backup_field,
                                                 const char *all_backup_field) {
        if (!target_cls) return;

        bool has_local_frame = (env->PushLocalFrame(256) == 0);

        jclass class_cls = env->FindClass("java/lang/Class");
        jmethodID get_declared_methods = class_cls
            ? env->GetMethodID(class_cls, "getDeclaredMethods", "()[Ljava/lang/reflect/Method;")
            : nullptr;
        if (!get_declared_methods) {
            env->ExceptionClear();
            LOGW("Class.getDeclaredMethods not available, skip %s.%s", target_cls_name, target_method_name);
            if (has_local_frame) env->PopLocalFrame(nullptr);
            return;
        }

        jobjectArray methods = (jobjectArray)env->CallObjectMethod(target_cls, get_declared_methods);
        if (env->ExceptionCheck() || !methods) {
            LOGW("Failed to enumerate methods for %s", target_cls_name);
            env->ExceptionClear();
            if (has_local_frame) env->PopLocalFrame(nullptr);
            return;
        }

        jclass method_cls = env->FindClass("java/lang/reflect/Method");
        if (!method_cls) {
            env->ExceptionClear();
            LOGW("java/lang/reflect/Method not found");
            if (has_local_frame) env->PopLocalFrame(nullptr);
            return;
        }
        jmethodID mid_get_name = env->GetMethodID(method_cls, "getName", "()Ljava/lang/String;");
        if (!mid_get_name) {
            env->ExceptionClear();
            LOGW("Method.getName not found");
            if (has_local_frame) env->PopLocalFrame(nullptr);
            return;
        }

        jmethodID hook_mid = find_method(env, hooker_class_ref, hook_method_name,
                                         "([Ljava/lang/Object;)Ljava/lang/Object;", false);
        jobject hook_method = to_reflected_method(env, hooker_class_ref, hook_mid, false);
        if (!hook_method) {
            LOGW("Hook method not found: Hooker.%s", hook_method_name);
            if (has_local_frame) env->PopLocalFrame(nullptr);
            return;
        }

        std::vector<jobject> backups;
        jsize n = env->GetArrayLength(methods);
        for (jsize i = 0; i < n; ++i) {
            jobject m = env->GetObjectArrayElement(methods, i);
            if (!m) continue;

            jstring jname = (jstring)env->CallObjectMethod(m, mid_get_name);
            if (env->ExceptionCheck() || !jname) {
                env->ExceptionClear();
                env->DeleteLocalRef(m);
                continue;
            }
            const char *cname = env->GetStringUTFChars(jname, nullptr);
            bool match = (cname && std::strcmp(cname, target_method_name) == 0);
            if (cname) env->ReleaseStringUTFChars(jname, cname);
            env->DeleteLocalRef(jname);

            if (!match) {
                env->DeleteLocalRef(m);
                continue;
            }

            jobject backup = lsplant::Hook(env, m, hooker_inst_ref, hook_method);
            if (backup) {
                backups.push_back(backup);
            } else {
                LOGW("lsplant::Hook failed for %s.%s overload #%d", target_cls_name, target_method_name, (int)i);
            }
            env->DeleteLocalRef(m);
        }

        if (backups.empty()) {
            LOGW("No overloads hooked for %s.%s", target_cls_name, target_method_name);
            if (has_local_frame) env->PopLocalFrame(nullptr);
            return;
        }

        jfieldID single_fid = env->GetStaticFieldID(hooker_class_ref, single_backup_field, "Ljava/lang/reflect/Method;");
        if (single_fid) {
            env->SetStaticObjectField(hooker_class_ref, single_fid, backups[0]);
        } else {
            env->ExceptionClear();
            LOGW("Backup field not found: %s", single_backup_field);
        }

        jfieldID all_fid = env->GetStaticFieldID(hooker_class_ref, all_backup_field, "[Ljava/lang/reflect/Method;");
        if (!all_fid) {
            env->ExceptionClear();
            LOGW("Backup array field not found: %s", all_backup_field);
            if (has_local_frame) env->PopLocalFrame(nullptr);
            return;
        }

        jobjectArray backup_arr = env->NewObjectArray((jsize)backups.size(), method_cls, nullptr);
        if (!backup_arr) {
            env->ExceptionClear();
            LOGW("Failed to allocate backup Method[] for %s.%s", target_cls_name, target_method_name);
            if (has_local_frame) env->PopLocalFrame(nullptr);
            return;
        }
        for (jsize i = 0; i < (jsize)backups.size(); ++i) {
            env->SetObjectArrayElement(backup_arr, i, backups[i]);
        }
        env->SetStaticObjectField(hooker_class_ref, all_fid, backup_arr);

        LOGI("Hooked %s.%s overloads: %d", target_cls_name, target_method_name, (int)backups.size());
        if (has_local_frame) env->PopLocalFrame(nullptr);
    };

    // 1) java.lang.ProcessImpl.start(...)
    jclass procimpl_cls = find_class(env, "java/lang/ProcessImpl");
    if (procimpl_cls) {
        hook_all_methods_by_name_and_store(procimpl_cls,
                                           "java.lang.ProcessImpl",
                                           "start",
                                           "hookProcessImplStart",
                                           "backupProcessImplStart",
                                           "backupProcessImplStartAll");
    } else {
        env->ExceptionClear();
        LOGW("java/lang/ProcessImpl not found");
    }

    // 2) java.lang.ProcessManager.exec(...)
    jclass procman_cls = find_class(env, "java/lang/ProcessManager");
    if (procman_cls) {
        hook_all_methods_by_name_and_store(procman_cls,
                                           "java.lang.ProcessManager",
                                           "exec",
                                           "hookProcessManagerExec",
                                           "backupProcessManagerExec",
                                           "backupProcessManagerExecAll");
    } else {
        env->ExceptionClear();
    }

    // ================================================================
    // Hook: ApplicationPackageManager.getInstallerPackageName
    // ================================================================
    jclass pm_cls = find_class(env, "android/app/ApplicationPackageManager");
    if (!pm_cls) {
        LOGW("android/app/ApplicationPackageManager not found (this is unexpected)");
    } else {
        jmethodID target_pm_mid = find_method(env, pm_cls, "getInstallerPackageName", "(Ljava/lang/String;)Ljava/lang/String;");
        jobject target_pm_method = to_reflected_method(env, pm_cls, target_pm_mid, false);

        jmethodID hook_pm_mid = find_method(env, hooker_class_ref, "hookGetInstallerPackageName", "([Ljava/lang/Object;)Ljava/lang/Object;", false);
        jobject hook_pm_method = to_reflected_method(env, hooker_class_ref, hook_pm_mid, false);

        if (target_pm_method && hook_pm_method) {
            jobject backup = lsplant::Hook(env, target_pm_method, hooker_inst_ref, hook_pm_method);
            if (backup) {
                LOGI("Successfully hooked ApplicationPackageManager.getInstallerPackageName");
                jfieldID backup_field = env->GetStaticFieldID(hooker_class_ref, "backupGetInstallerPackageName", "Ljava/lang/reflect/Method;");
                if (backup_field) {
                    env->SetStaticObjectField(hooker_class_ref, backup_field, backup);
                } else {
                    env->ExceptionClear();
                    LOGW("Field backupGetInstallerPackageName not found");
                }
            } else {
                LOGE("Failed to hook ApplicationPackageManager.getInstallerPackageName");
            }
        }
    }

    // ================================================================
    // Hook: InstallSourceInfo (Android 11+)
    // ================================================================
    jclass isi_cls = find_class(env, "android/content/pm/InstallSourceInfo");
    if (isi_cls) {
        LOGI("Found InstallSourceInfo class, attempting to hook getters");

        jmethodID target_ipn_mid = find_method(env, isi_cls, "getInstallingPackageName", "()Ljava/lang/String;");
        jobject target_ipn_method = to_reflected_method(env, isi_cls, target_ipn_mid, false);

        jmethodID hook_ipn_mid = find_method(env, hooker_class_ref, "hookGetInstallingPackageName", "([Ljava/lang/Object;)Ljava/lang/Object;", false);
        jobject hook_ipn_method = to_reflected_method(env, hooker_class_ref, hook_ipn_mid, false);

        if (target_ipn_method && hook_ipn_method) {
            jobject backup = lsplant::Hook(env, target_ipn_method, hooker_inst_ref, hook_ipn_method);
            if (backup) {
                LOGI("Successfully hooked InstallSourceInfo.getInstallingPackageName");
            }
        }

        jmethodID target_init_mid = find_method(env, isi_cls, "getInitiatingPackageName", "()Ljava/lang/String;");
        jobject target_init_method = to_reflected_method(env, isi_cls, target_init_mid, false);

        jmethodID hook_init_mid = find_method(env, hooker_class_ref, "hookGetInitiatingPackageName", "([Ljava/lang/Object;)Ljava/lang/Object;", false);
        jobject hook_init_method = to_reflected_method(env, hooker_class_ref, hook_init_mid, false);

        if (target_init_method && hook_init_method) {
            jobject backup = lsplant::Hook(env, target_init_method, hooker_inst_ref, hook_init_method);
            if (backup) {
                LOGI("Successfully hooked InstallSourceInfo.getInitiatingPackageName");
            }
        }
    } else {
        env->ExceptionClear();
        LOGI("InstallSourceInfo class not found (Android < 11?)");
    }

    LOGI("Java hooks installation complete");
}

} // namespace java_hook
} // namespace envcloak

