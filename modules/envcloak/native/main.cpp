#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>
#include <android/log.h>

#include "zygisk.hpp"
#include "native_hook.h"
#include "java_hook.h"

#ifndef ZMOD_ID
#define ZMOD_ID "envcloak"
#endif

#define LOG_TAG    "EnvCloak"
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// ========================================================================
//  Zygisk 模块实现
// ========================================================================

static std::vector<uint8_t> g_dex_data;

static void load_dex_data() {
    std::vector<std::string> paths;
    paths.emplace_back(std::string("/data/adb/modules/") + ZMOD_ID + "/classes.dex");
    paths.emplace_back(std::string("/data/local/tmp/") + ZMOD_ID + "/classes.dex"); // Dev fallback
    paths.emplace_back("/data/local/tmp/classes.dex"); // Dev fallback

    for (const auto &path : paths) {
        FILE *fp = fopen(path.c_str(), "rb");
        if (fp) {
            fseek(fp, 0, SEEK_END);
            long size = ftell(fp);
            fseek(fp, 0, SEEK_SET);

            if (size > 0) {
                g_dex_data.resize(size);
                fread(g_dex_data.data(), 1, size, fp);
                LOGI("Loaded DEX from %s (size: %ld)", path.c_str(), size);
                fclose(fp);
                return;
            }
            fclose(fp);
        }
    }
    LOGW("Failed to load classes.dex from known paths");
}

class EnvCloakModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api_ = api;
        this->env_ = env;
        LOGI("onLoad(%s): pid=%d uid=%d", ZMOD_ID, getpid(), getuid());

        // Install critical native hooks as early as possible in Zygote so forked app
        // processes inherit them. This helps catch checks performed in native init_array.
        if (envcloak::native_hook::initialize()) {
            envcloak::native_hook::install_early_hooks();
        }

        // Load DEX in Zygote process so it's available to all forked apps
        if (g_dex_data.empty()) {
            load_dex_data();
        }
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        const char *nice_name = env_->GetStringUTFChars(args->nice_name, nullptr);
        LOGI("preAppSpecialize(%s): pid=%d nice_name=%s target_uid=%d",
             ZMOD_ID, getpid(), nice_name ? nice_name : "null", args->uid);

        // Default: all normal apps (uid >= 10000)
        should_hook_ = (args->uid >= 10000);

        if (nice_name) {
            env_->ReleaseStringUTFChars(args->nice_name, nice_name);
        }

        if (!should_hook_) {
            api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs * /*args*/) override {
        if (!should_hook_) return;

        LOGI("postAppSpecialize(%s): pid=%d initializing hooks...", ZMOD_ID, getpid());

        envcloak::native_hook::install_hooks();

        if (envcloak::java_hook::initialize(env_)) {
            envcloak::java_hook::install_hooks(env_, g_dex_data);
        } else {
            LOGE("Failed to initialize Java hooks");
        }

        LOGI("All hooks installed");
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs * /*args*/) override {
        api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

private:
    zygisk::Api *api_ = nullptr;
    JNIEnv      *env_ = nullptr;
    bool         should_hook_ = false;
};

REGISTER_ZYGISK_MODULE(EnvCloakModule)

