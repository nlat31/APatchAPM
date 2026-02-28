#pragma once

#include <jni.h>
#include <vector>

namespace sample {
namespace java_hook {

bool initialize(JNIEnv *env);
void install_hooks(JNIEnv *env, const std::vector<uint8_t>& dex_data);

} // namespace java_hook
} // namespace sample

