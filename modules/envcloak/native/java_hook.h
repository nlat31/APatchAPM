#pragma once

#include <jni.h>
#include <string>
#include <vector>

namespace envcloak {
namespace java_hook {

bool initialize(JNIEnv *env);
void install_hooks(JNIEnv *env,
                   const std::vector<uint8_t>& dex_data,
                   bool enable_installer_spoof,
                   const std::string &installer_package,
                   bool hide_developer_mode,
                   bool hide_usb_debug,
                   bool hide_wireless_debug,
                   bool hide_debug_properties);

} // namespace java_hook
} // namespace envcloak

