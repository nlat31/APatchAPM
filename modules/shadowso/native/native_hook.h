#pragma once

#include <string>
#include <vector>

namespace sample {
namespace native_hook {

// Hook native: android_dlopen_ext (log only)
bool install_hooks(const std::vector<std::string> &hide_so);

} // namespace native_hook
} // namespace sample

