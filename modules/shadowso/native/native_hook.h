#pragma once

#include <string>
#include <vector>

namespace sample {
namespace native_hook {

// Hook native: android_dlopen_ext (log only)
bool install_hooks(const std::vector<std::string> &hide_so);

// Get real dlsym address (bypasses our hooked dlsym if installed).
void *get_real_dlsym(void *handle, const char *symbol);

} // namespace native_hook
} // namespace sample

