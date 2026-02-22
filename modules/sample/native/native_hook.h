#pragma once

namespace sample {
namespace native_hook {

// Hook native: __loader_dlopen (log only)
void install_hooks();

} // namespace native_hook
} // namespace sample

