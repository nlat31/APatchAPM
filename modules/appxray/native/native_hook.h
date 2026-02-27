#pragma once

namespace appxray {
namespace native_hook {

// Hook libc file operations (open/seek/read/write/close)
void install_hooks(const char *package_name, const char *file_names);

} // namespace native_hook
} // namespace appxray

