#pragma once

namespace appxray {
namespace native_hook {

// Hook libc file operations and/or dlopen/dlsym.
// All logs go to /data/data/<package>/log/<timestamp>-<pid>.log
void install_hooks(const char *package_name,
                   const char *file_names,
                   bool file_monitor_enabled,
                   bool dl_monitor_enabled);

} // namespace native_hook
} // namespace appxray

