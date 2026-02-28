#pragma once

#include <string>

namespace sample {
namespace maps_hook {

// Hook open/openat. When opening current process maps, copy to:
//   /data/data/<package>/temp/maps
// and redirect the open to that file, returning the fd from the original function.
bool install(const std::string &package_name);

} // namespace maps_hook
} // namespace sample

