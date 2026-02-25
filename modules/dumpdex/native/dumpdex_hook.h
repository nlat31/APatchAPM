#pragma once

#include <string>

namespace dumpdex {

// Install hooks in current process.
// `package_name` decides output path: /data/data/<package_name>/dumpdex/
void install(const std::string& package_name);

} // namespace dumpdex

