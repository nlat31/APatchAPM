#pragma once

#include <cstdint>
#include <string>

namespace dumpso {

struct HookOptions {
    bool watch = false;
    bool fix = true;
    uint32_t delay_us = 0;
    std::string so_name;
};

// Install linker do_dlopen hook in current process.
// `package_name` is used for output path: /data/data/<package_name>/dumpso/
void install_dlopen_hook(const std::string& package_name, const HookOptions& opts);

} // namespace dumpso

