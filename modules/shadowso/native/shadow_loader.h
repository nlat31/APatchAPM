#pragma once

#include <link.h>
#include <string>
#include <vector>

namespace sample {
namespace shadow_loader {

struct ShadowModuleInfo {
    std::string name_lower;    // configured target name (lowercased), e.g. "libc.so"

    // Original (system) module information (from dl_iterate_phdr + /proc/self/maps aggregation)
    std::string orig_path;
    uintptr_t   orig_base = 0; // lowest start address in maps for that module
    size_t      orig_size = 0; // sum(end-start) of all maps ranges for that module

    // Shadow (CSOLoader) module information (from csoloader return struct)
    std::string shadow_path;
    uintptr_t   shadow_base = 0; // lib->img->base
    size_t      shadow_size = 0; // lib->linker.main_map_size
    const ElfW(Phdr) *shadow_phdr = nullptr;
    ElfW(Half) shadow_phnum = 0;
};

// In target app process (postAppSpecialize), load an extra in-memory copy for each
// configured SO name (string match against currently loaded modules). For names not
// loaded yet, hook linker do_dlopen and load a copy immediately after it is loaded.
//
// `so_names` are typically like: ["libc.so", "libart.so", "libxxx.so"].
bool initialize(const std::vector<std::string> &so_names);

// Snapshot all modules that have been shadow-loaded so far (includes orig+shadow metadata).
std::vector<ShadowModuleInfo> snapshot_modules();

} // namespace shadow_loader
} // namespace sample

