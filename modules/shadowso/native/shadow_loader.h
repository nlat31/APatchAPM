#pragma once

#include <link.h>
#include <string>
#include <vector>

namespace sample {
namespace shadow_loader {

struct ShadowModuleInfo {
    std::string name_lower;    // configured target name (lowercased), e.g. "libc.so"

    // Original (system) module information (captured from dl_iterate_phdr early after fork)
    std::string orig_path;
    uintptr_t   orig_base = 0; // base address (lowest PT_LOAD mapping start)
    size_t      orig_size = 0; // total PT_LOAD address span
    const ElfW(Phdr) *orig_phdr = nullptr;
    ElfW(Half) orig_phnum = 0;

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

// Query cached original module info (captured once during initialize()).
// `basename_lower` should be like "libart.so" / "linker64".
bool get_orig_module_info(const std::string &basename_lower, std::string &out_path, uintptr_t &out_base);

} // namespace shadow_loader
} // namespace sample

