#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace dumpso {

// Dump a loaded module from memory and optionally rebuild ELF to *.fix.so.
// Output directory: /data/data/<package_name>/dumpso/
// `so_path` is optional; if null/empty, file name will be based on address range.
void dump_module(const std::string& package_name,
                 const char* so_path,
                 uintptr_t module_base,
                 size_t module_size,
                 bool fix);

} // namespace dumpso

