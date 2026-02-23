#pragma once

#include <cstdint>
#include <string>

namespace dumpso {

// Enumerate currently loaded modules after a delay and dump all ".so" modules.
// This mode must not install any hooks.
void enumerate_and_dump_after_delay(const std::string& package_name,
                                    uint32_t delay_us,
                                    bool fix);

} // namespace dumpso

