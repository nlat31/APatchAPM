#pragma once

namespace sample {
namespace phdr_hook {

// Hook dl_iterate_phdr and rewrite dl_phdr_info to shadow module info.
bool install();

} // namespace phdr_hook
} // namespace sample

