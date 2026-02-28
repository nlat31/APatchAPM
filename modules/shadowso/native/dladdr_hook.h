#pragma once

namespace sample {
namespace dladdr_hook {

// Hook dladdr and translate shadow addresses back to original module addresses.
bool install();

} // namespace dladdr_hook
} // namespace sample

