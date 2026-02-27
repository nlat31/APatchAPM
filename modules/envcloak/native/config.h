#pragma once

#include <string>
#include <unordered_set>

namespace envcloak {
namespace config {

struct Config {
    int version = 1;
    std::unordered_set<std::string> packages;

    bool installer_spoof_enabled = false;
    std::string installer_package = "com.android.vending";

    // Master switch (UI page "Hide Dev"). When false, all sub-options are treated as disabled.
    bool hide_dev_options_enabled = false;

    // Split options (mirrors temp/ImNotADeveloper PrefKeys)
    bool hide_developer_mode = true;
    bool hide_usb_debug = true;
    bool hide_wireless_debug = true;
    bool hide_debug_properties = true;
    bool hide_debug_properties_in_native = true;
};

// Read `/data/adb/modules/envcloak/config.json`.
// On error / missing file, returns defaults (empty packages => no app enabled).
Config read_config();

// Extract package name from process "nice name", e.g.:
// - "com.foo.bar" -> "com.foo.bar"
// - "com.foo.bar:service" -> "com.foo.bar"
// Returns empty string if input is null/empty.
std::string process_name_to_package(const char *nice_name);

} // namespace config
} // namespace envcloak

