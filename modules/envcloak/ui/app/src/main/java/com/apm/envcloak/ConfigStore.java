package com.apm.envcloak;

import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class ConfigStore {
    private ConfigStore() {}

    private static final String MOD_ID = "envcloak";
    private static final String CONFIG_PATH = "/data/adb/modules/" + MOD_ID + "/config.json";

    public static final class Config {
        public final Set<String> packages;
        public final boolean installerSpoofEnabled;
        public final String installerPackage;
        public final boolean hideDevOptionsEnabled;

        // Split switches (mirrors temp/ImNotADeveloper PrefKeys)
        public final boolean hideDeveloperMode;
        public final boolean hideUsbDebug;
        public final boolean hideWirelessDebug;
        public final boolean hideDebugProperties;
        public final boolean hideDebugPropertiesInNative;

        public Config(Set<String> packages,
                      boolean installerSpoofEnabled,
                      String installerPackage,
                      boolean hideDevOptionsEnabled,
                      boolean hideDeveloperMode,
                      boolean hideUsbDebug,
                      boolean hideWirelessDebug,
                      boolean hideDebugProperties,
                      boolean hideDebugPropertiesInNative) {
            this.packages = packages != null ? packages : new HashSet<String>();
            this.installerSpoofEnabled = installerSpoofEnabled;
            this.installerPackage = installerPackage != null ? installerPackage : "com.android.vending";
            this.hideDevOptionsEnabled = hideDevOptionsEnabled;
            this.hideDeveloperMode = hideDeveloperMode;
            this.hideUsbDebug = hideUsbDebug;
            this.hideWirelessDebug = hideWirelessDebug;
            this.hideDebugProperties = hideDebugProperties;
            this.hideDebugPropertiesInNative = hideDebugPropertiesInNative;
        }
    }

    public static Config readConfigOrNull() {
        RootShell.Result r = RootShell.exec("cat '" + CONFIG_PATH + "' 2>/dev/null");
        if (r.code != 0) return null;
        String txt = r.out != null ? r.out.trim() : "";
        if (txt.isEmpty()) return null;

        try {
            JSONObject obj = new JSONObject(txt);
            Set<String> pkgs = new HashSet<>();
            JSONArray arr = obj.optJSONArray("packages");
            if (arr != null) {
                for (int i = 0; i < arr.length(); i++) {
                    String v = arr.optString(i, "");
                    if (v != null && !v.trim().isEmpty()) pkgs.add(v.trim());
                }
            }
            return new Config(
                pkgs,
                obj.optBoolean("installer_spoof_enabled", false),
                obj.optString("installer_package", "com.android.vending"),
                obj.optBoolean("hide_dev_options_enabled", false),
                obj.optBoolean("hide_developer_mode", true),
                obj.optBoolean("hide_usb_debug", true),
                obj.optBoolean("hide_wireless_debug", true),
                obj.optBoolean("hide_debug_properties", true),
                obj.optBoolean("hide_debug_properties_in_native", true)
            );
        } catch (Throwable t) {
            return null;
        }
    }

    public static RootShell.Result writeConfig(Config cfg) {
        try {
            JSONObject obj = new JSONObject();
            obj.put("version", 1);
            obj.put("installer_spoof_enabled", cfg != null && cfg.installerSpoofEnabled);
            obj.put("installer_package", cfg != null ? (cfg.installerPackage != null ? cfg.installerPackage : "com.android.vending") : "com.android.vending");
            obj.put("hide_dev_options_enabled", cfg != null && cfg.hideDevOptionsEnabled);
            obj.put("hide_developer_mode", cfg != null && cfg.hideDeveloperMode);
            obj.put("hide_usb_debug", cfg != null && cfg.hideUsbDebug);
            obj.put("hide_wireless_debug", cfg != null && cfg.hideWirelessDebug);
            obj.put("hide_debug_properties", cfg != null && cfg.hideDebugProperties);
            obj.put("hide_debug_properties_in_native", cfg != null && cfg.hideDebugPropertiesInNative);

            List<String> pkgs = new ArrayList<>();
            if (cfg != null && cfg.packages != null) pkgs.addAll(cfg.packages);
            Collections.sort(pkgs);
            JSONArray arr = new JSONArray();
            for (String p : pkgs) arr.put(p);
            obj.put("packages", arr);

            String json = obj.toString(2);
            String b64 = Base64.encodeToString(json.getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP);

            String cmd =
                "mkdir -p /data/adb/modules/" + MOD_ID + " && " +
                "umask 022 && " +
                "printf '%s' '" + b64 + "' | base64 -d > '" + CONFIG_PATH + "' && " +
                "chmod 0644 '" + CONFIG_PATH + "'";

            return RootShell.exec(cmd);
        } catch (Throwable t) {
            return new RootShell.Result(1, "", String.valueOf(t));
        }
    }
}

