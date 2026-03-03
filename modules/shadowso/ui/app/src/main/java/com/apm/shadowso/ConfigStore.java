package com.apm.shadowso;

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

    private static final String MOD_ID = "shadowso";
    private static final String CONFIG_PATH = "/data/adb/modules/" + MOD_ID + "/config.json";

    public static final class Config {
        public final boolean enabled;
        public final boolean initLsplant;
        public final boolean hookJava;
        public final boolean optMapsRedirect;
        public final boolean optHookPhdr;
        public final boolean optHookDladdr;
        public final Set<String> packages;
        public final List<String> hideSo; // nullable: null means "not set in config"

        public Config(boolean enabled,
                      boolean initLsplant,
                      boolean hookJava,
                      boolean optMapsRedirect,
                      boolean optHookPhdr,
                      boolean optHookDladdr,
                      Set<String> packages,
                      List<String> hideSo) {
            this.enabled = enabled;
            this.initLsplant = initLsplant;
            this.hookJava = hookJava;
            this.optMapsRedirect = optMapsRedirect;
            this.optHookPhdr = optHookPhdr;
            this.optHookDladdr = optHookDladdr;
            this.packages = packages != null ? packages : new HashSet<String>();
            this.hideSo = hideSo;
        }
    }

    public static String getConfigPath() {
        return CONFIG_PATH;
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
            JSONArray hideArr = obj.optJSONArray("hide_so");
            List<String> hide = null;
            if (hideArr != null) {
                hide = new ArrayList<>();
                for (int i = 0; i < hideArr.length(); i++) {
                    String v = hideArr.optString(i, "");
                    if (v != null && !v.trim().isEmpty()) hide.add(v.trim());
                }
            }

            boolean enabled = obj.optBoolean("enabled", false);
            boolean initLsplant = obj.optBoolean("init_lsplant", false);
            boolean hookJava = obj.optBoolean("hook_java", false);
            if (!enabled) {
                initLsplant = false;
                hookJava = false;
            }

            boolean optMapsRedirect = obj.optBoolean("opt_maps_redirect", false);
            boolean optHookPhdr = obj.optBoolean("opt_hook_phdr", false);
            boolean optHookDladdr = obj.optBoolean("opt_hook_dladdr", false);

            return new Config(enabled, initLsplant, hookJava, optMapsRedirect, optHookPhdr, optHookDladdr, pkgs, hide);
        } catch (Throwable t) {
            return null;
        }
    }

    public static RootShell.Result writeConfig(Config cfg) {
        try {
            JSONObject obj = new JSONObject();
            obj.put("version", 2);
            obj.put("enabled", cfg != null && cfg.enabled);
            obj.put("init_lsplant", cfg != null && cfg.enabled && cfg.initLsplant);
            obj.put("hook_java", cfg != null && cfg.enabled && cfg.hookJava);
            obj.put("opt_maps_redirect", cfg != null && cfg.optMapsRedirect);
            obj.put("opt_hook_phdr", cfg != null && cfg.optHookPhdr);
            obj.put("opt_hook_dladdr", cfg != null && cfg.optHookDladdr);

            List<String> pkgs = new ArrayList<>();
            if (cfg != null && cfg.packages != null) pkgs.addAll(cfg.packages);
            Collections.sort(pkgs);
            JSONArray arr = new JSONArray();
            for (String p : pkgs) arr.put(p);
            obj.put("packages", arr);

            JSONArray hideArr = new JSONArray();
            if (cfg != null && cfg.hideSo != null) {
                for (String s : cfg.hideSo) {
                    if (s != null && !s.trim().isEmpty()) hideArr.put(s.trim());
                }
            }
            obj.put("hide_so", hideArr);

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

