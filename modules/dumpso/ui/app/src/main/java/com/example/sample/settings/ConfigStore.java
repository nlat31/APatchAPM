package com.apm.dumpso;

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

    private static final String MOD_ID = "dumpso";
    private static final String CONFIG_PATH = "/data/adb/modules/" + MOD_ID + "/config.json";

    public static final class Config {
        public final boolean watch;
        public final boolean fix;
        public final long delayUs;
        public final String dumpMode;
        public final long enumDelayUs;
        public final String soName;
        public final Set<String> packages;

        public Config(boolean watch,
                      boolean fix,
                      long delayUs,
                      String dumpMode,
                      long enumDelayUs,
                      String soName,
                      Set<String> packages) {
            this.watch = watch;
            this.fix = fix;
            this.delayUs = delayUs;
            this.dumpMode = dumpMode != null ? dumpMode : "hook";
            this.enumDelayUs = enumDelayUs;
            this.soName = soName != null ? soName : "";
            this.packages = packages != null ? packages : new HashSet<String>();
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
                obj.optBoolean("watch", false),
                obj.optBoolean("fix", true),
                obj.optLong("delay_us", obj.optLong("delay", 0L)),
                obj.optString("dump_mode", "hook"),
                obj.optLong("enum_delay_us", obj.optLong("enum_delay", 0L)),
                obj.optString("so_name", ""),
                pkgs
            );
        } catch (Throwable t) {
            return null;
        }
    }

    public static RootShell.Result writeConfig(Config cfg) {
        try {
            JSONObject obj = new JSONObject();
            obj.put("version", 1);
            obj.put("watch", cfg != null && cfg.watch);
            obj.put("fix", cfg != null && cfg.fix);
            obj.put("delay_us", cfg != null ? Math.max(0L, cfg.delayUs) : 0L);
            obj.put("dump_mode", cfg != null && cfg.dumpMode != null ? cfg.dumpMode : "hook");
            obj.put("enum_delay_us", cfg != null ? Math.max(0L, cfg.enumDelayUs) : 0L);
            obj.put("so_name", cfg != null && cfg.soName != null ? cfg.soName : "");

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

