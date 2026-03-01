package com.apm.shadowso;

import androidx.lifecycle.ViewModel;

import java.util.LinkedHashSet;
import java.util.Set;

public class SharedViewModel extends ViewModel {
    public boolean showSystemApps = false;
    public final Set<String> selectedPackages = new LinkedHashSet<>();
    public boolean enabled = false;
    public boolean initLsplant = false;
    public boolean hookJava = false;
    public boolean optMapsRedirect = false;
    public boolean optHookPhdr = false;
    public boolean optHookDladdr = false;
    public String hideSoInput = "libc.so libart.so";

    public void loadFromConfig(ConfigStore.Config cfg) {
        selectedPackages.clear();
        if (cfg != null && cfg.packages != null) selectedPackages.addAll(cfg.packages);
        enabled = cfg != null && cfg.enabled;
        initLsplant = cfg != null && cfg.initLsplant;
        hookJava = cfg != null && cfg.hookJava;
        optMapsRedirect = cfg != null && cfg.optMapsRedirect;
        optHookPhdr = cfg != null && cfg.optHookPhdr;
        optHookDladdr = cfg != null && cfg.optHookDladdr;
        if (cfg != null && cfg.hideSo != null) {
            StringBuilder sb = new StringBuilder();
            for (String s : cfg.hideSo) {
                if (s == null) continue;
                String t = s.trim();
                if (t.isEmpty()) continue;
                if (sb.length() > 0) sb.append(' ');
                sb.append(t);
            }
            hideSoInput = sb.toString();
        }
    }
}

