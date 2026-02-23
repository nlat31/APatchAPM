package com.example.sample.settings;

import androidx.lifecycle.ViewModel;

import java.util.LinkedHashSet;
import java.util.Set;

public class SharedViewModel extends ViewModel {
    public boolean showSystemApps = false;
    public final Set<String> selectedPackages = new LinkedHashSet<>();
    public boolean hookNative = false;
    public boolean watch = false;
    public boolean onLoad = false;
    public boolean fix = true;
    public long delayUs = 0L;
    public String dumpMode = "hook";
    public long enumDelayUs = 0L;
    public String soName = "";
    public String regex = "";

    public void loadFromConfig(ConfigStore.Config cfg) {
        selectedPackages.clear();
        if (cfg != null && cfg.packages != null) selectedPackages.addAll(cfg.packages);
        hookNative = cfg != null && cfg.hookNative;
        watch = cfg != null && cfg.watch;
        onLoad = cfg != null && cfg.onLoad;
        fix = cfg == null || cfg.fix;
        delayUs = cfg != null ? Math.max(0L, cfg.delayUs) : 0L;
        dumpMode = cfg != null && cfg.dumpMode != null ? cfg.dumpMode : "hook";
        enumDelayUs = cfg != null ? Math.max(0L, cfg.enumDelayUs) : 0L;
        soName = cfg != null && cfg.soName != null ? cfg.soName : "";
        regex = cfg != null && cfg.regex != null ? cfg.regex : "";
    }
}

