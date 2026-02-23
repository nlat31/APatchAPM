package com.apm.dumpso;

import androidx.lifecycle.ViewModel;

import java.util.LinkedHashSet;
import java.util.Set;

public class SharedViewModel extends ViewModel {
    public boolean showSystemApps = false;
    public final Set<String> selectedPackages = new LinkedHashSet<>();
    public boolean watch = false;
    public boolean fix = true;
    public long delayUs = 0L;
    public String dumpMode = "hook";
    public long enumDelayUs = 0L;
    public String soName = "";

    public void loadFromConfig(ConfigStore.Config cfg) {
        selectedPackages.clear();
        if (cfg != null && cfg.packages != null) selectedPackages.addAll(cfg.packages);
        watch = cfg != null && cfg.watch;
        fix = cfg == null || cfg.fix;
        delayUs = cfg != null ? Math.max(0L, cfg.delayUs) : 0L;
        dumpMode = cfg != null && cfg.dumpMode != null ? cfg.dumpMode : "hook";
        enumDelayUs = cfg != null ? Math.max(0L, cfg.enumDelayUs) : 0L;
        soName = cfg != null && cfg.soName != null ? cfg.soName : "";
    }
}

