package com.example.sample.settings;

import androidx.lifecycle.ViewModel;

import java.util.LinkedHashSet;
import java.util.Set;

public class SharedViewModel extends ViewModel {
    public boolean showSystemApps = false;
    public final Set<String> selectedPackages = new LinkedHashSet<>();
    public boolean hookNative = false;
    public boolean hookJava = false;

    public void loadFromConfig(ConfigStore.Config cfg) {
        selectedPackages.clear();
        if (cfg != null && cfg.packages != null) selectedPackages.addAll(cfg.packages);
        hookNative = cfg != null && cfg.hookNative;
        hookJava = cfg != null && cfg.hookJava;
    }
}

