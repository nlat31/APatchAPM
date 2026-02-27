package com.example.sample.settings;

import androidx.lifecycle.ViewModel;

import java.util.LinkedHashSet;
import java.util.Set;

public class SharedViewModel extends ViewModel {
    public boolean showSystemApps = false;
    public final Set<String> selectedPackages = new LinkedHashSet<>();
    public boolean fileMonitorEnabled = false;
    public String fileNames = "";

    public void loadFromConfig(ConfigStore.Config cfg) {
        selectedPackages.clear();
        if (cfg != null && cfg.packages != null) selectedPackages.addAll(cfg.packages);
        fileMonitorEnabled = cfg != null && cfg.fileMonitorEnabled;
        fileNames = cfg != null && cfg.fileNames != null ? cfg.fileNames : "";
    }
}

