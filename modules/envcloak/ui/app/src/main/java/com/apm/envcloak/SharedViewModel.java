package com.apm.envcloak;

import androidx.lifecycle.ViewModel;

import java.util.LinkedHashSet;
import java.util.Set;

public class SharedViewModel extends ViewModel {
    public boolean showSystemApps = false;
    public final Set<String> selectedPackages = new LinkedHashSet<>();

    public boolean installerSpoofEnabled = false;
    public String installerPackage = "com.android.vending";

    // Master switch for the "Hide Dev" page
    public boolean hideDevOptionsEnabled = false;

    // Split switches (defaults match temp/ImNotADeveloper: true)
    public boolean hideDeveloperMode = true;
    public boolean hideUsbDebug = true;
    public boolean hideWirelessDebug = true;
    public boolean hideDebugProperties = true;
    public boolean hideDebugPropertiesInNative = true;

    public void loadFromConfig(ConfigStore.Config cfg) {
        selectedPackages.clear();
        if (cfg != null && cfg.packages != null) selectedPackages.addAll(cfg.packages);

        installerSpoofEnabled = cfg != null && cfg.installerSpoofEnabled;
        installerPackage = (cfg != null && cfg.installerPackage != null && !cfg.installerPackage.trim().isEmpty())
            ? cfg.installerPackage.trim()
            : "com.android.vending";

        hideDevOptionsEnabled = cfg != null && cfg.hideDevOptionsEnabled;
        hideDeveloperMode = cfg == null || cfg.hideDeveloperMode;
        hideUsbDebug = cfg == null || cfg.hideUsbDebug;
        hideWirelessDebug = cfg == null || cfg.hideWirelessDebug;
        hideDebugProperties = cfg == null || cfg.hideDebugProperties;
        hideDebugPropertiesInNative = cfg == null || cfg.hideDebugPropertiesInNative;
    }
}

