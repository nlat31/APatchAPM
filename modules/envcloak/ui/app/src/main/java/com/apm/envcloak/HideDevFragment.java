package com.apm.envcloak;

import android.os.Bundle;
import android.view.View;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;

import com.google.android.material.switchmaterial.SwitchMaterial;

public class HideDevFragment extends Fragment {
    public HideDevFragment() {
        super(R.layout.fragment_hide_dev);
    }

    private SharedViewModel vm;

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        vm = new ViewModelProvider(requireActivity()).get(SharedViewModel.class);

        SwitchMaterial sw = view.findViewById(R.id.switchEnableHideDev);
        SwitchMaterial swDevMode = view.findViewById(R.id.switchHideDeveloperMode);
        SwitchMaterial swUsb = view.findViewById(R.id.switchHideUsbDebug);
        SwitchMaterial swWifi = view.findViewById(R.id.switchHideWirelessDebug);
        SwitchMaterial swProps = view.findViewById(R.id.switchHideDebugProperties);
        SwitchMaterial swPropsNative = view.findViewById(R.id.switchHideDebugPropertiesInNative);

        Runnable applyEnabled = () -> {
            boolean en = vm.hideDevOptionsEnabled;
            swDevMode.setEnabled(en);
            swUsb.setEnabled(en);
            swWifi.setEnabled(en);
            swProps.setEnabled(en);
            swPropsNative.setEnabled(en);
        };

        sw.setChecked(vm.hideDevOptionsEnabled);
        swDevMode.setChecked(vm.hideDeveloperMode);
        swUsb.setChecked(vm.hideUsbDebug);
        swWifi.setChecked(vm.hideWirelessDebug);
        swProps.setChecked(vm.hideDebugProperties);
        swPropsNative.setChecked(vm.hideDebugPropertiesInNative);
        applyEnabled.run();

        sw.setOnCheckedChangeListener((buttonView, isChecked) -> {
            vm.hideDevOptionsEnabled = isChecked;
            applyEnabled.run();
        });
        swDevMode.setOnCheckedChangeListener((buttonView, isChecked) -> vm.hideDeveloperMode = isChecked);
        swUsb.setOnCheckedChangeListener((buttonView, isChecked) -> vm.hideUsbDebug = isChecked);
        swWifi.setOnCheckedChangeListener((buttonView, isChecked) -> vm.hideWirelessDebug = isChecked);
        swProps.setOnCheckedChangeListener((buttonView, isChecked) -> vm.hideDebugProperties = isChecked);
        swPropsNative.setOnCheckedChangeListener((buttonView, isChecked) -> vm.hideDebugPropertiesInNative = isChecked);
    }
}

