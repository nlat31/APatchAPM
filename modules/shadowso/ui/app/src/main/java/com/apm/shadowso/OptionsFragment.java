package com.apm.shadowso;

import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;

import com.google.android.material.switchmaterial.SwitchMaterial;
import com.google.android.material.textfield.TextInputEditText;

public class OptionsFragment extends Fragment {
    public OptionsFragment() {
        super(R.layout.fragment_options);
    }

    private SharedViewModel vm;

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        vm = new ViewModelProvider(requireActivity()).get(SharedViewModel.class);

        SwitchMaterial switchEnabled = view.findViewById(R.id.switchEnabled);
        SwitchMaterial switchInitLsplant = view.findViewById(R.id.switchInitLsplant);
        SwitchMaterial switchJavaHook = view.findViewById(R.id.switchJavaHook);
        SwitchMaterial switchMaps = view.findViewById(R.id.switchMaps);
        SwitchMaterial switchPhdr = view.findViewById(R.id.switchPhdr);
        SwitchMaterial switchDladdr = view.findViewById(R.id.switchDladdr);
        TextInputEditText editHideSo = view.findViewById(R.id.editHideSo);

        switchEnabled.setChecked(vm.enabled);
        Runnable updateEnabledState = () -> {
            boolean on = vm.enabled;
            if (switchInitLsplant != null) switchInitLsplant.setEnabled(on);
            if (switchJavaHook != null) switchJavaHook.setEnabled(on && vm.initLsplant);
            if (switchMaps != null) switchMaps.setEnabled(on);
            if (switchPhdr != null) switchPhdr.setEnabled(on);
            if (switchDladdr != null) switchDladdr.setEnabled(on);
            if (editHideSo != null) editHideSo.setEnabled(on);
        };
        switchEnabled.setOnCheckedChangeListener((buttonView, isChecked) -> {
            vm.enabled = isChecked;
            updateEnabledState.run();
        });

        if (switchInitLsplant != null) {
            switchInitLsplant.setChecked(vm.initLsplant);
            switchInitLsplant.setOnCheckedChangeListener((buttonView, isChecked) -> {
                vm.initLsplant = isChecked;
                if (!isChecked && switchJavaHook != null) {
                    switchJavaHook.setChecked(false);
                    vm.hookJava = false;
                }
                updateEnabledState.run();
            });
        }

        if (switchJavaHook != null) {
            switchJavaHook.setChecked(vm.hookJava);
            switchJavaHook.setOnCheckedChangeListener((buttonView, isChecked) -> vm.hookJava = isChecked);
        }

        if (editHideSo != null) {
            editHideSo.setText(vm.hideSoInput);

            editHideSo.addTextChangedListener(new TextWatcher() {
                @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
                @Override public void onTextChanged(CharSequence s, int start, int before, int count) {}
                @Override public void afterTextChanged(Editable s) {
                    vm.hideSoInput = s != null ? s.toString() : "";
                }
            });
        }

        if (switchMaps != null) {
            switchMaps.setChecked(vm.optMapsRedirect);
            switchMaps.setOnCheckedChangeListener((buttonView, isChecked) -> vm.optMapsRedirect = isChecked);
        }
        if (switchPhdr != null) {
            switchPhdr.setChecked(vm.optHookPhdr);
            switchPhdr.setOnCheckedChangeListener((buttonView, isChecked) -> vm.optHookPhdr = isChecked);
        }
        if (switchDladdr != null) {
            switchDladdr.setChecked(vm.optHookDladdr);
            switchDladdr.setOnCheckedChangeListener((buttonView, isChecked) -> vm.optHookDladdr = isChecked);
        }

        updateEnabledState.run();
    }
}

