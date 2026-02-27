package com.apm.envcloak;

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
import com.google.android.material.textfield.TextInputLayout;

public class InstallerSpoofFragment extends Fragment {
    public InstallerSpoofFragment() {
        super(R.layout.fragment_installer_spoof);
    }

    private SharedViewModel vm;

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        vm = new ViewModelProvider(requireActivity()).get(SharedViewModel.class);

        SwitchMaterial sw = view.findViewById(R.id.switchEnableInstallerSpoof);
        TextInputLayout til = view.findViewById(R.id.inputInstallerPkgLayout);
        TextInputEditText et = view.findViewById(R.id.editInstallerPkg);

        sw.setChecked(vm.installerSpoofEnabled);
        et.setText(vm.installerPackage);
        til.setEnabled(vm.installerSpoofEnabled);

        sw.setOnCheckedChangeListener((buttonView, isChecked) -> {
            vm.installerSpoofEnabled = isChecked;
            til.setEnabled(isChecked);
        });

        et.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {}
            @Override public void afterTextChanged(Editable s) {
                String v = s != null ? s.toString().trim() : "";
                vm.installerPackage = v.isEmpty() ? "com.android.vending" : v;
            }
        });
    }
}

