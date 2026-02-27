package com.example.sample.settings;

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

public class OptionsFragment extends Fragment {
    public OptionsFragment() {
        super(R.layout.fragment_options);
    }

    private SharedViewModel vm;

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        vm = new ViewModelProvider(requireActivity()).get(SharedViewModel.class);

        SwitchMaterial sw = view.findViewById(R.id.switchEnableFileMonitor);
        TextInputLayout til = view.findViewById(R.id.inputFileNamesLayout);
        TextInputEditText et = view.findViewById(R.id.editFileNames);

        sw.setChecked(vm.fileMonitorEnabled);
        til.setEnabled(vm.fileMonitorEnabled);
        et.setText(vm.fileNames);

        sw.setOnCheckedChangeListener((buttonView, isChecked) -> {
            vm.fileMonitorEnabled = isChecked;
            til.setEnabled(isChecked);
        });

        et.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {}
            @Override public void afterTextChanged(Editable s) {
                vm.fileNames = s != null ? s.toString() : "";
            }
        });
    }
}

