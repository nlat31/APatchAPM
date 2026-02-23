package com.example.sample.settings;

import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;

import com.google.android.material.checkbox.MaterialCheckBox;
import com.google.android.material.textfield.TextInputEditText;
import android.widget.RadioButton;
import android.widget.RadioGroup;

public class OptionsFragment extends Fragment {
    public OptionsFragment() {
        super(R.layout.fragment_options);
    }

    private SharedViewModel vm;

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        vm = new ViewModelProvider(requireActivity()).get(SharedViewModel.class);

        MaterialCheckBox cEnable = view.findViewById(R.id.checkEnableHook);
        MaterialCheckBox cWatch = view.findViewById(R.id.checkWatch);
        MaterialCheckBox cOnLoad = view.findViewById(R.id.checkOnLoad);
        MaterialCheckBox cFix = view.findViewById(R.id.checkFix);

        TextInputEditText editDelaySec = view.findViewById(R.id.editDelaySeconds);
        TextInputEditText editEnumDelaySec = view.findViewById(R.id.editEnumDelaySeconds);
        TextInputEditText editSoName = view.findViewById(R.id.editSoName);
        TextInputEditText editRegex = view.findViewById(R.id.editRegex);

        RadioGroup groupMode = view.findViewById(R.id.radioDumpMode);
        RadioButton radioHook = view.findViewById(R.id.radioModeHook);
        RadioButton radioEnum = view.findViewById(R.id.radioModeEnumerate);

        cEnable.setChecked(vm.hookNative);
        cWatch.setChecked(vm.watch);
        cOnLoad.setChecked(vm.onLoad);
        cFix.setChecked(vm.fix);

        cEnable.setOnCheckedChangeListener((buttonView, isChecked) -> vm.hookNative = isChecked);
        cWatch.setOnCheckedChangeListener((buttonView, isChecked) -> vm.watch = isChecked);
        cOnLoad.setOnCheckedChangeListener((buttonView, isChecked) -> vm.onLoad = isChecked);
        cFix.setOnCheckedChangeListener((buttonView, isChecked) -> vm.fix = isChecked);

        boolean isEnum = "enumerate".equals(vm.dumpMode);
        radioEnum.setChecked(isEnum);
        radioHook.setChecked(!isEnum);
        groupMode.setOnCheckedChangeListener((group, checkedId) -> {
            if (checkedId == R.id.radioModeEnumerate) {
                vm.dumpMode = "enumerate";
            } else {
                vm.dumpMode = "hook";
            }
        });

        long sec = vm.delayUs > 0 ? (vm.delayUs / 1_000_000L) : 0L;
        editDelaySec.setText(String.valueOf(sec));
        long enumSec = vm.enumDelayUs > 0 ? (vm.enumDelayUs / 1_000_000L) : 0L;
        editEnumDelaySec.setText(String.valueOf(enumSec));
        editSoName.setText(vm.soName != null ? vm.soName : "");
        editRegex.setText(vm.regex != null ? vm.regex : "");

        editDelaySec.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {}
            @Override public void afterTextChanged(Editable s) {
                String t = s != null ? s.toString().trim() : "";
                long seconds = 0L;
                if (!t.isEmpty()) {
                    try { seconds = Long.parseLong(t); } catch (Throwable ignored) { seconds = 0L; }
                }
                if (seconds < 0) seconds = 0;
                vm.delayUs = seconds * 1_000_000L;
            }
        });

        editEnumDelaySec.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {}
            @Override public void afterTextChanged(Editable s) {
                String t = s != null ? s.toString().trim() : "";
                long seconds = 0L;
                if (!t.isEmpty()) {
                    try { seconds = Long.parseLong(t); } catch (Throwable ignored) { seconds = 0L; }
                }
                if (seconds < 0) seconds = 0;
                vm.enumDelayUs = seconds * 1_000_000L;
            }
        });

        editSoName.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {}
            @Override public void afterTextChanged(Editable s) {
                vm.soName = s != null ? s.toString() : "";
            }
        });

        editRegex.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {}
            @Override public void afterTextChanged(Editable s) {
                vm.regex = s != null ? s.toString() : "";
            }
        });
    }
}

