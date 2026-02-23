package com.apm.dumpso;

import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;

import com.google.android.material.checkbox.MaterialCheckBox;
import com.google.android.material.card.MaterialCardView;
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

        MaterialCheckBox cWatch = view.findViewById(R.id.checkWatch);
        MaterialCheckBox cFix = view.findViewById(R.id.checkFix);

        TextInputEditText editDelaySec = view.findViewById(R.id.editDelaySeconds);
        TextInputEditText editEnumDelaySec = view.findViewById(R.id.editEnumDelaySeconds);
        TextInputEditText editSoName = view.findViewById(R.id.editSoName);

        RadioGroup groupMode = view.findViewById(R.id.radioDumpMode);
        RadioButton radioHook = view.findViewById(R.id.radioModeHook);
        RadioButton radioEnum = view.findViewById(R.id.radioModeEnumerate);

        MaterialCardView cardHook = view.findViewById(R.id.cardHookMode);
        MaterialCardView cardEnum = view.findViewById(R.id.cardEnumMode);

        cWatch.setChecked(vm.watch);
        cFix.setChecked(vm.fix);

        cWatch.setOnCheckedChangeListener((buttonView, isChecked) -> vm.watch = isChecked);
        cFix.setOnCheckedChangeListener((buttonView, isChecked) -> vm.fix = isChecked);

        boolean isEnum = "enumerate".equals(vm.dumpMode);
        radioEnum.setChecked(isEnum);
        radioHook.setChecked(!isEnum);

        Runnable updateModeUi = () -> {
            boolean e = "enumerate".equals(vm.dumpMode);
            cardHook.setVisibility(e ? View.GONE : View.VISIBLE);
            cardEnum.setVisibility(e ? View.VISIBLE : View.GONE);
        };
        updateModeUi.run();

        groupMode.setOnCheckedChangeListener((group, checkedId) -> {
            if (checkedId == R.id.radioModeEnumerate) {
                vm.dumpMode = "enumerate";
            } else {
                vm.dumpMode = "hook";
            }
            updateModeUi.run();
        });

        long sec = vm.delayUs > 0 ? (vm.delayUs / 1_000_000L) : 0L;
        editDelaySec.setText(String.valueOf(sec));
        long enumSec = vm.enumDelayUs > 0 ? (vm.enumDelayUs / 1_000_000L) : 0L;
        editEnumDelaySec.setText(String.valueOf(enumSec));
        editSoName.setText(vm.soName != null ? vm.soName : "");

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
    }
}

