package com.example.sample.settings;

import android.os.Bundle;
import android.view.View;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;

import com.google.android.material.checkbox.MaterialCheckBox;

public class OptionsFragment extends Fragment {
    public OptionsFragment() {
        super(R.layout.fragment_options);
    }

    private SharedViewModel vm;

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        vm = new ViewModelProvider(requireActivity()).get(SharedViewModel.class);

        MaterialCheckBox cNative = view.findViewById(R.id.checkHookNative);
        MaterialCheckBox cJava = view.findViewById(R.id.checkHookJava);

        cNative.setChecked(vm.hookNative);
        cJava.setChecked(vm.hookJava);

        cNative.setOnCheckedChangeListener((buttonView, isChecked) -> vm.hookNative = isChecked);
        cJava.setOnCheckedChangeListener((buttonView, isChecked) -> vm.hookJava = isChecked);
    }
}

