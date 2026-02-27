package com.example.sample.settings;

import android.os.Bundle;
import android.view.View;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;

import com.google.android.material.switchmaterial.SwitchMaterial;

public class DlMonitorFragment extends Fragment {
    public DlMonitorFragment() {
        super(R.layout.fragment_dl_monitor);
    }

    private SharedViewModel vm;

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        vm = new ViewModelProvider(requireActivity()).get(SharedViewModel.class);

        SwitchMaterial sw = view.findViewById(R.id.switchEnableDlMonitor);
        sw.setChecked(vm.dlMonitorEnabled);
        sw.setOnCheckedChangeListener((buttonView, isChecked) -> vm.dlMonitorEnabled = isChecked);
    }
}

