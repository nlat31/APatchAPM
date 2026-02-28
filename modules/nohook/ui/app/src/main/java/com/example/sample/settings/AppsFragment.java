package com.example.sample.settings;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Build;
import android.view.View;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.switchmaterial.SwitchMaterial;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public class AppsFragment extends Fragment {
    public AppsFragment() {
        super(R.layout.fragment_apps);
    }

    private SharedViewModel vm;
    private AppsAdapter adapter;

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        vm = new ViewModelProvider(requireActivity()).get(SharedViewModel.class);

        SwitchMaterial switchShowSystem = view.findViewById(R.id.switchShowSystem);
        RecyclerView recycler = view.findViewById(R.id.recyclerApps);

        recycler.setLayoutManager(new LinearLayoutManager(requireContext()));
        adapter = new AppsAdapter(requireContext().getPackageManager(), vm.selectedPackages);
        recycler.setAdapter(adapter);

        Runnable loadApps = () -> {
            PackageManager pm = requireContext().getPackageManager();
            List<ApplicationInfo> apps;
            if (Build.VERSION.SDK_INT >= 33) {
                apps = pm.getInstalledApplications(
                    PackageManager.ApplicationInfoFlags.of(PackageManager.GET_META_DATA)
                );
            } else {
                apps = pm.getInstalledApplications(PackageManager.GET_META_DATA);
            }
            List<ApplicationInfo> filtered = new ArrayList<>();
            for (ApplicationInfo ai : apps) {
                boolean isSystem = (ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
                boolean isUpdatedSystem = (ai.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0;
                boolean treatAsSystem = isSystem || isUpdatedSystem;
                if (vm.showSystemApps || !treatAsSystem) {
                    filtered.add(ai);
                }
            }
            Collections.sort(filtered, Comparator.comparing(ai ->
                pm.getApplicationLabel(ai).toString().toLowerCase()
            ));
            adapter.submitList(filtered);
        };

        switchShowSystem.setChecked(vm.showSystemApps);
        switchShowSystem.setOnCheckedChangeListener((buttonView, isChecked) -> {
            vm.showSystemApps = isChecked;
            loadApps.run();
        });

        loadApps.run();
    }

    public void clearSelection() {
        if (vm != null) vm.selectedPackages.clear();
        if (adapter != null) adapter.notifyDataSetChanged();
    }
}

