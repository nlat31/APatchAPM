package com.example.sample.settings;

import android.os.Bundle;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.lifecycle.ViewModelProvider;
import androidx.viewpager2.widget.ViewPager2;

import com.google.android.material.floatingactionbutton.ExtendedFloatingActionButton;
import com.google.android.material.tabs.TabLayout;
import com.google.android.material.tabs.TabLayoutMediator;

public class MainActivity extends AppCompatActivity {
    private SharedViewModel vm;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        vm = new ViewModelProvider(this).get(SharedViewModel.class);

        ViewPager2 pager = findViewById(R.id.pager);
        TabLayout tabs = findViewById(R.id.tabs);
        ExtendedFloatingActionButton btnClear = findViewById(R.id.btnClear);
        ExtendedFloatingActionButton btnApply = findViewById(R.id.btnApply);

        pager.setAdapter(new MainPagerAdapter(this));
        new TabLayoutMediator(tabs, pager, (tab, pos) -> {
            tab.setText(getString(pos == 0 ? R.string.tab_apps : R.string.tab_options));
        }).attach();

        Runnable updateClearVisibility = () -> btnClear.setVisibility(pager.getCurrentItem() == 0 ? android.view.View.VISIBLE : android.view.View.GONE);
        updateClearVisibility.run();
        pager.registerOnPageChangeCallback(new ViewPager2.OnPageChangeCallback() {
            @Override public void onPageSelected(int position) {
                updateClearVisibility.run();
            }
        });

        btnClear.setOnClickListener(v -> {
            for (androidx.fragment.app.Fragment f : getSupportFragmentManager().getFragments()) {
                if (f instanceof AppsFragment) {
                    ((AppsFragment) f).clearSelection();
                    break;
                }
            }
        });

        // Request root early (shows Magisk prompt)
        if (!RootShell.ensureRoot()) {
            new AlertDialog.Builder(this)
                .setTitle(R.string.app_name)
                .setMessage(R.string.root_required)
                .setPositiveButton(android.R.string.ok, null)
                .show();
        } else {
            ConfigStore.Config cfg = ConfigStore.readConfigOrNull();
            if (cfg != null) vm.loadFromConfig(cfg);
        }

        btnApply.setOnClickListener(v -> {
            if (!RootShell.ensureRoot()) {
                Toast.makeText(this, R.string.root_required, Toast.LENGTH_LONG).show();
                return;
            }

            ConfigStore.Config cfg = new ConfigStore.Config(
                vm.hookNative,
                vm.hookJava,
                new java.util.LinkedHashSet<>(vm.selectedPackages)
            );
            RootShell.Result r = ConfigStore.writeConfig(cfg);
            if (r.code == 0) {
                Toast.makeText(this, "Saved to /data/adb/modules/sample/config.json", Toast.LENGTH_LONG).show();
            } else {
                String msg = (r.err != null && !r.err.trim().isEmpty()) ? r.err : r.out;
                Toast.makeText(this, "Save failed: " + msg, Toast.LENGTH_LONG).show();
            }
        });
    }
}

