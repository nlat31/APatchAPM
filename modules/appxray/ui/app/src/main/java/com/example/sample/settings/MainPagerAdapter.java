package com.example.sample.settings;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.fragment.app.Fragment;
import androidx.viewpager2.adapter.FragmentStateAdapter;

public class MainPagerAdapter extends FragmentStateAdapter {
    public MainPagerAdapter(@NonNull AppCompatActivity activity) {
        super(activity);
    }

    @NonNull
    @Override
    public Fragment createFragment(int position) {
        if (position == 0) return new AppsFragment();
        if (position == 1) return new OptionsFragment();
        return new DlMonitorFragment();
    }

    @Override
    public int getItemCount() {
        return 3;
    }
}

