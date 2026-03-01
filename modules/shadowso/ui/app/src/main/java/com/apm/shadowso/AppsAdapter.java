package com.apm.shadowso;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.DiffUtil;
import androidx.recyclerview.widget.ListAdapter;
import androidx.recyclerview.widget.RecyclerView;

import java.util.Set;

public class AppsAdapter extends ListAdapter<ApplicationInfo, AppsAdapter.VH> {
    private final PackageManager pm;
    private final Set<String> selected;

    public AppsAdapter(PackageManager pm, Set<String> selected) {
        super(DIFF);
        this.pm = pm;
        this.selected = selected;
    }

    static class VH extends RecyclerView.ViewHolder {
        final ImageView icon;
        final TextView title;
        final TextView subtitle;
        final CheckBox check;

        VH(@NonNull View v) {
            super(v);
            icon = v.findViewById(R.id.icon);
            title = v.findViewById(R.id.title);
            subtitle = v.findViewById(R.id.subtitle);
            check = v.findViewById(R.id.check);
        }
    }

    @NonNull
    @Override
    public VH onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View v = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_app, parent, false);
        return new VH(v);
    }

    @Override
    public void onBindViewHolder(@NonNull VH holder, int position) {
        ApplicationInfo ai = getItem(position);
        String pkg = ai.packageName;

        String label = pm.getApplicationLabel(ai).toString();
        Drawable icon = null;
        try {
            icon = pm.getApplicationIcon(ai);
        } catch (Throwable ignored) {
        }

        holder.title.setText(label);
        holder.subtitle.setText(pkg);
        holder.icon.setImageDrawable(icon);

        holder.check.setOnCheckedChangeListener(null);
        holder.check.setChecked(selected.contains(pkg));
        holder.check.setOnCheckedChangeListener((buttonView, isChecked) -> {
            if (isChecked) selected.add(pkg);
            else selected.remove(pkg);
        });

        holder.itemView.setOnClickListener(v -> holder.check.setChecked(!holder.check.isChecked()));
    }

    private static final DiffUtil.ItemCallback<ApplicationInfo> DIFF = new DiffUtil.ItemCallback<ApplicationInfo>() {
        @Override
        public boolean areItemsTheSame(@NonNull ApplicationInfo oldItem, @NonNull ApplicationInfo newItem) {
            return oldItem.packageName.equals(newItem.packageName);
        }

        @Override
        public boolean areContentsTheSame(@NonNull ApplicationInfo oldItem, @NonNull ApplicationInfo newItem) {
            return oldItem.packageName.equals(newItem.packageName) && oldItem.flags == newItem.flags;
        }
    };
}

