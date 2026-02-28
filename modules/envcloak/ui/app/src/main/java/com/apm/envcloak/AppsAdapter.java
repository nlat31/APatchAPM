package com.apm.envcloak;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.DiffUtil;
import androidx.recyclerview.widget.ListAdapter;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.checkbox.MaterialCheckBox;

import java.util.Set;

public class AppsAdapter extends ListAdapter<ApplicationInfo, AppsAdapter.VH> {
    private final PackageManager pm;
    private final Set<String> selected;

    public AppsAdapter(PackageManager pm, Set<String> selected) {
        super(DIFF);
        this.pm = pm;
        this.selected = selected;
    }

    static final DiffUtil.ItemCallback<ApplicationInfo> DIFF = new DiffUtil.ItemCallback<ApplicationInfo>() {
        @Override public boolean areItemsTheSame(@NonNull ApplicationInfo oldItem, @NonNull ApplicationInfo newItem) {
            return oldItem.packageName.equals(newItem.packageName);
        }

        @Override public boolean areContentsTheSame(@NonNull ApplicationInfo oldItem, @NonNull ApplicationInfo newItem) {
            return oldItem.packageName.equals(newItem.packageName);
        }
    };

    static class VH extends RecyclerView.ViewHolder {
        ImageView icon;
        TextView title;
        TextView subtitle;
        MaterialCheckBox check;
        VH(@NonNull View itemView) {
            super(itemView);
            icon = itemView.findViewById(R.id.icon);
            title = itemView.findViewById(R.id.title);
            subtitle = itemView.findViewById(R.id.subtitle);
            check = itemView.findViewById(R.id.check);
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

        CharSequence label = pm.getApplicationLabel(ai);
        Drawable icon = pm.getApplicationIcon(ai);

        holder.title.setText(label);
        holder.subtitle.setText(pkg);
        holder.icon.setImageDrawable(icon);

        holder.check.setOnCheckedChangeListener(null);
        holder.check.setChecked(selected.contains(pkg));
        holder.check.setOnCheckedChangeListener((buttonView, isChecked) -> {
            if (isChecked) selected.add(pkg);
            else selected.remove(pkg);
        });

        holder.itemView.setOnClickListener(v -> holder.check.toggle());
    }
}

