## UI (optional)

如果需要做复杂配置，建议为模块开发一个独立 Android App（需要 root 写配置文件）。

本目录为 `envcloak` 模块的 UI 工程；当前仓库未把 UI 编译集成到 `build.sh`。

### 配置文件

UI 会读写：`/data/adb/modules/envcloak/config.json`

字段：

- `packages`: 作用目标包名数组（按进程名 `com.pkg(:suffix)?` 前缀匹配）
- `installer_spoof_enabled`: 是否启用安装来源伪装
- `installer_package`: 安装来源包名（默认 `com.android.vending`）
- `hide_dev_options_enabled`: 隐藏开发者选项总开关（关闭则不安装任何 hide-dev 相关 hook）
- `hide_developer_mode`: 隐藏开发者模式（Settings: `development_settings_enabled`)
- `hide_usb_debug`: 隐藏 USB 调试（Settings: `adb_enabled`)
- `hide_wireless_debug`: 隐藏无线调试（Settings: `adb_wifi_enabled`)
- `hide_debug_properties`: 隐藏调试属性（Java: `SystemProperties.native_get*` + `getprop` 命令掩码）
- `hide_debug_properties_in_native`: 隐藏调试属性（Native: `__system_property_get/find`）

