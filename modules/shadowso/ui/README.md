## UI (optional)

如果需要做复杂配置，建议为模块开发一个独立 Android App（需要 root 写配置文件）。

本目录是 `shadowso` 模块的设置 App。

### 配置文件

- Path: `/data/adb/modules/shadowso/config.json`
- Format:

```json
{
  "version": 2,
  "enabled": true,
  "hook_native": true,
  "hook_java": true,
  "hide_so": ["libc.so", "libart.so"],
  "packages": ["com.example.app", "com.example.app:remote"]
}
```

模块逻辑：
- 只有 `packages` 中被勾选的 app 才会被注入（按进程名**前缀**匹配：`包名` / `包名:xxx` / `包名.xxx`）
- `enabled=false`：仍注入模块，但不安装任何 hook
- `hide_so`：空格分隔填写后会保存为数组（用于指定需要 shadow-load / 伪装的 so 名称）


