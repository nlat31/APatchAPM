## UI (optional)

如果需要做复杂配置，建议为模块开发一个独立 Android App（需要 root 写配置文件）。

本目录是 `sample` 模块的设置 App。

### 配置文件

- Path: `/data/adb/modules/sample/config.json`
- Format:

```json
{
  "version": 1,
  "hook_native": true,
  "hook_java": true,
  "packages": ["com.example.app", "com.example.app:remote"]
}
```

模块逻辑：
- 只有 `packages` 中被勾选的 app 才会被注入（按进程名匹配 `包名` 或 `包名:xxx`）
- `hook_native=true` 才会 hook `__loader_dlopen`
- `hook_java=true` 才会 hook `System.loadLibrary`
- 两项都为 false：只注入不执行 hook


