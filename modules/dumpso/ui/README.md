## UI (optional)

如果需要做复杂配置，建议为模块开发一个独立 Android App（需要 root 写配置文件）。

本目录是 `dumpso` 模块的设置 App。

### 配置文件

- Path: `/data/adb/modules/dumpso/config.json`
- Format:

```json
{
  "version": 1,
  "watch": false,
  "fix": true,
  "delay_us": 0,
  "dump_mode": "hook",
  "enum_delay_us": 0,
  "so_name": "libil2cpp.so",
  "packages": ["com.example.app", "com.example.app:remote"]
}
```

模块逻辑：
- 只有 `packages` 中被勾选的 app 才会被注入（按进程名**前缀**匹配：`包名` / `包名:xxx` / `包名.xxx`）
- `so_name` 为空时会 dump 所有（hook 模式：dump 所有触发 do_dlopen 的库；枚举模式：dump 所有可枚举到的模块）
- `delay_us` 用于延迟 dump（例如等待 so 解密完成）
- `dump_mode=hook`：hook 模式（会安装 hook）
- `dump_mode=enumerate`：枚举模式（不会安装 hook；在 `enum_delay_us` 后枚举并 dump 所有 `.so`）


