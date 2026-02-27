## appxray

文件操作跟踪模块：

- Native hook：`open/openat/lseek/read/write/close`（日志 + fd->path 映射）

### 配置

模块从 `/data/adb/modules/appxray/config.json` 读取配置（JSON），只有被勾选的包名才会注入（按进程名**前缀**匹配：`包名` / `包名:xxx` / `包名.xxx`）。

配置项：

- `file_monitor_enabled`: 是否启用文件监控（关闭则不安装 file hook）
- `file_names`: 文件名匹配规则（空=监控所有；多个用空格分隔；open 时用字串匹配）

### Paths

- Native entry: `modules/appxray/native/`
- Magisk template: `modules/appxray/magisk/`
- UI app: `modules/appxray/ui/`

