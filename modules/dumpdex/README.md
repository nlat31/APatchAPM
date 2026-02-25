## sample (template)

这是一个用于复制/改名的**样板模块**，仅包含最小闭环：

- Java hook：`android.app.ActivityThread.main(String[] args)`（日志）
- Native hook：`android_dlopen_ext`（日志）

### 配置

模块从 `/data/adb/modules/sample/config.json` 读取配置（JSON），只有被勾选的包名才会注入（按进程名**前缀**匹配：`包名` / `包名:xxx` / `包名.xxx`）。

### Paths

- Native entry: `modules/sample/native/`
- Java hook DEX source: `modules/sample/java/Hooker.java`
- Magisk template: `modules/sample/magisk/`
- Optional UI app placeholder: `modules/sample/ui/`

