## sample (template)

这是一个用于复制/改名的**样板模块**，仅包含最小闭环：

- Java hook：`java.lang.System.loadLibrary(String)`（日志）
- Native hook：`__loader_dlopen`（日志，best-effort）

### 配置

模块从 `/data/adb/modules/sample/config.json` 读取配置（JSON），只有被勾选的包名才会注入。

### Paths

- Native entry: `modules/sample/native/`
- Java hook DEX source: `modules/sample/java/Hooker.java`
- Magisk template: `modules/sample/magisk/`
- Optional UI app placeholder: `modules/sample/ui/`

