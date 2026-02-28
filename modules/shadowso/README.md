## shadowso

这是一个用于 shadow-load / 伪装模块信息的模块：

- Shadow-load：使用 CSOLoader 额外加载一份目标 so
- 伪装：拦截 `maps`/`dl_iterate_phdr`/`dladdr` 以返回 shadow/原始视图

### 配置

模块从 `/data/adb/modules/shadowso/config.json` 读取配置（JSON），只有被勾选的包名才会注入（按进程名**前缀**匹配：`包名` / `包名:xxx` / `包名.xxx`）。

### Paths

- Native entry: `modules/shadowso/native/`
- Java hook DEX source: `modules/shadowso/java/Hooker.java`
- Magisk template: `modules/shadowso/magisk/`
- Optional UI app: `modules/shadowso/ui/`

