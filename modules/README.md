## modules/ 目录结构约定

这个仓库支持在同一个工程里开发多个 Zygisk 模块。每个模块放在 `modules/<module_id>/` 下。

### 每个模块的推荐布局

```
modules/<module_id>/
  native/               # Zygisk .so (CMake target)
    CMakeLists.txt
    *.cpp *.h
    export.map
  java/                 # 可选：InMemoryDexClassLoader 加载的 Hooker.java
    Hooker.java
  magisk/               # Magisk 模块模板文件（打包时会与编译产物合并）
    module.prop
    customize.sh
    classes.dex         # 可选：由 ./compile_hook.sh 生成
    META-INF/...
  ui/                   # 可选：对应的独立配置 App（不参与本仓库的默认构建）
```

### 构建与打包

- `./build.sh` 会自动扫描 `modules/*/native/CMakeLists.txt` 并编译所有模块，产物会 staging 到 `out/<module_id>/module/zygisk/<abi>.so`。
- `./build.sh` 打包时会读取 `modules/<module_id>/magisk/module.prop`，把 `magisk/` 下的文件复制到 staging 目录，并生成 zip 到 `./out/`。
- `./compile_hook.sh` 会扫描 `modules/*/java/Hooker.java`，把每个模块的 `Hooker.java` 编译成 `modules/<module_id>/magisk/classes.dex`（需要 Android SDK build-tools）。

