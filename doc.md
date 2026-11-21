## 逆向排查与架构演进记录

1. **第一阶段：摸底（用 `otool` 和 `strings` 定位线索）**
   - `otool -ov` 用于打印二进制里所有暴露给 Objective-C 运行时的类名、方法名和成员变量偏移量。从中拿到防截屏的窗口方法、控制聊天框文字选中的 `_TtC6ChatUI15ChatInteraction`（`disableSelectAbility`），以及老版底部广告视图 `ChatSponsoredView`。
   - `strings` 用于提取明文字符串。纯 Swift 代码编译后函数符号被抹除（Strip），无法按函数名定位，但编译器保留了 `AdMessages.swift`、`ApplyMaxReadIndexInteractively.swift`、`CopyProtection.swift` 等源码路径字符串，可作为 ARM64 `ADRP+ADD` 交叉引用扫描的定位锚点。

2. **第二阶段：注入与体积精简**
   - 使用 `lipo -thin arm64` 剔除主程序与 Swift 动态库中的 Intel（`x86_64`）切片（改用临时文件写入后原子替换，避免中断写坏原二进制），同时删掉 `TelegramShare.appex`、Sparkle 自动更新器和多余语言包，整体体积减少超过 60%。
   - 向主程序 Mach-O 头部加载表末尾追加 `LC_LOAD_DYLIB` 指令，启动时加载纯 Rust 编译的 `libtg_patch.dylib`，并在顶部菜单栏挂载控制面板。

3. **第三阶段：解决启动闪退、`Data Access Blocked` 与清理工具误删**
   - 官网/GitHub 直装版与 App Store 版共用带官方团队号（`6N38VWS5BX`）的 `~/Library/Group Containers/6N38VWS5BX.ru.keepcoder.Telegram`。本地重签后失去官方私钥，macOS TCC 会直接拦截访问并返回空路径，Telegram 源码强制解包该路径导致立刻闪退（`brk 1`）。
   - **解法**：在重签名权限表中剔除带官方团队号的 `application-groups`，并在动态库加载第一时间钩住 `NSFileManager` 的 `containerURLForSecurityApplicationGroupIdentifier:`。仅当查询 ID 包含 `ru.keepcoder.Telegram` 时重定向，其余系统请求原样传递。
   - **目录命名修正**：早期重定向至 `~/Library/Application Support/TelegramPatcher/Container`，因该目录名无法对应已安装软件的 Bundle ID，易被 Mole 等清理工具判定为孤儿目录误删。后续统一改道至 `~/Library/Application Support/ru.keepcoder.Telegram`（与 `/Applications/Telegram.app` 的 Bundle ID 一致，并去掉多余的 `Container/` 层级），并在 CLI 与动态库中内置旧目录原地无损迁移逻辑。

4. **第四阶段：掐断伪装成聊天气泡的频道赞助广告**
   - 新版 Telegram 将频道广告做成了普通消息气泡，不再走老版 `ChatSponsoredView`。通过定位 `_TtC12TelegramCore...AdMessagesHistoryContextImpl` 与 `AdMessages.swift`，抓到 3 处关键指令并改为基于 `__text` 代码节的 ARM64 特征码自动扫描：
     1. 本地 5 分钟（`300` 秒）缓存广告分支（`b.le` -> `NOP`），废除本地缓存广告（`13.2.0` 命中 `0x100a3b488`）。
     2. 广告数组条数读取（`ldr x27, [x19, #0x10]` -> `mov x27, #0`），强制条数为 0 直接走空数组返回（`13.2.0` 命中 `0x100a3b5e8`）。
     3. 激活拉取广告入口（`tbz` -> `NOP`），直接退出不发网络请求（`13.2.0` 命中 `0x100a3b848`）。
   - **稳定性修正**：早期支持在菜单栏运行时热切去广告开关，会通过 `vm_protect` 在多线程运行期间撤销 16KB 代码页可执行权限，存在并发踩空触发 `EXC_BAD_ACCESS` 闪退风险。现改为仅在进程单线程启动阶段写入一次，菜单栏切换后重启生效。

5. **第五阶段：13.2.0（Build 283494）代码审计与高危缺陷修复**
   - **补签 `XPCServices`**：`lipo` 裁减会处理 `Contents/XPCServices/WidgetEngineService.xpc`，旧版签名逻辑漏掉了该目录导致组件签名损坏，现已补齐递归重签名，并新增 `--sign-identity` 支持本地自建证书。
   - **平稳退出保缓存**：旧版使用 `killall -9` 强杀正在读写 6 个 SQLite WAL 数据库的进程，存在损坏 `postbox/media` 索引的风险。现改为先发 `SIGTERM` 等待最多 4 秒落盘，超时后再强杀。
   - **放弃二进制注入实现「无痕 / 防撤回 / 底层解保存」的结论**：
     - 对 `13.2.0` 的 `CopyProtection.swift`（`0x100c97c50`、`0x100cfa5b4`）反汇编确认，其核心是提交 `postbox.transaction` 修改会话保护状态，而非界面层判断能否保存/复制的开关；真正限制保存的判断被 Swift 编译器大量内联散落在 `ChatUI`，跨版本维护成本过高。
     - `ApplyMaxReadIndexInteractively.swift`（`0x100a41ddc`）和 `TypingDraftStop.swift`（`0x100b8cd40`）均为纯 Swift `Signal` 构造函数，返回带引用计数的异步对象，单靠指令修改无法安全构造合法空 `Signal`，硬改必崩或破坏未读计数。

---

## 逆向探针脚本留档

### 1. 广告特征探测

```fish
begin
    echo "=== 1. 赞助广告相关 MTProto 协议构造器与字符串 ==="
    strings -n 6 /Applications/Telegram.app/Contents/MacOS/Telegram | rg -i "(sponsored|admessage|hidead|removead|markad)" | rg -v "PeerInfo|Localizable" | sort -u | head -n 80

    echo -e "\n=== 2. 广告相关 Swift 源码路径锚点 ==="
    strings -n 8 /Applications/Telegram.app/Contents/MacOS/Telegram | rg "\.swift\$" | rg -i "(Ad|Sponsor)" | sort -u

    echo -e "\n=== 3. ChatUI / ChatRowItem 中与广告相关的类与成员变量 (Ivars) ==="
    otool -ov /Applications/Telegram.app/Contents/MacOS/Telegram | rg -B 2 -A 6 -i "name.*(sponsor|adattribute|admessage|removead|isad)"
end
```

### 2. 版本、权限表与源码锚点探测

```fish
begin
    echo "=== 1. 版本与更新渠道 ==="
    /usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" -c "Print :CFBundleVersion" -c "Print :SUFeedURL" /Applications/Telegram.app/Contents/Info.plist 2>/dev/null

    echo -e "\n=== 2. 签名权限表 (Entitlements) ==="
    codesign -d --entitlements :- /Applications/Telegram.app 2>/dev/null

    echo -e "\n=== 3. 包内组件与插件结构 ==="
    ls -la /Applications/Telegram.app/Contents/Frameworks /Applications/Telegram.app/Contents/PlugIns /Applications/Telegram.app/Contents/XPCServices /Applications/Telegram.app/Contents/Helpers 2>/dev/null

    echo -e "\n=== 4. 核心源码路径锚点 ==="
    strings -n 8 /Applications/Telegram.app/Contents/MacOS/Telegram | rg "\.swift\$" | rg -i "(Read|CopyProtection|Delete|Sponsored|Premium|Screenshot|Secret|Account|Typing)" | sort -u
end
```
