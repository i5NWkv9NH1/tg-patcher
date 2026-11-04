## 逆向排查过程

1. **第一阶段：摸底（最开始用 `otool` 和 `strings` 跑出来的日志）**
   - `otool -ov` 的作用是把二进制里所有**暴露给 Objective-C 运行时的类名、方法名和成员变量偏移量**打印出来。从中拿到了负责防截屏的窗口方法、负责控制聊天框能否选中文字的 `_TtC6ChatUI15ChatInteraction`（偏移 `33` 字节的 `disableSelectAbility`），以及老版底部广告视图 `ChatSponsoredView`。
   - `strings` 的作用是把二进制里所有明文字符串翻出来。因为纯 Swift 代码编译后函数名全被抹掉了（Strip），没法直接按名字找函数，但编译器留下了像 `AdMessages.swift`、`ApplyMaxReadIndexInteractively.swift` 这样的**源码路径字符串**，这就成了我们在茫茫机器码里定位目标函数的「路标」。

2. **第二阶段：注入与瘦身（复用 `futu-patcher` 核心原理）**
   - 用 `lipo -thin arm64` 把主程序和 28 个 Swift 库里的 Intel (`x86_64`) 机器码全部剔除，并删掉 42MB 的系统右键分享插件（`TelegramShare.appex`）和多国语言包，直接把体积从 `343.4 MB` 砍到 `135.0 MB`（减少 `60.7%`）。
   - 往主程序 Mach-O 头部的加载表末尾塞入一条 `LC_LOAD_DYLIB` 指令，让 Telegram 启动时强制加载我们用 Rust 写的 `libtg_patch.dylib`，并在顶部菜单栏挂上「⚡ 增强设置」。

3. **第三阶段：解决启动闪退与 `Data Access Blocked` 弹窗**
   - 第一次打完补丁打开时闪退，是因为之前装过官方原版，系统里留下了带官方开发者团队号（`6N38VWS5BX`）的目录 `~/Library/Group Containers/6N38VWS5BX.ru.keepcoder.Telegram`。
   - 本地重签名后的客户端没有苹果官方私钥，一去读那个目录就被 macOS 系统安全守卫（TCC）当成「跨软件偷读数据」拦截了；而 Telegram 代码里写死了强制解包 `FileManager.default.containerURL(...)!`，拿不到目录就当场自杀闪退（`brk 1`）。
   - **解法**：我们在 Rust 动态库加载的第一时间，钩住 `NSFileManager` 的 `containerURLForSecurityApplicationGroupIdentifier:` 方法，把数据目录重定向到不受跨团队限制的 `~/Library/Application Support/TelegramPatcher/Container`，闪退和系统拦截弹窗当场解决。

4. **第四阶段：彻底拔掉伪装成聊天气泡的 `BTC.CC` 牛皮癣广告**
   - 进频道后发现广告还在，因为新版 Telegram 把广告做成了一条普通的图文消息气泡，不再走老的 `ChatSponsoredView`。
   - 我们用正则搜出 `_TtC12TelegramCore...AdMessagesHistoryContextImpl` 和 `AdMessages.swift`，再用 `objdump` 把 `0x100837b40 ~ 0x100838020` 这段机器码反汇编出来，当场抓到了它加载广告的 3 个命门：
     1. `0x100837bbc`：对比本地缓存广告是否未满 5 分钟（`300` 秒），未满就直接读取本地缓存的 `BTC.CC` 广告 -> **我们把它改成 `NOP`（空指令），废掉本地缓存广告**。
     2. `0x100837d1c`：读取广告数组条数 `count` 到寄存器 `x27` 准备生成聊天气泡 -> **我们把它改成 `mov x27, #0`，强制广告条数永远为 0，直接走空数组返回**。
     3. `0x100837f7c`：检查 `isActivated` 是否为 `0`，为 `0` 就发网络请求去拉新广告 -> **我们把它改成 `NOP`，让它直接走下面的 `ret` 退出，连网络请求都不发**。

5. 广告探针

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

```fish
begin
    echo "=== 1. AdMessagesHistoryContext 与 Impl 的完整成员变量 ==="
    otool -ov /Applications/Telegram.app/Contents/MacOS/Telegram | rg -A 65 "_TtC12TelegramCore.*AdMessagesHistoryContext"

    echo -e "\n=== 2. 持有 allAdMessages 与 adAttribute 的所属类名及方法 ==="
    otool -ov /Applications/Telegram.app/Contents/MacOS/Telegram | rg -B 45 "pendingDynamicAdMessages" | rg "(name.*_Tt|baseMethods|imp )"
    otool -ov /Applications/Telegram.app/Contents/MacOS/Telegram | rg -B 60 "name.*adAttribute" | rg "(name.*_Tt|baseMethods|imp )"

    echo -e "\n=== 3. 扫描 AdMessages.swift 与 ChannelAds.swift 的函数引用 ==="
    otool -tV /Applications/Telegram.app/Contents/MacOS/Telegram | rg -B 25 -A 10 "AdMessages\.swift|ChannelAds\.swift|Cons_sponsoredMessages" | head -n 120
end
```

```fish
begin
    echo "=== 1. AdMessages.swift 初始化与激活函数头 (0x100837b40 - 0x100838020) ==="
    /usr/bin/objdump -d --start-address=0x100837b40 --stop-address=0x100838020 /Applications/Telegram.app/Contents/MacOS/Telegram

    echo -e "\n=== 2. ApplyMaxReadIndexInteractively.swift 已读回执总入口 (0x10083e590 - 0x10083e640) ==="
    /usr/bin/objdump -d --start-address=0x10083e590 --stop-address=0x10083e640 /Applications/Telegram.app/Contents/MacOS/Telegram
end
```

2. 字符串特征

```fish
begin
    echo "=== 1. 版本与更新渠道 ==="
    /usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" -c "Print :CFBundleVersion" -c "Print :SUFeedURL" /Applications/Telegram.app/Contents/Info.plist 2>/dev/null

    echo -e "\n=== 2. 签名权限表 (Entitlements) ==="
    codesign -d --entitlements :- /Applications/Telegram.app 2>/dev/null

    echo -e "\n=== 3. 包内组件与插件结构 ==="
    ls -la /Applications/Telegram.app/Contents/Frameworks /Applications/Telegram.app/Contents/PlugIns /Applications/Telegram.app/Contents/XPCServices /Applications/Telegram.app/Contents/Helpers 2>/dev/null

    echo -e "\n=== 4. 撤回 / 已读 / 正在输入 / 在线状态 协议特征 ==="
    strings -n 8 /Applications/Telegram.app/Contents/MacOS/Telegram | rg -i "^(Cons_updateDelete|Cons_updateRead|Cons_messages\.read|Cons_messages\.setTyping|Cons_account\.updateStatus|Cons_stories\.read)" | sort -u

    echo -e "\n=== 5. 核心源码路径锚点 ==="
    strings -n 8 /Applications/Telegram.app/Contents/MacOS/Telegram | rg "\.swift\$" | rg -i "(Read|CopyProtection|Delete|Sponsored|Premium|Screenshot|Secret|Account|Typing)" | sort -u

    echo -e "\n=== 6. 防截屏与窗口共享 API 引用 ==="
    nm -u /Applications/Telegram.app/Contents/MacOS/Telegram 2>/dev/null | rg -i "(sharingType|AppCenter|Sparkle|SQLite)"
    otool -ov /Applications/Telegram.app/Contents/MacOS/Telegram | rg -i "name.*(sharingType|isPremium|copyProtection|sponsored|deleteMessages)" | sort -u
end
```
