# tg-patcher: macOS 原生 Telegram 客户端增强与精简工具

针对 [`TelegramMessenger/telegram-macos`](https://github.com/TelegramMessenger/telegram-macos)（Swift + Cocoa/TGUIKit 原生版，非 Qt 跨平台版）构建的纯 Rust 注入与瘦身工具。

通过向主二进制尾部注入 `libtg_patch.dylib`，在系统顶部菜单栏直接挂载 **「⚡ 增强设置」** 下拉菜单，支持**运行时毫秒级实时热切换**，无需重启客户端或重复执行补丁。

---

### 一、 功能边界清单（已实现 / TODO / 无法实现）

#### 1. 已实现功能（v0.1.0 开箱即用）

- **顶部菜单栏「⚡ 增强设置」实时热切换**：启动 Telegram 后，屏幕最顶部菜单栏（紧挨「帮助」右侧）直接显示「⚡ 增强设置」，点击即可实时勾选开启或关闭以下功能，配置自动持久化保存至 `~/Library/Application Support/TelegramPatcher/config.conf`。
- **破除禁止截屏与录屏黑框**：拦截 `NSWindow.setSharingType:` 与 `NSView.setAccessibilityProtectedContent:`，强制将受保护窗口与阅后即焚图层的截图权限改为允许读写，截图与录屏不再变黑框。
- **屏蔽频道底部官方赞助广告**：动态扫描匹配 `_TtC6ChatUI*ChatSponsoredView`（无视随版本变动的 Swift 私有文件哈希），在视图布局阶段直接将其隐藏并将高度锁死为 `0`。
- **解除受限群组文字选中与右键复制限制**：在 `_TtC6ChatUI15ChatInteraction` 初始化阶段自动清零 `disableSelectAbility` 标志位。
- **拦截 Sparkle 自动更新检查**：屏蔽内置 `Sparkle.framework` 的后台更新检查与弹窗，防止客户端静默更新覆盖补丁。
- **纯 arm64 架构极限瘦身**：对主二进制 `Telegram`、内置的 28 个 `libswift*.dylib`、`Sparkle.framework` 与 `TelegramShare.appex` 统一执行 `lipo -thin arm64` 剥离 `x86_64` 代码，并清理多余语言包（预计缩减约 **45% ~ 50%** 磁盘体积）。
- **保活登录态的安全重签名**：自动提取并保留原版 `Entitlements.plist` 中的 `6N38VWS5BX.ru.keepcoder.Telegram` 共享容器权限，固定使用 `ru.keepcoder.Telegram` 签名标识由内向外重签，**打补丁或升级客户端后不闪退、不掉登录**。
- **内置 ARM64 机器码交叉引用探针 (`--inspect`)**：无需依赖 Hopper / IDA，直接用纯 Rust 解析 `LC_FUNCTION_STARTS` 与 `__TEXT,__text` 中的 `ADRP + ADD` 指令对，自动定位被剥离符号（Strip）的纯 Swift 核心函数入口地址。

#### 2. 待接入功能（TODO：已内置探针定位，后续版本挂载内存跳板）

以下功能位于 `TelegramCore` 纯 Swift 静态层（无导出符号），目前已通过 `tg-patcher -i` 完成 ARM64 字符串交叉引用定位，后续核对不同函数返回值的 Swift ABI 寄存器约定后即可接入菜单栏热开关：

- `[TODO]` **幽灵模式：看消息不发「已读」回执**（定位锚点：`ApplyMaxReadIndexInteractively.swift` / `SynchronizePeerReadState.swift`）。
- `[TODO]` **幽灵模式：隐藏「正在输入... / 正在录音...」状态**（定位锚点：`TypingDraftStop.swift`）。
- `[TODO]` **受限频道图片/视频直接「另存为」解锁**（定位锚点：`CopyProtection.swift` 底层 Peer 标志位）。
- `[TODO]` **暴力版防撤回（忽略消息删除指令）**（定位锚点：`Cons_updateDeleteMessages` / `Cons_updateDeleteChannelMessages`，拦截后被撤回的消息不会从聊天窗口消失，但界面上不会显示「已撤回」角标）。
- `[TODO]` **解除本地登录账号数量上限**（突破非会员最多同时登录 3 个账号的客户端限制）。

#### 3. 外部 Patch 完全做不到的功能（客观限制说明）

以下功能受限于 Telegram 服务端强校验或本地 `Postbox` 自定义加密数据库结构，**任何外部注入补丁均无法实现**（除非拉取全部 Swift 源码魔改重编译）：

- **AyuGram 式的「带已撤回标记」的完美防撤回**：`Postbox` 数据库的消息结构是定长/强类型 Swift 序列化格式，外部动态库无法向消息气泡 UI 凭空注入「已撤回」图标或修改数据库表结构，最多只能做到上面的「暴力拦截删除指令」。
- **查看消息的「编辑历史记录（Edit History）」**：收到 `updateEditMessage` 时本地数据库会直接覆写原消息记录，外部 Hook 无处存储也无原生界面展示历史版本。
- **服务端校验的 Telegram Premium 特权**：如 4GB 超大文件上传、发送专属付费表情、服务端下载队列加速等由 Telegram 数据中心（DC）在服务端鉴权的功能，本地修改无效。

---

### 二、 安装与运行方式

> **前置要求**：请确保安装的是 [Telegram 官网直装版 / GitHub Release 版](https://macos.telegram.org/)（而非 Mac App Store 沙盒版）。若尚未登录账号，建议先运行本工具打完补丁后再扫码登录。

```bash
# 交互模式运行 (默认全选)
curl -fsSL https://raw.githubusercontent.com/i5NWkv9NH1/tg-patcher/master/install.sh | bash

# 一键静默全自动处理
curl -fsSL https://raw.githubusercontent.com/i5NWkv9NH1/tg-patcher/master/install.sh | bash -s -- -y
```

### 二、 安装与运行方式

> **前置要求**：请确保安装的是 [Telegram 官网直装版 / GitHub Release 版](https://macos.telegram.org/)（而非 Mac App Store 沙盒版）。若尚未登录账号，建议先运行本工具打完补丁后再扫码登录。

#### 方式一：一条命令运行

```bash
# 交互模式运行 (默认全选)
curl -fsSL https://raw.githubusercontent.com/i5NWkv9NH1/tg-patcher/master/install.sh | bash

# 一键静默全自动处理
curl -fsSL https://raw.githubusercontent.com/i5NWkv9NH1/tg-patcher/master/install.sh | bash -s -- -y
```

#### 方式二：从源码编译运行

```bash
# 1. 编译发布版本
cargo build --release

# 2. 诊断模式：探测客户端结构与纯 Swift 核心函数的 ARM64 入口地址 (无需 sudo)
./target/release/tg-patcher -i

# 3. 交互模式执行补丁与瘦身 (默认全选)
sudo ./target/release/tg-patcher

# 4. 或一键静默执行全部优化
sudo ./target/release/tg-patcher -y
```

---

### 三、 常见问题与版本更新说明

1. **客户端更新后需要做什么？**
   - 当你手动下载新版 `Telegram.app` 覆盖安装后，只需重新运行一次 `sudo tg-patcher -y` 即可。
   - 因为重签名模块固定保留了 `ru.keepcoder.Telegram` 签名标识与 `6N38VWS5BX.ru.keepcoder.Telegram` 容器权限，重新打补丁后**不需要重新登录账号**。
2. **如何实时开关某项功能？**
   - 打开 Telegram 后，直接点击 macOS 屏幕顶部系统菜单栏最右侧的 **「⚡ 增强设置」**，勾选或取消对应项目即可立即生效。
