基于 **Rust** 构建的 macOS 原生 Telegram（Telegram-Mac）增强与精简工具。

> [!NOTE]
> 由 Gemini 辅助编写及代码审计重构。

## 核心功能

- **菜单栏开关**：在顶部菜单栏提供「增强设置 / Patcher」控制面板，支持实时开关各项功能及中英文切换。
- **屏蔽频道广告**：启动期从 ARM64 机器码层拦截并清除频道内伪装成普通消息气泡的赞助广告（通过特征码自动适配新版本）。
- **解除截屏限制**：允许在私密聊天、频道以及阅后即焚消息中进行截屏和录屏。
- **解除复制限制**：解除受限群组和频道的文字选中限制。
- **拦截自动更新**：支持在菜单栏实时开关 Sparkle 自动更新检查，避免官方更新直接覆盖补丁。
- **大幅精简体积**：移除 x86_64 架构代码、分享插件、自动更新器及多余语言包，并补全 `XPCServices` 重签名，安装包体积缩减超过 60%（从 343 MB 减小到 135~156 MB）。
- **保护本地缓存**：打补丁前先发送正常退出信号让 SQLite WAL 落盘，再执行替换；数据目录重定向至 `~/Library/Application Support/ru.keepcoder.Telegram`，旧版 `TelegramPatcher` 目录会自动原地无损迁移。

## 功能边界说明

- **不通过二进制补丁实现**：无痕浏览（不发已读回执 / 不发正在输入）、防撤回与撤回 UI 标记、受限频道底层禁止保存媒体。上述逻辑在原生端属于纯 Swift 异步 `Signal` 构造或编译器高度内联的权限判断，二进制注入维护成本极高且易闪退，如需深度定制建议直接基于开源仓库编译。
- **服务端强校验限制**：消息编辑历史记录、4GB 大文件上传等依赖 Telegram 服务端校验的会员特权无法通过本地补丁绕过。

---

## 快速使用

### 一键执行

````fish
# 交互模式 (默认全选)
curl -fsSL [https://raw.githubusercontent.com/i5NWkv9NH1/tg-patcher/master/install.sh](https://raw.githubusercontent.com/i5NWkv9NH1/tg-patcher/master/install.sh) | bash

# 全自动静默执行
curl -fsSL [https://raw.githubusercontent.com/i5NWkv9NH1/tg-patcher/master/install.sh](https://raw.githubusercontent.com/i5NWkv9NH1/tg-patcher/master/install.sh) | bash -s -- -y
```

### 源码编译运行

```bash
cargo build --release

# 交互式打补丁
sudo ./target/release/tg-patcher

# 全自动打补丁，并顺手清理运行日志（绝不动媒体缓存）
sudo ./target/release/tg-patcher -y --clean-logs

# 使用本地钥匙串自建代码签名证书重签（避免更新后系统通知/麦克风权限重置）
sudo ./target/release/tg-patcher -y --sign-identity "你的证书名称"

# 诊断模式：检查去广告特征码命中状态与 ARM64 交叉引用地址
./target/release/tg-patcher -i
````

---

## 数据目录与清理工具防护

本地重签后的客户端因不含官方开发团队私钥，无法读写 ~/Library/Group Containers/6N38VWS5BX.ru.keepcoder.Telegram，补丁会自动将数据与媒体缓存重定向至：

```fish
~/Library/Application Support/ru.keepcoder.Telegram
```

若使用 Mole 等磁盘清理工具，建议将其加入白名单，防止误删已缓存的频道图片与视频：

```fish
mkdir -p ~/.config/mole
printf "\n%s\n%s\n" \
  "$HOME/Library/Application Support/ru.keepcoder.Telegram" \
  "$HOME/Library/Caches/ru.keepcoder.Telegram" >> ~/.config/mole/whitelist
```

---

## 客户端更新说明

当官方客户端更新覆盖后，只需重新执行一次 `sudo tg-patcher -y` 即可，内置的 ARM64 特征码扫描器会自动适配新版本，且不会丢失已有登录态、配置与媒体缓存。更新后可运行 tg-patcher -i 确认 3 处去广告特征码是否全部显示 [命中]。
