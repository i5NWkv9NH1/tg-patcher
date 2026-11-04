基于 **Rust** 构建的 macOS 原生 Telegram 增强与精简工具。

> [!NOTE]
> 由 Gemini 3.8 Flash 与 Gemini 4 Argon 辅助编写。

## 核心功能

- **菜单栏开关**：在顶部菜单栏提供控制面板，支持实时开启/关闭功能，并支持一键切换语言。
- **屏蔽频道广告**：从底层拦截并清除频道内伪装成普通消息的赞助广告。
- **解除截屏限制**：允许在私密聊天、频道以及阅后即焚消息中进行截屏和录屏。
- **解除复制限制**：允许在原本受限的群组和频道中选中并复制文字。
- **大幅精简体积**：移除 x86_64 架构代码、分享插件、自动更新组件及多余语言包，安装包体积缩减超过 60%（从 343 MB 减小到 135 MB）。

## 功能边界说明

- **开发中 (TODO)**：无痕浏览（看消息不留下已读标记、不显示正在输入状态）与防撤回功能。
- **无法通过补丁实现**：撤回消息时的 UI 标记、消息编辑历史记录，以及需要 Telegram 服务器验证的会员特权（如 4GB 大文件上传）。

---

## 快速使用

### 一键执行

```bash
# Interactive Mode / 交互模式 (默认全选)
curl -fsSL https://raw.githubusercontent.com/i5NWkv9NH1/tg-patcher/master/install.sh | bash

# Silent Mode / 一键静默执行
curl -fsSL https://raw.githubusercontent.com/i5NWkv9NH1/tg-patcher/master/install.sh | bash -s -- -y
```

### 源码编译运行

```bash
cargo build --release

# Run patcher (interactive) / 交互式打补丁
sudo ./target/release/tg-patcher

# Run patcher (auto) / 全自动打补丁
sudo ./target/release/tg-patcher -y

# Inspect binary & ARM64 XREFs / 诊断模式与 ARM64 交叉引用探测
./target/release/tg-patcher -i
```

---

## 客户端更新说明

当客户端更新覆盖后，只需重新执行一次 `sudo tg-patcher -y` 即可，内置的 ARM64 特征码扫描器会自动适配新版本偏移，且**不会丢失已有登录态与配置**。
