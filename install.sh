#!/usr/bin/env bash
# tg-patcher 一键在线下载与执行脚本
set -euo pipefail

TMP_BIN="/tmp/tg-patcher"
RELEASE_URL="https://github.com/i5NWkv9NH1/tg-patcher/releases/latest/download/tg-patcher"

cleanup() {
    rm -f "$TMP_BIN"
}
trap cleanup EXIT

OS="$(uname -s)"
ARCH="$(uname -m)"

if [ "$OS" != "Darwin" ]; then
    echo "错误: 本工具仅支持 macOS 系统 (当前系统: $OS)" >&2
    exit 1
fi

if [ "$ARCH" != "arm64" ]; then
    echo "错误: 本工具仅支持 Apple Silicon (arm64) 架构 (当前架构: $ARCH)" >&2
    exit 1
fi

echo "==> 正在下载 tg-patcher 预编译二进制..."
if command -v curl >/dev/null 2>&1; then
    curl -fSL "$RELEASE_URL" -o "$TMP_BIN"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$TMP_BIN" "$RELEASE_URL"
else
    echo "错误: 未找到 curl 或 wget 下载工具" >&2
    exit 1
fi

chmod +x "$TMP_BIN"

echo "==> 启动 Telegram 客户端处理程序 (若提示请输入当前用户开机密码)..."
if [ -t 0 ]; then
    sudo "$TMP_BIN" "$@"
else
    sudo "$TMP_BIN" "$@" < /dev/tty
fi
