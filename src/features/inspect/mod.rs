// * 诊断模式切片：探测 Telegram.app 版本、组件体积、权限表与纯 Swift 函数 ARM64 交叉引用地址

use console::style;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use crate::features::clean::{calculate_dir_size, format_size};
use crate::features::macho::scan_arm64_string_xrefs;

pub fn run_inspect() {
    let app_path = PathBuf::from("/Applications/Telegram.app");
    if !app_path.exists() {
        eprintln!(
            "{}",
            style("未在系统中检测到 /Applications/Telegram.app")
                .red()
                .bold()
        );
        return;
    }

    println!(
        "{}",
        style("==========================================================").dim()
    );
    println!(
        "{}",
        style("Telegram macOS 客户端结构与 ARM64 交叉引用诊断报告")
            .cyan()
            .bold()
    );
    println!(
        "{}",
        style("----------------------------------------------------------").dim()
    );

    // * 1. 读取版本号与更新源
    let plist_path = app_path.join("Contents/Info.plist");
    let read_plist_key = |key: &str| -> String {
        Command::new("/usr/libexec/PlistBuddy")
            .arg("-c")
            .arg(format!("Print :{key}"))
            .arg(&plist_path)
            .output()
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "未知".to_string())
    };

    let version = read_plist_key("CFBundleShortVersionString");
    let build = read_plist_key("CFBundleVersion");
    let feed = read_plist_key("SUFeedURL");

    println!(
        "客户端版本: {} (Build {})",
        style(&version).green().bold(),
        build
    );
    println!("更新订阅源: {}", style(&feed).dim());
    println!(
        "当前总体积: {}",
        style(format_size(calculate_dir_size(&app_path))).yellow()
    );
    println!();

    // * 2. 扫描主要内部目录体积
    println!("{}", style("包内核心目录占用:").yellow().bold());
    let subdirs = [
        ("Contents/MacOS", app_path.join("Contents/MacOS")),
        ("Contents/Frameworks", app_path.join("Contents/Frameworks")),
        ("Contents/PlugIns", app_path.join("Contents/PlugIns")),
        ("Contents/Resources", app_path.join("Contents/Resources")),
    ];
    for (label, dir) in &subdirs {
        if dir.exists() {
            println!(
                "  - {:<24} {}",
                label,
                style(format_size(calculate_dir_size(dir))).dim()
            );
        }
    }
    println!();

    // * 3. 执行纯 Rust ARM64 ADRP+ADD 交叉引用扫描，定位被 Strip 的纯 Swift 核心函数入口
    println!(
        "{}",
        style("ARM64 特征字符串交叉引用 (XREF) 自动定位结果:")
            .yellow()
            .bold()
    );
    let main_bin = app_path.join("Contents/MacOS/Telegram");
    let needles = [
        "ApplyMaxReadIndexInteractively.swift",
        "SynchronizePeerReadState.swift",
        "TypingDraftStop.swift",
        "CopyProtection.swift",
        "Cons_updateDeleteMessages",
        "Cons_updateDeleteChannelMessages",
        "Cons_updateReadHistoryInbox",
    ];

    match fs::read(&main_bin) {
        Ok(bytes) => match scan_arm64_string_xrefs(&bytes, &needles) {
            Ok(matches) => {
                if matches.is_empty() {
                    println!("  (未扫描到直接 ADRP+ADD 交叉引用)");
                } else {
                    for m in matches {
                        let func_str = m
                            .func_start_va
                            .map(|v| format!("0x{v:x}"))
                            .unwrap_or_else(|| "未知".to_string());
                        println!("  • 锚点: {}", style(&m.needle).green().bold());
                        println!(
                            "    字符串 VA: 0x{:x} | 引用指令 PC: 0x{:x} | 所属函数入口: {}",
                            m.string_va,
                            m.xref_insn_va,
                            style(func_str).cyan()
                        );
                        println!(
                            "    函数头 4 条指令: {:08x} {:08x} {:08x} {:08x}",
                            m.prologue_insns[0],
                            m.prologue_insns[1],
                            m.prologue_insns[2],
                            m.prologue_insns[3]
                        );
                    }
                }
            }
            Err(e) => println!("  扫描异常: {e}"),
        },
        Err(e) => println!("  读取主二进制失败: {e}"),
    }

    println!(
        "{}",
        style("==========================================================").dim()
    );
}
