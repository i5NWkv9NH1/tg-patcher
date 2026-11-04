// * 组件精简与架构瘦身切片：剥离 x86_64 冗余架构并清理多余语言包

use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::Command;
use tracing::{debug, warn};
use walkdir::WalkDir;

use crate::features::macho::{CPU_TYPE_ARM64, FAT_CIGAM, FAT_MAGIC};

// * 计算指定目录或文件的总磁盘占用（字节数）
pub fn calculate_dir_size<P: AsRef<Path>>(path: P) -> u64 {
    let mut total_size = 0u64;
    for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
        if let Ok(meta) = entry.metadata()
            && meta.is_file()
        {
            total_size += meta.len();
        }
    }
    total_size
}

// * 将字节数转换为直观的人类可读格式 (KB/MB/GB)
pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

// * 1. 清理 Contents/Resources 与 Frameworks 内多余的 .lproj 语言包（仅保留英文与中文）
pub fn prune_locales(app_path: &Path) -> Result<Vec<String>, std::io::Error> {
    let mut pruned = Vec::new();
    let keep_list = [
        "Base.lproj",
        "en.lproj",
        "zh-Hans.lproj",
        "zh-Hant.lproj",
        "zh_CN.lproj",
        "zh_TW.lproj",
    ];

    for entry in WalkDir::new(app_path)
        .max_depth(6)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.ends_with(".lproj") && !keep_list.contains(&name) {
            if fs::remove_dir_all(path).is_ok() {
                pruned.push(name.to_string());
            }
        }
    }

    Ok(pruned)
}

// * 2. 提取纯 arm64 架构 (对主程序、28 个 libswift*.dylib、Sparkle 与 TelegramShare.appex 执行 lipo -thin arm64)
pub fn thin_arm64_binaries(app_path: &Path) -> Result<usize, std::io::Error> {
    if std::env::consts::ARCH != "aarch64" {
        warn!("当前系统非 arm64 架构，跳过 lipo 架构剥离");
        return Ok(0);
    }

    let mut count = 0;
    debug!("开始扫描 Telegram.app 包内所有通用二进制文件");

    for entry in WalkDir::new(app_path).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        // ! 跳过符号链接与非普通文件
        if !path.is_file() || entry.path_is_symlink() {
            continue;
        }

        let Ok(mut file) = fs::File::open(path) else {
            continue;
        };
        let mut header = [0u8; 8];
        if file.read_exact(&mut header).is_err() {
            continue;
        }
        drop(file);

        let magic = u32::from_ne_bytes([header[0], header[1], header[2], header[3]]);
        if magic != FAT_MAGIC && magic != FAT_CIGAM {
            continue;
        }

        let nfat_arch = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
        if nfat_arch == 0 || nfat_arch > 8 {
            continue;
        }

        let Ok(data) = fs::read(path) else {
            continue;
        };
        if data.len() < 8 + nfat_arch * 20 {
            continue;
        }

        let mut has_arm64 = false;
        for i in 0..nfat_arch {
            let off = 8 + i * 20;
            let cputype =
                u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
            if cputype == CPU_TYPE_ARM64 {
                has_arm64 = true;
                break;
            }
        }

        if !has_arm64 {
            continue;
        }

        let output = Command::new("/usr/bin/lipo")
            .arg("-thin")
            .arg("arm64")
            .arg(path)
            .arg("-output")
            .arg(path)
            .output();

        match output {
            Ok(out) if out.status.success() => {
                count += 1;
                debug!("转换为纯 arm64: {}", path.display());
            }
            _ => {
                warn!("lipo 转换失败: {}", path.display());
            }
        }
    }

    Ok(count)
}
