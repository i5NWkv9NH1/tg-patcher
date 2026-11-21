// * 组件清理、架构裁减与数据目录无损迁移模块
use std::ffi::{CStr, CString};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, info, warn};
use walkdir::WalkDir;

use crate::features::macho::{CPU_TYPE_ARM64, FAT_CIGAM, FAT_MAGIC};

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

// * 获取真实用户主目录及 UID/GID（正确处理 sudo 提权场景）
fn resolve_real_user_home_and_ids() -> (PathBuf, Option<(u32, u32)>) {
    if let Ok(uid_str) = std::env::var("SUDO_UID")
        && let Ok(uid) = uid_str.parse::<u32>()
    {
        let gid = std::env::var("SUDO_GID")
            .ok()
            .and_then(|s| s.parse::<u32>().ok());
        unsafe {
            let pw = libc::getpwuid(uid);
            if !pw.is_null() && !(*pw).pw_dir.is_null() {
                let dir = CStr::from_ptr((*pw).pw_dir).to_string_lossy().into_owned();
                let real_gid = gid.unwrap_or((*pw).pw_gid);
                return (PathBuf::from(dir), Some((uid, real_gid)));
            }
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/Shared".to_string());
    (PathBuf::from(home), None)
}

fn chown_if_root(path: &Path, ids: Option<(u32, u32)>) {
    if unsafe { libc::geteuid() != 0 } {
        return;
    }
    let Some((uid, gid)) = ids else {
        return;
    };
    if let Ok(cpath) = CString::new(path.to_string_lossy().as_bytes()) {
        unsafe {
            let _ = libc::chown(cpath.as_ptr(), uid, gid);
        }
    }
}

// * 将旧版 ~/Library/Application Support/TelegramPatcher 原地原子迁移至 ru.keepcoder.Telegram
pub fn migrate_legacy_data_dir() -> Result<bool, std::io::Error> {
    let (home, ids) = resolve_real_user_home_and_ids();
    let app_support = home.join("Library/Application Support");
    let old_root = app_support.join("TelegramPatcher");
    if !old_root.exists() {
        return Ok(false);
    }

    let new_root = app_support.join("ru.keepcoder.Telegram");
    if !new_root.exists() {
        fs::create_dir_all(&new_root)?;
        chown_if_root(&new_root, ids);
    }

    let mut moved_any = false;
    let old_container = old_root.join("Container");
    if old_container.exists() {
        for entry in fs::read_dir(&old_container)? {
            let entry = entry?;
            let src = entry.path();
            let dst = new_root.join(entry.file_name());
            if !dst.exists() {
                fs::rename(&src, &dst)?;
                moved_any = true;
            }
        }
        let _ = fs::remove_dir(&old_container);
    }

    let old_conf = old_root.join("config.conf");
    let new_conf = new_root.join("patcher.conf");
    if old_conf.exists() && !new_conf.exists() {
        fs::rename(&old_conf, &new_conf)?;
        chown_if_root(&new_conf, ids);
        moved_any = true;
    }

    let _ = fs::remove_dir(&old_root);
    if moved_any {
        info!(
            "已完成缓存与配置原地迁移: TelegramPatcher -> {}",
            new_root.display()
        );
    }
    Ok(moved_any)
}

// * 仅清理 stable/logs 运行日志，绝不触碰 postbox/media 媒体缓存
pub fn clean_telegram_logs() -> Result<u64, std::io::Error> {
    let (home, _) = resolve_real_user_home_and_ids();
    let logs_dir = home.join("Library/Application Support/ru.keepcoder.Telegram/stable/logs");
    if !logs_dir.exists() {
        return Ok(0);
    }
    let mut freed = 0u64;
    for entry in fs::read_dir(&logs_dir)? {
        let entry = entry?;
        let p = entry.path();
        if let Ok(meta) = entry.metadata()
            && meta.is_file()
        {
            freed += meta.len();
            let _ = fs::remove_file(&p);
        }
    }
    Ok(freed)
}

// * 移除无用组件 (TelegramShare.appex 分享扩展与 Sparkle 自动更新器)
pub fn remove_bloatware(app_path: &Path) -> Result<Vec<String>, std::io::Error> {
    let mut removed = Vec::new();
    let targets = [
        app_path.join("Contents/PlugIns/TelegramShare.appex"),
        app_path.join("Contents/Frameworks/Sparkle.framework/Versions/A/Resources/Autoupdate.app"),
        app_path.join("Contents/Frameworks/Sparkle.framework/Versions/A/Updater.app"),
    ];
    for target in &targets {
        if target.exists() {
            if target.is_dir() {
                fs::remove_dir_all(target)?;
            } else {
                fs::remove_file(target)?;
            }
            let name = target
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            removed.push(name);
        }
    }
    Ok(removed)
}

// * 清理多余 .lproj 语言包（仅保留中文与英文）
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

// * 提取纯 arm64 架构（只读 FAT 头，输出至临时文件再原子替换，避免损坏原二进制）
pub fn thin_arm64_binaries(app_path: &Path) -> Result<usize, std::io::Error> {
    if std::env::consts::ARCH != "aarch64" {
        warn!("当前系统非 arm64 架构，跳过 lipo 架构剥离");
        return Ok(0);
    }
    let mut count = 0;
    debug!("开始扫描 Telegram.app 包内所有通用二进制文件");
    for entry in WalkDir::new(app_path).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
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
        let magic = u32::from_ne_bytes([header[0], header[1], header[2], header[3]]);
        if magic != FAT_MAGIC && magic != FAT_CIGAM {
            continue;
        }
        let nfat_arch = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
        if nfat_arch == 0 || nfat_arch > 8 {
            continue;
        }
        let mut arch_buf = vec![0u8; nfat_arch * 20];
        if file.read_exact(&mut arch_buf).is_err() {
            continue;
        }
        drop(file);

        let mut has_arm64 = false;
        for i in 0..nfat_arch {
            let off = i * 20;
            let cputype = u32::from_be_bytes([
                arch_buf[off],
                arch_buf[off + 1],
                arch_buf[off + 2],
                arch_buf[off + 3],
            ]);
            if cputype == CPU_TYPE_ARM64 {
                has_arm64 = true;
                break;
            }
        }
        if !has_arm64 {
            continue;
        }

        let orig_perm = fs::metadata(path).ok().map(|m| m.permissions());
        let tmp_path = path.with_extension("arm64.tmp");
        let _ = fs::remove_file(&tmp_path);

        let output = Command::new("/usr/bin/lipo")
            .arg("-thin")
            .arg("arm64")
            .arg(path)
            .arg("-output")
            .arg(&tmp_path)
            .output();

        match output {
            Ok(out) if out.status.success() => {
                if let Some(perm) = orig_perm {
                    let _ = fs::set_permissions(&tmp_path, perm);
                }
                if fs::rename(&tmp_path, path).is_ok() {
                    count += 1;
                    debug!("转换为纯 arm64: {}", path.display());
                } else {
                    let _ = fs::remove_file(&tmp_path);
                    warn!("替换纯 arm64 文件失败: {}", path.display());
                }
            }
            _ => {
                let _ = fs::remove_file(&tmp_path);
                warn!("lipo 转换失败: {}", path.display());
            }
        }
    }
    Ok(count)
}
