// * 核心补丁流水线：平稳退出、缓存目录无损迁移、精简组件、架构裁减、注入与重签名
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::features::clean::{
    calculate_dir_size, clean_telegram_logs, format_size, migrate_legacy_data_dir, prune_locales,
    remove_bloatware, thin_arm64_binaries,
};
use crate::features::macho::{InjectResult, inject_file};
use crate::features::sign::{extract_or_default_entitlements, resign_telegram_bundle};

pub const PATCH_DYLIB_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/libtg_patch.dylib"));

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchOptions {
    pub core_patch: bool,
    pub remove_bloatware: bool,
    pub prune_locales: bool,
    pub thin_arm64: bool,
    pub clean_logs: bool,
    pub sign_identity: String,
}

impl Default for PatchOptions {
    fn default() -> Self {
        Self {
            core_patch: true,
            remove_bloatware: true,
            prune_locales: true,
            thin_arm64: true,
            clean_logs: false,
            sign_identity: "-".to_string(),
        }
    }
}

#[derive(Debug, Default)]
pub struct PatchReport {
    pub initial_size: u64,
    pub final_size: u64,
    pub inject_status: Option<InjectResult>,
    pub removed_components: Vec<String>,
    pub pruned_locales_count: usize,
    pub thinned_count: usize,
    pub migrated_data_dir: bool,
    pub cleaned_logs_bytes: u64,
}

fn is_telegram_running() -> bool {
    Command::new("/usr/bin/pgrep")
        .arg("-x")
        .arg("Telegram")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// * 优先发 SIGTERM 平稳退出让 SQLite WAL 落盘，超时 4 秒后再强杀
fn stop_telegram_gracefully() {
    if !is_telegram_running() {
        return;
    }
    debug!("检测到运行中的 Telegram，正在发送平稳退出信号 (SIGTERM)...");
    let _ = Command::new("/usr/bin/pkill")
        .arg("-TERM")
        .arg("-x")
        .arg("Telegram")
        .output();

    for _ in 0..25 {
        if !is_telegram_running() {
            std::thread::sleep(Duration::from_millis(150));
            info!("已平稳退出「Telegram」进程（数据库已安全落盘）");
            return;
        }
        std::thread::sleep(Duration::from_millis(160));
    }

    warn!("「Telegram」4 秒内未响应正常退出，执行强制终止");
    let _ = Command::new("/usr/bin/pkill")
        .arg("-KILL")
        .arg("-x")
        .arg("Telegram")
        .output();
    std::thread::sleep(Duration::from_millis(250));
}

pub fn run_pipeline(options: &PatchOptions) -> Result<PatchReport, String> {
    let app_path = PathBuf::from("/Applications/Telegram.app");
    if !app_path.exists() {
        return Err("未在系统中检测到 /Applications/Telegram.app".to_string());
    }
    let mut report = PatchReport {
        initial_size: calculate_dir_size(&app_path),
        ..Default::default()
    };
    info!(
        "开始处理客户端: 「Telegram.app」 (当前体积: {})",
        format_size(report.initial_size)
    );

    let entitlements_xml = extract_or_default_entitlements(&app_path);

    // * 1. 先平稳关闭 Telegram，确保 SQLite 数据库落盘后再做目录迁移与二进制替换
    stop_telegram_gracefully();

    // * 2. 自动把旧 TelegramPatcher 数据目录无损迁移至 ru.keepcoder.Telegram
    match migrate_legacy_data_dir() {
        Ok(migrated) => report.migrated_data_dir = migrated,
        Err(e) => warn!("迁移旧数据目录时遇到异常: {e}"),
    }

    // * 2.1 按需清理运行日志（绝不碰 postbox/media 媒体缓存）
    if options.clean_logs {
        match clean_telegram_logs() {
            Ok(bytes) => {
                if bytes > 0 {
                    info!("已清理运行日志: {}", format_size(bytes));
                }
                report.cleaned_logs_bytes = bytes;
            }
            Err(e) => warn!("清理日志时遇到异常: {e}"),
        }
    }

    // * 3. 移除无用组件
    if options.remove_bloatware {
        match remove_bloatware(&app_path) {
            Ok(removed) => {
                if !removed.is_empty() {
                    info!(
                        "已删除无用组件: {} 项 ({})",
                        removed.len(),
                        removed.join(", ")
                    );
                }
                report.removed_components = removed;
            }
            Err(e) => warn!("移除无用组件时遇到异常: {e}"),
        }
    }

    // * 4. 清理多余语言包
    if options.prune_locales {
        match prune_locales(&app_path) {
            Ok(pruned) => {
                if !pruned.is_empty() {
                    info!("已清理多余语言包: {} 个", pruned.len());
                }
                report.pruned_locales_count = pruned.len();
            }
            Err(e) => warn!("清理语言包时遇到异常: {e}"),
        }
    }

    // * 5. 提取纯 arm64 架构
    if options.thin_arm64 {
        match thin_arm64_binaries(&app_path) {
            Ok(count) => {
                if count > 0 {
                    info!("已完成纯 arm64 架构转换: {count} 个通用二进制");
                }
                report.thinned_count = count;
            }
            Err(e) => warn!("提取 arm64 架构时遇到异常: {e}"),
        }
    }

    // * 6. 部署 libtg_patch.dylib 并向主二进制尾部注入 LC_LOAD_DYLIB
    if options.core_patch {
        let fw_dir = app_path.join("Contents/Frameworks");
        let target_dylib = fw_dir.join("libtg_patch.dylib");
        let _ = fs::remove_file(&target_dylib);
        if let Err(e) = fs::write(&target_dylib, PATCH_DYLIB_BYTES) {
            return Err(format!(
                "部署动态库到 Frameworks 失败: {e} (请确认是否使用 sudo 运行)"
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&target_dylib, fs::Permissions::from_mode(0o755));
        }
        let main_bin = app_path.join("Contents/MacOS/Telegram");
        match inject_file(&main_bin, "@rpath/libtg_patch.dylib") {
            Ok(res) => {
                report.inject_status = Some(res);
                match res {
                    InjectResult::Injected => info!("已追加 @rpath/libtg_patch.dylib 至加载表末尾"),
                    InjectResult::AlreadyPresent => {
                        info!("已更新补丁动态库 libtg_patch.dylib (加载表已就绪)")
                    }
                    InjectResult::FixedAndInjected => {
                        info!("已修复错位加载项并重写至加载表末尾")
                    }
                }
            }
            Err(e) => return Err(format!("Mach-O 注入失败: {e}")),
        }
    }

    // * 7. 由内向外重签名（含 XPCServices）
    if let Err(e) = resign_telegram_bundle(&app_path, &entitlements_xml, &options.sign_identity) {
        warn!("重签名过程中发生异常: {e}");
    }

    report.final_size = calculate_dir_size(&app_path);
    info!(
        "处理完成: 「Telegram.app」 (当前体积: {})",
        format_size(report.final_size)
    );
    Ok(report)
}
