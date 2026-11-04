// * 核心补丁流水线切片：串联进程清理、语言包精简、arm64 精简、动态库注入与保活重签名

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tracing::{debug, info, warn};

use crate::features::clean::{
    calculate_dir_size, format_size, prune_locales, remove_bloatware, thin_arm64_binaries,
};
use crate::features::macho::{InjectResult, inject_file};
use crate::features::sign::{extract_or_default_entitlements, resign_telegram_bundle};

// * 编译期内嵌的纯 Rust 补丁动态库 (由 build.rs 编译生成)
pub const PATCH_DYLIB_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/libtg_patch.dylib"));

// * 补丁执行选项结构体
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchOptions {
    // * 1. 注入增强补丁动态库 (顶部「⚡ 增强设置」热切换菜单 / 破防截屏 / 去广告 / 解除禁止选中)
    pub core_patch: bool,
    // * 2. 删除无用组件 (TelegramShare.appex 分享插件 / Sparkle 自动更新器)
    pub remove_bloatware: bool,
    // * 3. 删除多余语言包 (.lproj)
    pub prune_locales: bool,
    // * 4. 提取纯 arm64 架构 (lipo 移除主程序与 28 个 Swift 动态库中的 x86_64 代码)
    pub thin_arm64: bool,
}

impl Default for PatchOptions {
    fn default() -> Self {
        Self {
            core_patch: true,
            remove_bloatware: true,
            prune_locales: true,
            thin_arm64: true,
        }
    }
}
// * 处理结果统计报表
#[derive(Debug, Default)]
pub struct PatchReport {
    pub initial_size: u64,
    pub final_size: u64,
    pub inject_status: Option<InjectResult>,
    pub removed_components: Vec<String>,
    pub pruned_locales_count: usize,
    pub thinned_count: usize,
}

// * 执行完整的 Telegram 客户端处理流水线
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

    // * 1. 提前提取原版 Entitlements 权限表，确保后续重签名不丢失 Group Container 登录态
    let entitlements_xml = extract_or_default_entitlements(&app_path);

    // * 2. 终止正在运行的 Telegram 进程，避免内核签名缓存冲突 (SIGKILL)
    debug!("检查并终止运行中的 Telegram 进程");
    if let Ok(out) = Command::new("/usr/bin/killall")
        .arg("-9")
        .arg("Telegram")
        .output()
        && out.status.success()
    {
        info!("已终止正在运行的「Telegram」进程");
        std::thread::sleep(std::time::Duration::from_millis(250));
    }

    // * 2.5 移除无用组件 (TelegramShare.appex 与 Autoupdate.app)
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

    // * 3. 精简多国语言包
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

    // * 4. 提取纯 arm64 架构 (在注入前完成二进制精简)
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

    // * 5. 写入 libtg_patch.dylib 并向主二进制尾部注入 LC_LOAD_DYLIB
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
                    InjectResult::Injected => {
                        info!("已追加 @rpath/libtg_patch.dylib 至加载表末尾")
                    }
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

    // * 6. 由内向外执行保活登录态的 Ad-hoc 重签名
    if let Err(e) = resign_telegram_bundle(&app_path, &entitlements_xml) {
        warn!("重签名过程中发生异常: {e}");
    }

    report.final_size = calculate_dir_size(&app_path);
    info!(
        "处理完成: 「Telegram.app」 (精简后体积: {})",
        format_size(report.final_size)
    );

    Ok(report)
}
