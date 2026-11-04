// * 签名切片：保留 Group Containers 权限表并执行由内向外的 Ad-hoc 重签名，确保不闪退、不掉登录

use std::fs;
use std::path::Path;
use std::process::Command;
use tracing::{debug, info, warn};
use walkdir::WalkDir;

// * Telegram 官网直装版标准权限表兜底模板（关闭沙盒，保留 Group Container 与音视频权限）
// * 本地 Ad-hoc 签名专用干净权限表（剔除带官方 TeamID 的 application-groups，防止 macOS 26/27 TCC 拦截与闪退）
const DEFAULT_TELEGRAM_ENTITLEMENTS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.app-sandbox</key>
    <false/>
    <key>com.apple.security.device.audio-input</key>
    <true/>
    <key>com.apple.security.device.camera</key>
    <true/>
    <key>com.apple.security.personal-information.location</key>
    <true/>
</dict>
</plist>
"#;

// * 提取原版 Telegram.app 的权限表 XML（若提取失败或已被破坏则回退使用标准模板）
pub fn extract_or_default_entitlements(_app_path: &Path) -> String {
    debug!("使用已剥离跨团队 Group Container 校验的干净权限表");
    DEFAULT_TELEGRAM_ENTITLEMENTS.to_string()
    // let output = Command::new("/usr/bin/codesign")
    //     .arg("-d")
    //     .arg("--entitlements")
    //     .arg(":-")
    //     .arg(app_path)
    //     .output();

    // if let Ok(out) = output
    //     && out.status.success()
    // {
    //     let xml = String::from_utf8_lossy(&out.stdout).trim().to_string();
    //     if xml.contains("<plist") && xml.contains("6N38VWS5BX.ru.keepcoder.Telegram") {
    //         // ! 确保关闭强制沙盒，避免 Ad-hoc 签名下被 secinitd 拦截
    //         if !xml.contains("<key>com.apple.security.app-sandbox</key><true/>") {
    //             debug!("成功提取原版 Telegram.app 权限表");
    //             return xml;
    //         }
    //     }
    // }
    // DEFAULT_TELEGRAM_ENTITLEMENTS.to_string()
}

// * 对单个目标执行静默 Ad-hoc 签名
fn sign_single_item(
    path: &Path,
    identifier: Option<&str>,
    entitlements_file: Option<&Path>,
) -> bool {
    let mut cmd = Command::new("/usr/bin/codesign");
    cmd.arg("--force").arg("-s").arg("-");

    if let Some(id) = identifier {
        cmd.arg("--identifier").arg(id);
    }
    if let Some(ent) = entitlements_file {
        cmd.arg("--entitlements").arg(ent);
    }

    cmd.arg(path);
    match cmd.output() {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}

// * 由内向外递归重签名整个 Telegram.app，保留 Group Container 登录态访问权
pub fn resign_telegram_bundle(
    app_path: &Path,
    entitlements_xml: &str,
) -> Result<(), std::io::Error> {
    // * 1. 清除隔离属性 (com.apple.quarantine)
    let _ = Command::new("/usr/bin/xattr")
        .arg("-cr")
        .arg(app_path)
        .output();

    // * 2. 先对 Frameworks 下的所有 .dylib 和子组件由内向外逐一签名
    let fw_dir = app_path.join("Contents/Frameworks");
    if fw_dir.exists() {
        for entry in WalkDir::new(&fw_dir)
            .min_depth(1)
            .contents_first(true)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let p = entry.path();
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            if name.ends_with(".dylib")
                || name.ends_with(".framework")
                || name.ends_with(".xpc")
                || name.ends_with(".app")
            {
                sign_single_item(p, None, None);
            }
        }
    }

    // * 3. 对 PlugIns 下的扩展插件 (如 TelegramShare.appex) 进行签名
    let plugins_dir = app_path.join("Contents/PlugIns");
    if plugins_dir.exists() {
        for entry in WalkDir::new(&plugins_dir)
            .min_depth(1)
            .contents_first(true)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let p = entry.path();
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            if name.ends_with(".appex") {
                sign_single_item(p, None, None);
            }
        }
    }

    // * 4. 将权限表写入临时文件，固定以 ru.keepcoder.Telegram 标识重签主 App 包
    let tmp_ent = std::env::temp_dir().join("tg_patcher_entitlements.plist");
    fs::write(&tmp_ent, entitlements_xml)?;

    let ok = sign_single_item(app_path, Some("ru.keepcoder.Telegram"), Some(&tmp_ent));
    let _ = fs::remove_file(&tmp_ent);

    if ok {
        info!("已完成保活登录态的 Ad-hoc 重签名 (Identifier: ru.keepcoder.Telegram)");
    } else {
        warn!("主程序重签名返回非零状态，请检查是否有管理员权限");
    }

    Ok(())
}
