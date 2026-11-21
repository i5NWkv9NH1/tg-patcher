// * 签名模块：支持本地固定证书与 Ad-hoc 重签名，覆盖 Frameworks / XPCServices / PlugIns
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};
use walkdir::WalkDir;

// * 剔除带官方 TeamID 的 application-groups，防止 macOS TCC 跨团队拦截与闪退
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

pub fn extract_or_default_entitlements(_app_path: &Path) -> String {
    debug!("使用已剥离跨团队 Group Container 校验的干净权限表");
    DEFAULT_TELEGRAM_ENTITLEMENTS.to_string()
}

fn sign_single_item(
    path: &Path,
    identity: &str,
    identifier: Option<&str>,
    entitlements_file: Option<&Path>,
) -> bool {
    let mut cmd = Command::new("/usr/bin/codesign");
    cmd.arg("--force").arg("-s").arg(identity);
    if let Some(id) = identifier {
        cmd.arg("--identifier").arg(id);
    }
    if let Some(ent) = entitlements_file {
        cmd.arg("--entitlements").arg(ent);
    }
    cmd.arg(path);
    match cmd.output() {
        Ok(out) if out.status.success() => true,
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            warn!("codesign 失败 ({}): {}", path.display(), err);
            false
        }
        Err(e) => {
            warn!("调用 codesign 失败 ({}): {e}", path.display());
            false
        }
    }
}

fn resign_subdir(dir: &Path, identity: &str, extensions: &[&str]) {
    if !dir.exists() {
        return;
    }
    for entry in WalkDir::new(dir)
        .min_depth(1)
        .contents_first(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let p = entry.path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        if extensions.iter().any(|ext| name.ends_with(ext)) {
            sign_single_item(p, identity, None, None);
        }
    }
}

// * 由内向外重签名整个 Telegram.app（包含 XPCServices）
pub fn resign_telegram_bundle(
    app_path: &Path,
    entitlements_xml: &str,
    sign_identity: &str,
) -> Result<(), std::io::Error> {
    let _ = Command::new("/usr/bin/xattr")
        .arg("-cr")
        .arg(app_path)
        .output();

    resign_subdir(
        &app_path.join("Contents/Frameworks"),
        sign_identity,
        &[".dylib", ".framework", ".xpc", ".app"],
    );
    resign_subdir(
        &app_path.join("Contents/XPCServices"),
        sign_identity,
        &[".dylib", ".framework", ".xpc", ".app"],
    );
    resign_subdir(
        &app_path.join("Contents/PlugIns"),
        sign_identity,
        &[".dylib", ".framework", ".appex"],
    );

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_ent = std::env::temp_dir().join(format!(
        "tg_patcher_ent_{}_{}.plist",
        std::process::id(),
        ts
    ));
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_ent)?;
        f.write_all(entitlements_xml.as_bytes())?;
    }

    let ok = sign_single_item(
        app_path,
        sign_identity,
        Some("ru.keepcoder.Telegram"),
        Some(&tmp_ent),
    );
    let _ = fs::remove_file(&tmp_ent);

    if ok {
        info!(
            "已完成重签名 (签名身份: {}, Identifier: ru.keepcoder.Telegram)",
            sign_identity
        );
    } else {
        warn!("主程序重签名失败，请检查管理员权限或本地签名证书名称是否正确");
    }
    Ok(())
}
