// * tg-patcher 单元测试集合

use clap::Parser;
use tempfile::tempdir;
use tg_patcher::CliArgs;
use tg_patcher::features::clean::{format_size, prune_locales};
use tg_patcher::features::macho::{
    CPU_TYPE_ARM64, InjectResult, MH_MAGIC_64, MachoError, inject_slice, scan_arm64_string_xrefs,
};
use tg_patcher::features::patch::PATCH_DYLIB_BYTES;

fn create_mock_macho_64() -> Vec<u8> {
    let mut buf = vec![0u8; 4096];
    buf[0..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
    buf[4..8].copy_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
    buf[8..12].copy_from_slice(&0x02u32.to_le_bytes());
    buf[12..16].copy_from_slice(&0x02u32.to_le_bytes());
    buf
}

#[test]
fn test_inject_and_idempotency() {
    let mut macho = create_mock_macho_64();
    let target = "@rpath/libtg_patch.dylib";

    let res1 = inject_slice(&mut macho, 0, target).expect("首次注入应成功");
    assert_eq!(res1, InjectResult::Injected);

    let res2 = inject_slice(&mut macho, 0, target).expect("重复注入应幂等跳过");
    assert_eq!(res2, InjectResult::AlreadyPresent);
}

#[test]
fn test_header_padding_security_guard() {
    let mut macho = create_mock_macho_64();
    macho[40] = 0xFF;
    let res = inject_slice(&mut macho, 0, "@rpath/libtg_patch.dylib");
    assert!(matches!(res, Err(MachoError::HeaderPaddingNotZero)));
}

#[test]
fn test_prune_locales_keeps_chinese_and_english() {
    let tmp = tempdir().unwrap();
    let res_dir = tmp.path().join("Contents/Resources");
    std::fs::create_dir_all(res_dir.join("fr.lproj")).unwrap();
    std::fs::create_dir_all(res_dir.join("ru.lproj")).unwrap();
    std::fs::create_dir_all(res_dir.join("en.lproj")).unwrap();
    std::fs::create_dir_all(res_dir.join("zh-Hans.lproj")).unwrap();

    let pruned = prune_locales(tmp.path()).unwrap();
    assert_eq!(pruned.len(), 2);
    assert!(res_dir.join("en.lproj").exists());
    assert!(res_dir.join("zh-Hans.lproj").exists());
    assert!(!res_dir.join("fr.lproj").exists());
}

#[test]
fn test_embedded_dylib_valid_macho() {
    assert!(PATCH_DYLIB_BYTES.len() > 64);
    let magic = u32::from_le_bytes(PATCH_DYLIB_BYTES[0..4].try_into().unwrap());
    assert_eq!(magic, MH_MAGIC_64);
}

#[test]
fn test_cli_flags() {
    let args = CliArgs::parse_from(["tg-patcher", "-y", "--no-thin"]);
    let opts = args.to_patch_options();
    assert!(opts.core_patch);
    assert!(opts.prune_locales);
    assert!(!opts.thin_arm64);
    assert_eq!(format_size(1048576), "1.0 MB");
}

#[test]
fn test_xref_scanner_empty_macho() {
    let macho = create_mock_macho_64();
    let matches = scan_arm64_string_xrefs(&macho, &["CopyProtection.swift"]).unwrap();
    assert!(matches.is_empty());
}
