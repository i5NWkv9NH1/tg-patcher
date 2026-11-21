// * tg-patcher 核心库入口：CLI 参数定义、交互式多选菜单与汇总报表输出
pub mod features;

use clap::Parser;
use console::style;
use dialoguer::MultiSelect;
use features::clean::format_size;
use features::inspect::run_inspect;
use features::macho::InjectResult;
use features::patch::{PatchOptions, PatchReport, run_pipeline};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

#[derive(Parser, Debug)]
#[command(
    name = "tg-patcher",
    author = "sora",
    version,
    about = "macOS 原生 Telegram 客户端 (Telegram-Mac) 增强补丁、热切换菜单与架构精简工具"
)]
pub struct CliArgs {
    #[arg(
        short = 'y',
        long = "yes",
        help = "跳过交互菜单，使用默认配置全自动执行"
    )]
    pub yes: bool,

    #[arg(long = "no-core", help = "跳过注入 libtg_patch.dylib 增强补丁")]
    pub no_core: bool,

    #[arg(
        long = "no-bloat",
        help = "跳过删除 TelegramShare.appex 与 Autoupdate.app"
    )]
    pub no_bloat: bool,

    #[arg(long = "no-locales", help = "跳过删除多余的 .lproj 语言包")]
    pub no_locales: bool,

    #[arg(long = "no-thin", help = "跳过 lipo thin arm64 通用二进制剥离")]
    pub no_thin: bool,

    #[arg(
        long = "clean-logs",
        help = "顺手清理 stable/logs 运行日志（保留所有媒体缓存）"
    )]
    pub clean_logs: bool,

    #[arg(
        long = "sign-identity",
        default_value = "-",
        help = "重签名证书名称（默认 - 为临时签名；填入钥匙串自建代码签名证书名可保留系统权限）"
    )]
    pub sign_identity: String,

    #[arg(
        short = 'i',
        long = "inspect",
        help = "诊断模式：探测 Telegram.app 结构、去广告命中状态与 ARM64 交叉引用地址"
    )]
    pub inspect: bool,

    #[arg(short = 'v', long = "verbose", help = "输出详细调试日志")]
    pub verbose: bool,
}

impl CliArgs {
    pub fn to_patch_options(&self) -> PatchOptions {
        PatchOptions {
            core_patch: !self.no_core,
            remove_bloatware: !self.no_bloat,
            prune_locales: !self.no_locales,
            thin_arm64: !self.no_thin,
            clean_logs: self.clean_logs,
            sign_identity: self.sign_identity.clone(),
        }
    }
}

pub fn init_tracing(verbose: bool) {
    let level = if verbose { Level::DEBUG } else { Level::INFO };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .without_time()
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
}

pub fn check_root_privilege() {
    let is_root = unsafe { libc::geteuid() == 0 };
    if !is_root {
        eprintln!(
            "{}",
            style("提示: 修改 /Applications/Telegram.app 需要管理员权限，请使用 sudo tg-patcher 运行！")
                .yellow()
                .bold()
        );
    }
}

pub fn print_summary(report: &PatchReport) {
    let saved = report.initial_size.saturating_sub(report.final_size);
    let percent = if report.initial_size > 0 {
        (saved as f64 / report.initial_size as f64) * 100.0
    } else {
        0.0
    };
    println!();
    println!(
        "{}",
        style("==========================================================").dim()
    );
    println!("{}", style("处理汇总统计").cyan().bold());
    println!(
        "{}",
        style("----------------------------------------------------------").dim()
    );
    println!(
        "• 目标客户端: {}",
        style("Telegram.app (macOS Swift 原生版)").green().bold()
    );
    println!(
        "  体积对比: {} -> {} (减少: {}, 减幅: {:.1}%)",
        format_size(report.initial_size),
        format_size(report.final_size),
        style(format_size(saved)).yellow().bold(),
        percent
    );
    if report.migrated_data_dir {
        println!(
            "  数据目录: 已无损迁移至 {}",
            style("~/Library/Application Support/ru.keepcoder.Telegram")
                .green()
                .bold()
        );
    }
    if report.cleaned_logs_bytes > 0 {
        println!(
            "  日志清理: 已释放 {}",
            style(format_size(report.cleaned_logs_bytes)).yellow()
        );
    }
    if let Some(st) = report.inject_status {
        let desc = match st {
            InjectResult::Injected => "成功追加至加载表末尾",
            InjectResult::AlreadyPresent => "已更新补丁动态库 (加载表已就绪)",
            InjectResult::FixedAndInjected => "已修复错位项并重写至末尾",
        };
        println!("  补丁状态: {}", style(desc).cyan());
        println!(
            "  热切菜单: 启动客户端后可在屏幕顶部菜单栏点击「{}」实时开关各项功能",
            style("⚡ 增强设置").green().bold()
        );
    }
    if !report.removed_components.is_empty() {
        println!(
            "  清理组件: 已移除 {} 个 ({})",
            report.removed_components.len(),
            report.removed_components.join(", ")
        );
    }
    if report.pruned_locales_count > 0 {
        println!(
            "  语言精简: 已移除 {} 个冗余语言包",
            report.pruned_locales_count
        );
    }
    if report.thinned_count > 0 {
        println!(
            "  架构精简: {} 个二进制完成纯 arm64 转换",
            report.thinned_count
        );
    }
    println!(
        "{}",
        style("==========================================================").dim()
    );
}

pub fn run() {
    let args = CliArgs::parse();
    init_tracing(args.verbose);
    if args.inspect {
        run_inspect();
        return;
    }
    println!(
        "{}",
        style("macOS 原生 Telegram 客户端增强与精简工具 v0.1.0")
            .bold()
            .cyan()
    );
    check_root_privilege();
    let is_interactive = !args.yes && console::user_attended();
    let options = if is_interactive {
        let items = [
            "1. 注入增强补丁 (顶部「⚡ 增强设置」菜单 / 破防截屏 / 屏蔽频道广告 / 解除禁止选中 / 禁用自动更新)",
            "2. 删除无用组件 (移除 TelegramShare.appex 分享扩展与 Autoupdate.app)",
            "3. 清理多余语言包 (仅保留简繁中文与英文)",
            "4. 提取纯 arm64 架构 (lipo 剥离主程序与 Swift 库的 x86_64 代码)",
            "5. 顺手清理运行日志 (仅删 stable/logs，保留所有媒体缓存)",
        ];
        let defaults = [true, true, true, true, false];
        println!();
        println!("请选择需要执行的项目 (空格切换，回车确认):");
        let selections = MultiSelect::new()
            .items(&items)
            .defaults(&defaults)
            .interact()
            .unwrap_or_else(|_| vec![0, 1, 2, 3]);
        PatchOptions {
            core_patch: selections.contains(&0),
            remove_bloatware: selections.contains(&1),
            prune_locales: selections.contains(&2),
            thin_arm64: selections.contains(&3),
            clean_logs: selections.contains(&4),
            sign_identity: args.sign_identity.clone(),
        }
    } else {
        args.to_patch_options()
    };

    match run_pipeline(&options) {
        Ok(report) => print_summary(&report),
        Err(e) => {
            eprintln!("{}", style(format!("处理失败: {e}")).red().bold());
            std::process::exit(1);
        }
    }
}
