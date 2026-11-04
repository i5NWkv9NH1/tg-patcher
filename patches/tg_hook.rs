// * 纯 Rust 编写的 macOS 原生 Telegram 客户端注入动态库 (libtg_patch.dylib)
// * 支持中英双语顶部菜单栏「⚡ 增强设置 / ⚡ Patcher」实时热切换、防截屏破除、ARM64 内存级去频道气泡广告、解除禁止复制与屏蔽自动更新

use std::ffi::{CStr, CString, c_char, c_int, c_ulong, c_void};
use std::fs;
use std::path::PathBuf;
use std::sync::Once;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CGSize {
    pub width: f64,
    pub height: f64,
}

// * 运行时热切换全局原子开关
static OPT_ALLOW_SCREENSHOT: AtomicBool = AtomicBool::new(true);
static OPT_HIDE_SPONSORED: AtomicBool = AtomicBool::new(true);
static OPT_UNLOCK_COPY: AtomicBool = AtomicBool::new(true);
static OPT_DISABLE_SPARKLE: AtomicBool = AtomicBool::new(true);
static OPT_LANG_EN: AtomicBool = AtomicBool::new(false);

// * 缓存菜单项指针以支持运行时一键切换中英文标题
static MENU_SUB_PTR: AtomicUsize = AtomicUsize::new(0);
static ITEM_SS_PTR: AtomicUsize = AtomicUsize::new(0);
static ITEM_AD_PTR: AtomicUsize = AtomicUsize::new(0);
static ITEM_CP_PTR: AtomicUsize = AtomicUsize::new(0);
static ITEM_SP_PTR: AtomicUsize = AtomicUsize::new(0);
static ITEM_LANG_PTR: AtomicUsize = AtomicUsize::new(0);

static MENU_INJECTED: Once = Once::new();

unsafe extern "C" {
    static mach_task_self_: u32;
    fn getpagesize() -> c_int;
    fn sys_icache_invalidate(start: *mut c_void, len: usize);
    fn vm_protect(
        target_task: u32,
        address: usize,
        size: usize,
        set_maximum: i32,
        new_protection: i32,
    ) -> i32;

    fn _dyld_image_count() -> u32;
    fn _dyld_get_image_name(image_index: u32) -> *const c_char;
    fn _dyld_get_image_header(image_index: u32) -> *const c_void;

    fn getprogname() -> *const c_char;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;

    fn objc_getClass(name: *const c_char) -> *mut c_void;
    fn objc_copyClassList(out_count: *mut u32) -> *mut *mut c_void;
    fn class_getName(cls: *mut c_void) -> *const c_char;
    fn class_getInstanceMethod(cls: *mut c_void, sel: *mut c_void) -> *mut c_void;
    fn class_getInstanceVariable(cls: *mut c_void, name: *const c_char) -> *mut c_void;
    fn ivar_getOffset(ivar: *mut c_void) -> isize;
    fn method_getImplementation(method: *mut c_void) -> *mut c_void;
    fn method_setImplementation(method: *mut c_void, imp: *mut c_void) -> *mut c_void;
    fn sel_registerName(name: *const c_char) -> *mut c_void;
    fn objc_allocateClassPair(
        superclass: *mut c_void,
        name: *const c_char,
        extra_bytes: usize,
    ) -> *mut c_void;
    fn objc_registerClassPair(cls: *mut c_void);
    fn class_addMethod(
        cls: *mut c_void,
        name: *mut c_void,
        imp: *mut c_void,
        types: *const c_char,
    ) -> i8;
    fn free(ptr: *mut c_void);
}

const RTLD_DEFAULT: *mut c_void = -2isize as *mut c_void;

#[inline]
unsafe fn msg_send_ptr() -> *mut c_void {
    unsafe { dlsym(RTLD_DEFAULT, c"objc_msgSend".as_ptr()) }
}

unsafe fn make_nsstring(s: &str) -> *mut c_void {
    let Ok(cstr) = CString::new(s) else {
        return std::ptr::null_mut();
    };
    unsafe {
        let cls = objc_getClass(c"NSString".as_ptr());
        let sel = sel_registerName(c"stringWithUTF8String:".as_ptr());
        let f: unsafe extern "C" fn(*mut c_void, *mut c_void, *const c_char) -> *mut c_void =
            std::mem::transmute(msg_send_ptr());
        f(cls, sel, cstr.as_ptr())
    }
}

// * 1. 本地配置文件读写与系统语言自动检测

fn get_config_file_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/Shared".to_string());
    let dir = PathBuf::from(format!(
        "{home}/Library/Application Support/TelegramPatcher"
    ));
    let _ = fs::create_dir_all(&dir);
    dir.join("config.conf")
}

fn detect_default_english() -> bool {
    if let Ok(lang) = std::env::var("LANG") {
        return !lang.to_ascii_lowercase().starts_with("zh");
    }
    false
}

fn load_runtime_config() {
    let path = get_config_file_path();
    let Ok(content) = fs::read_to_string(path) else {
        OPT_LANG_EN.store(detect_default_english(), Ordering::Relaxed);
        save_runtime_config();
        return;
    };
    for line in content.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let val = v.trim();
        let enabled =
            val == "1" || val.eq_ignore_ascii_case("true") || val.eq_ignore_ascii_case("en");
        match k.trim() {
            "allow_screenshot" => OPT_ALLOW_SCREENSHOT.store(enabled, Ordering::Relaxed),
            "hide_sponsored" => OPT_HIDE_SPONSORED.store(enabled, Ordering::Relaxed),
            "unlock_copy" => OPT_UNLOCK_COPY.store(enabled, Ordering::Relaxed),
            "disable_sparkle" => OPT_DISABLE_SPARKLE.store(enabled, Ordering::Relaxed),
            "lang_en" => OPT_LANG_EN.store(enabled, Ordering::Relaxed),
            _ => {}
        }
    }
}

fn save_runtime_config() {
    let path = get_config_file_path();
    let body = format!(
        "allow_screenshot={}\nhide_sponsored={}\nunlock_copy={}\ndisable_sparkle={}\nlang_en={}\n",
        usize::from(OPT_ALLOW_SCREENSHOT.load(Ordering::Relaxed)),
        usize::from(OPT_HIDE_SPONSORED.load(Ordering::Relaxed)),
        usize::from(OPT_UNLOCK_COPY.load(Ordering::Relaxed)),
        usize::from(OPT_DISABLE_SPARKLE.load(Ordering::Relaxed)),
        usize::from(OPT_LANG_EN.load(Ordering::Relaxed)),
    );
    let _ = fs::write(path, body);
}

// * 2. 核心防闪退钩子：将受 macOS TCC 跨团队保护的 Group Container 重定向至 Application Support
unsafe extern "C" fn hooked_container_url(
    _this: *mut c_void,
    _sel: *mut c_void,
    _group_id: *mut c_void,
) -> *mut c_void {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/Shared".to_string());
    let container_dir = format!("{home}/Library/Application Support/TelegramPatcher/Container");
    let _ = fs::create_dir_all(&container_dir);

    unsafe {
        let url_cls = objc_getClass(c"NSURL".as_ptr());
        let sel = sel_registerName(c"fileURLWithPath:isDirectory:".as_ptr());
        let f: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, i8) -> *mut c_void =
            std::mem::transmute(msg_send_ptr());
        let ns_path = make_nsstring(&container_dir);
        f(url_cls, sel, ns_path, 1)
    }
}

// * 3. 破除禁止截屏与录屏黑框限制 (NSWindow.sharingType & NSView.protectedContent)

static mut ORIG_SET_SHARING_TYPE: Option<unsafe extern "C" fn(*mut c_void, *mut c_void, c_ulong)> =
    None;
static mut ORIG_SHARING_TYPE: Option<unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_ulong> =
    None;
static mut ORIG_SET_PROTECTED_CONTENT: Option<unsafe extern "C" fn(*mut c_void, *mut c_void, i8)> =
    None;

unsafe extern "C" fn hooked_set_sharing_type(
    this: *mut c_void,
    sel: *mut c_void,
    mut sharing_type: c_ulong,
) {
    if OPT_ALLOW_SCREENSHOT.load(Ordering::Relaxed) && sharing_type == 0 {
        sharing_type = 1;
    }
    if let Some(orig) = unsafe { ORIG_SET_SHARING_TYPE } {
        unsafe { orig(this, sel, sharing_type) };
    }
}

unsafe extern "C" fn hooked_sharing_type(this: *mut c_void, sel: *mut c_void) -> c_ulong {
    if OPT_ALLOW_SCREENSHOT.load(Ordering::Relaxed) {
        return 1;
    }
    if let Some(orig) = unsafe { ORIG_SHARING_TYPE } {
        return unsafe { orig(this, sel) };
    }
    1
}

unsafe extern "C" fn hooked_set_protected_content(
    this: *mut c_void,
    sel: *mut c_void,
    mut protected: i8,
) {
    if OPT_ALLOW_SCREENSHOT.load(Ordering::Relaxed) {
        protected = 0;
    }
    if let Some(orig) = unsafe { ORIG_SET_PROTECTED_CONTENT } {
        unsafe { orig(this, sel, protected) };
    }
}

unsafe fn refresh_all_windows_sharing_type() {
    if !OPT_ALLOW_SCREENSHOT.load(Ordering::Relaxed) {
        return;
    }
    unsafe {
        let app_cls = objc_getClass(c"NSApplication".as_ptr());
        if app_cls.is_null() {
            return;
        }
        let f_obj: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
            std::mem::transmute(msg_send_ptr());
        let shared_app = f_obj(app_cls, sel_registerName(c"sharedApplication".as_ptr()));
        if shared_app.is_null() {
            return;
        }
        let windows = f_obj(shared_app, sel_registerName(c"windows".as_ptr()));
        if windows.is_null() {
            return;
        }
        let f_count: unsafe extern "C" fn(*mut c_void, *mut c_void) -> usize =
            std::mem::transmute(msg_send_ptr());
        let f_at: unsafe extern "C" fn(*mut c_void, *mut c_void, usize) -> *mut c_void =
            std::mem::transmute(msg_send_ptr());
        let f_set_share: unsafe extern "C" fn(*mut c_void, *mut c_void, c_ulong) =
            std::mem::transmute(msg_send_ptr());

        let count = f_count(windows, sel_registerName(c"count".as_ptr()));
        let sel_at = sel_registerName(c"objectAtIndex:".as_ptr());
        let sel_set = sel_registerName(c"setSharingType:".as_ptr());
        for i in 0..count {
            let win = f_at(windows, sel_at, i);
            if !win.is_null() {
                f_set_share(win, sel_set, 1);
            }
        }
    }
}

// * 4. ARM64 内存指令热修补：从 AdMessages.swift 源头彻底掐断频道伪装气泡广告

struct AdPatchSpot {
    addr: usize,
    orig_insn: u32,
    patch_insn: u32,
}

static AD_PATCH_SPOTS: std::sync::OnceLock<Vec<AdPatchSpot>> = std::sync::OnceLock::new();

unsafe fn find_telegram_text_region() -> Option<(usize, &'static [u32])> {
    unsafe {
        let count = _dyld_image_count();
        for i in 0..count {
            let name_ptr = _dyld_get_image_name(i);
            if name_ptr.is_null() {
                continue;
            }
            let name_bytes = CStr::from_ptr(name_ptr).to_bytes();
            if name_bytes.ends_with(b"/MacOS/Telegram") {
                let base = _dyld_get_image_header(i) as usize;
                let ncmds = *((base + 16) as *const u32) as usize;
                let mut cur = base + 32;
                for _ in 0..ncmds {
                    let cmd = *(cur as *const u32);
                    let cmdsize = *((cur + 4) as *const u32) as usize;
                    if cmd == 0x19 {
                        let segname = std::slice::from_raw_parts((cur + 8) as *const u8, 16);
                        if segname.starts_with(b"__TEXT\0") {
                            let vmsize = *((cur + 32) as *const u64) as usize;
                            let words = std::slice::from_raw_parts(base as *const u32, vmsize / 4);
                            return Some((base, words));
                        }
                    }
                    cur += cmdsize;
                }
            }
        }
        None
    }
}

fn resolve_ad_patch_spots() -> &'static [AdPatchSpot] {
    AD_PATCH_SPOTS.get_or_init(|| {
        let mut spots = Vec::new();
        let Some((base, words)) = (unsafe { find_telegram_text_region() }) else {
            return spots;
        };

        // * 关卡 1: AdMessagesHistoryContextImpl.init 本地 5 分钟缓存广告分支 (b.le -> NOP)
        let off1 = 0x837bbc / 4;
        if off1 < words.len() && words[off1] == 0x540002cd && words[off1 - 4] == 0x1e780108 {
            spots.push(AdPatchSpot {
                addr: base + off1 * 4,
                orig_insn: 0x540002cd,
                patch_insn: 0xd503201f,
            });
        } else if let Some(idx) = words
            .windows(5)
            .position(|w| w[0] == 0x1e780108 && w[1] == 0x7104b108 && w[3] == 0x6b1b011f)
        {
            spots.push(AdPatchSpot {
                addr: base + (idx + 4) * 4,
                orig_insn: words[idx + 4],
                patch_insn: 0xd503201f,
            });
        }

        // * 关卡 2: AdMessages 状态构建循环的广告数组长度 (ldr x27, [x19, #0x10] -> mov x27, #0)
        let off2 = 0x837d1c / 4;
        if off2 < words.len() && words[off2] == 0xf9400a7b && words[off2 + 1] == 0xd2800015 {
            spots.push(AdPatchSpot {
                addr: base + off2 * 4,
                orig_insn: 0xf9400a7b,
                patch_insn: 0xd280001b,
            });
        } else if let Some(idx) = words
            .windows(3)
            .position(|w| w[0] == 0xf9400a7b && w[1] == 0xd2800015 && w[2] == 0x92420b1c)
        {
            spots.push(AdPatchSpot {
                addr: base + idx * 4,
                orig_insn: 0xf9400a7b,
                patch_insn: 0xd280001b,
            });
        }

        // * 关卡 3: AdMessagesHistoryContextImpl.activate 网络拉取广告入口 (tbz -> NOP)
        let off3 = 0x837f7c / 4;
        if off3 < words.len() && words[off3] == 0x36000128 && words[off3 - 1] == 0x39420288 {
            spots.push(AdPatchSpot {
                addr: base + off3 * 4,
                orig_insn: 0x36000128,
                patch_insn: 0xd503201f,
            });
        } else if let Some(idx) = words.windows(3).position(|w| {
            w[0] == 0x39420288 && (w[1] & 0xff00001f) == 0x36000008 && w[2] == 0xa9487bfd
        }) {
            spots.push(AdPatchSpot {
                addr: base + (idx + 1) * 4,
                orig_insn: words[idx + 1],
                patch_insn: 0xd503201f,
            });
        }

        spots
    })
}

unsafe fn write_arm64_insn(addr: usize, insn: u32) {
    unsafe {
        let page_size = getpagesize() as usize;
        let page_start = addr & !(page_size - 1);

        if vm_protect(mach_task_self_, page_start, page_size, 0, 0x13) != 0
            && vm_protect(mach_task_self_, page_start, page_size, 0, 0x03) != 0
        {
            return;
        }

        let ptr = addr as *mut u32;
        *ptr = insn;

        let _ = vm_protect(mach_task_self_, page_start, page_size, 0, 0x05);
        sys_icache_invalidate(ptr as *mut c_void, 4);
    }
}

unsafe fn apply_adblock_memory_patches(block_ads: bool) {
    let spots = resolve_ad_patch_spots();
    for spot in spots {
        let target_insn = if block_ads {
            spot.patch_insn
        } else {
            spot.orig_insn
        };
        unsafe { write_arm64_insn(spot.addr, target_insn) };
    }
}

static mut ORIG_SPONSORED_LAYOUT: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)> = None;

unsafe extern "C" fn hooked_sponsored_layout(this: *mut c_void, sel: *mut c_void) {
    if let Some(orig) = unsafe { ORIG_SPONSORED_LAYOUT } {
        unsafe { orig(this, sel) };
    }
    if OPT_HIDE_SPONSORED.load(Ordering::Relaxed) && !this.is_null() {
        unsafe {
            let f_hide: unsafe extern "C" fn(*mut c_void, *mut c_void, i8) =
                std::mem::transmute(msg_send_ptr());
            f_hide(this, sel_registerName(c"setHidden:".as_ptr()), 1);

            let f_size: unsafe extern "C" fn(*mut c_void, *mut c_void, CGSize) =
                std::mem::transmute(msg_send_ptr());
            f_size(
                this,
                sel_registerName(c"setFrameSize:".as_ptr()),
                CGSize {
                    width: 0.0,
                    height: 0.0,
                },
            );
        }
    }
}

// * 5. 解除受限群组/频道的禁止选中与右键菜单限制

static mut ORIG_CHAT_INTERACTION_INIT: Option<
    unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void,
> = None;
static mut ORIG_CONTEXT_MENU_POPUP: Option<
    unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void, *mut c_void),
> = None;

unsafe fn clear_disable_select_ability(instance: *mut c_void) {
    if instance.is_null() || !OPT_UNLOCK_COPY.load(Ordering::Relaxed) {
        return;
    }
    unsafe {
        let cls = objc_getClass(c"_TtC6ChatUI15ChatInteraction".as_ptr());
        if cls.is_null() {
            return;
        }
        let ivar = class_getInstanceVariable(cls, c"disableSelectAbility".as_ptr());
        if !ivar.is_null() {
            let offset = ivar_getOffset(ivar);
            if offset > 0 && offset < 4096 {
                let field_ptr = (instance as *mut u8).offset(offset);
                *field_ptr = 0;
            }
        }
    }
}

unsafe extern "C" fn hooked_chat_interaction_init(
    this: *mut c_void,
    sel: *mut c_void,
) -> *mut c_void {
    let obj = if let Some(orig) = unsafe { ORIG_CHAT_INTERACTION_INIT } {
        unsafe { orig(this, sel) }
    } else {
        this
    };
    unsafe { clear_disable_select_ability(obj) };
    obj
}

unsafe extern "C" fn hooked_context_menu_popup(
    this: *mut c_void,
    sel: *mut c_void,
    menu: *mut c_void,
    event: *mut c_void,
    view: *mut c_void,
) {
    unsafe { ensure_patcher_menu_injected() };
    if let Some(orig) = unsafe { ORIG_CONTEXT_MENU_POPUP } {
        unsafe { orig(this, sel, menu, event, view) };
    }
}

// * 6. 拦截 Sparkle 自动更新检查

unsafe extern "C" fn noop_sparkle_check(
    _this: *mut c_void,
    _sel: *mut c_void,
    _sender: *mut c_void,
) {
}

unsafe extern "C" fn noop_sparkle_bg(_this: *mut c_void, _sel: *mut c_void) {}

// * 7. 顶部系统菜单栏「⚡ 增强设置 / ⚡ Patcher」动态挂载与中英文实时切换

unsafe extern "C" fn on_toggle_screenshot(
    _this: *mut c_void,
    _sel: *mut c_void,
    sender: *mut c_void,
) {
    let next = !OPT_ALLOW_SCREENSHOT.load(Ordering::Relaxed);
    OPT_ALLOW_SCREENSHOT.store(next, Ordering::Relaxed);
    save_runtime_config();
    unsafe {
        set_menu_item_state(sender, next);
        refresh_all_windows_sharing_type();
    }
}

unsafe extern "C" fn on_toggle_sponsored(
    _this: *mut c_void,
    _sel: *mut c_void,
    sender: *mut c_void,
) {
    let next = !OPT_HIDE_SPONSORED.load(Ordering::Relaxed);
    OPT_HIDE_SPONSORED.store(next, Ordering::Relaxed);
    save_runtime_config();
    unsafe {
        set_menu_item_state(sender, next);
        apply_adblock_memory_patches(next);
    }
}

unsafe extern "C" fn on_toggle_unlock_copy(
    _this: *mut c_void,
    _sel: *mut c_void,
    sender: *mut c_void,
) {
    let next = !OPT_UNLOCK_COPY.load(Ordering::Relaxed);
    OPT_UNLOCK_COPY.store(next, Ordering::Relaxed);
    save_runtime_config();
    unsafe { set_menu_item_state(sender, next) };
}

unsafe extern "C" fn on_toggle_disable_sparkle(
    _this: *mut c_void,
    _sel: *mut c_void,
    sender: *mut c_void,
) {
    let next = !OPT_DISABLE_SPARKLE.load(Ordering::Relaxed);
    OPT_DISABLE_SPARKLE.store(next, Ordering::Relaxed);
    save_runtime_config();
    unsafe { set_menu_item_state(sender, next) };
}

unsafe extern "C" fn on_toggle_language(
    _this: *mut c_void,
    _sel: *mut c_void,
    _sender: *mut c_void,
) {
    let next = !OPT_LANG_EN.load(Ordering::Relaxed);
    OPT_LANG_EN.store(next, Ordering::Relaxed);
    save_runtime_config();
    unsafe { refresh_menu_titles(next) };
}

unsafe fn set_obj_title(obj: usize, title: &str) {
    if obj == 0 {
        return;
    }
    unsafe {
        let f_title: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) =
            std::mem::transmute(msg_send_ptr());
        f_title(
            obj as *mut c_void,
            sel_registerName(c"setTitle:".as_ptr()),
            make_nsstring(title),
        );
    }
}

// * 实时刷新菜单栏中英文标题文案
unsafe fn refresh_menu_titles(is_en: bool) {
    unsafe {
        if is_en {
            set_obj_title(MENU_SUB_PTR.load(Ordering::Relaxed), "⚡ Patcher");
            set_obj_title(
                ITEM_SS_PTR.load(Ordering::Relaxed),
                "Allow Screenshots & Screen Recording",
            );
            set_obj_title(
                ITEM_AD_PTR.load(Ordering::Relaxed),
                "Block Channel Sponsored Ads (Re-enter Chat)",
            );
            set_obj_title(
                ITEM_CP_PTR.load(Ordering::Relaxed),
                "Unlock Copy & Text Selection in Protected Chats",
            );
            set_obj_title(
                ITEM_SP_PTR.load(Ordering::Relaxed),
                "Disable Sparkle Auto-Update Checks",
            );
            set_obj_title(
                ITEM_LANG_PTR.load(Ordering::Relaxed),
                "🌐 切换为简体中文 (Switch to Chinese)",
            );
        } else {
            set_obj_title(MENU_SUB_PTR.load(Ordering::Relaxed), "⚡ 增强设置");
            set_obj_title(
                ITEM_SS_PTR.load(Ordering::Relaxed),
                "强制允许截屏与录屏 (破除黑框)",
            );
            set_obj_title(
                ITEM_AD_PTR.load(Ordering::Relaxed),
                "屏蔽频道官方赞助广告 (重进频道生效)",
            );
            set_obj_title(
                ITEM_CP_PTR.load(Ordering::Relaxed),
                "解除受限群文字选中与复制限制",
            );
            set_obj_title(
                ITEM_SP_PTR.load(Ordering::Relaxed),
                "拦截 Sparkle 自动更新弹窗",
            );
            set_obj_title(
                ITEM_LANG_PTR.load(Ordering::Relaxed),
                "🌐 Switch to English (切换英文)",
            );
        }
    }
}

unsafe fn set_menu_item_state(item: *mut c_void, enabled: bool) {
    if item.is_null() {
        return;
    }
    unsafe {
        let f_state: unsafe extern "C" fn(*mut c_void, *mut c_void, isize) =
            std::mem::transmute(msg_send_ptr());
        f_state(
            item,
            sel_registerName(c"setState:".as_ptr()),
            if enabled { 1 } else { 0 },
        );
    }
}

unsafe fn create_menu_item(
    title: &str,
    action_sel_name: *const c_char,
    target: *mut c_void,
    initial_state: Option<bool>,
) -> *mut c_void {
    unsafe {
        let item_cls = objc_getClass(c"NSMenuItem".as_ptr());
        let f_alloc: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
            std::mem::transmute(msg_send_ptr());
        let raw = f_alloc(item_cls, sel_registerName(c"alloc".as_ptr()));

        let f_init: unsafe extern "C" fn(
            *mut c_void,
            *mut c_void,
            *mut c_void,
            *mut c_void,
            *mut c_void,
        ) -> *mut c_void = std::mem::transmute(msg_send_ptr());

        let ns_title = make_nsstring(title);
        let ns_key = make_nsstring("");
        let action_sel = sel_registerName(action_sel_name);
        let item = f_init(
            raw,
            sel_registerName(c"initWithTitle:action:keyEquivalent:".as_ptr()),
            ns_title,
            action_sel,
            ns_key,
        );

        let f_target: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) =
            std::mem::transmute(msg_send_ptr());
        f_target(item, sel_registerName(c"setTarget:".as_ptr()), target);
        if let Some(st) = initial_state {
            set_menu_item_state(item, st);
        }
        item
    }
}

unsafe fn ensure_patcher_menu_injected() {
    unsafe {
        let app_cls = objc_getClass(c"NSApplication".as_ptr());
        if app_cls.is_null() {
            return;
        }
        let f_obj: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
            std::mem::transmute(msg_send_ptr());
        let shared_app = f_obj(app_cls, sel_registerName(c"sharedApplication".as_ptr()));
        if shared_app.is_null() {
            return;
        }
        let main_menu = f_obj(shared_app, sel_registerName(c"mainMenu".as_ptr()));
        if main_menu.is_null() {
            return;
        }

        MENU_INJECTED.call_once(|| {
            let nsobject_cls = objc_getClass(c"NSObject".as_ptr());
            let handler_cls =
                objc_allocateClassPair(nsobject_cls, c"TGPatcherMenuHandler".as_ptr(), 0);
            if !handler_cls.is_null() {
                let _ = class_addMethod(
                    handler_cls,
                    sel_registerName(c"toggleScreenshot:".as_ptr()),
                    on_toggle_screenshot as *mut c_void,
                    c"v24@0:8@16".as_ptr(),
                );
                let _ = class_addMethod(
                    handler_cls,
                    sel_registerName(c"toggleSponsored:".as_ptr()),
                    on_toggle_sponsored as *mut c_void,
                    c"v24@0:8@16".as_ptr(),
                );
                let _ = class_addMethod(
                    handler_cls,
                    sel_registerName(c"toggleUnlockCopy:".as_ptr()),
                    on_toggle_unlock_copy as *mut c_void,
                    c"v24@0:8@16".as_ptr(),
                );
                let _ = class_addMethod(
                    handler_cls,
                    sel_registerName(c"toggleDisableSparkle:".as_ptr()),
                    on_toggle_disable_sparkle as *mut c_void,
                    c"v24@0:8@16".as_ptr(),
                );
                let _ = class_addMethod(
                    handler_cls,
                    sel_registerName(c"toggleLanguage:".as_ptr()),
                    on_toggle_language as *mut c_void,
                    c"v24@0:8@16".as_ptr(),
                );
                objc_registerClassPair(handler_cls);
            }

            let target_cls = objc_getClass(c"TGPatcherMenuHandler".as_ptr());
            if target_cls.is_null() {
                return;
            }
            let target_instance = f_obj(
                f_obj(target_cls, sel_registerName(c"alloc".as_ptr())),
                sel_registerName(c"init".as_ptr()),
            );

            let menu_item_cls = objc_getClass(c"NSMenuItem".as_ptr());
            let top_item = f_obj(
                f_obj(menu_item_cls, sel_registerName(c"alloc".as_ptr())),
                sel_registerName(c"init".as_ptr()),
            );

            let menu_cls = objc_getClass(c"NSMenu".as_ptr());
            let f_init_title: unsafe extern "C" fn(
                *mut c_void,
                *mut c_void,
                *mut c_void,
            ) -> *mut c_void = std::mem::transmute(msg_send_ptr());
            let sub_menu = f_init_title(
                f_obj(menu_cls, sel_registerName(c"alloc".as_ptr())),
                sel_registerName(c"initWithTitle:".as_ptr()),
                make_nsstring("⚡ 增强设置"),
            );

            let f_add_item: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) =
                std::mem::transmute(msg_send_ptr());
            let sel_add = sel_registerName(c"addItem:".as_ptr());

            let item_ss = create_menu_item(
                "",
                c"toggleScreenshot:".as_ptr(),
                target_instance,
                Some(OPT_ALLOW_SCREENSHOT.load(Ordering::Relaxed)),
            );
            let item_ad = create_menu_item(
                "",
                c"toggleSponsored:".as_ptr(),
                target_instance,
                Some(OPT_HIDE_SPONSORED.load(Ordering::Relaxed)),
            );
            let item_cp = create_menu_item(
                "",
                c"toggleUnlockCopy:".as_ptr(),
                target_instance,
                Some(OPT_UNLOCK_COPY.load(Ordering::Relaxed)),
            );
            let item_sp = create_menu_item(
                "",
                c"toggleDisableSparkle:".as_ptr(),
                target_instance,
                Some(OPT_DISABLE_SPARKLE.load(Ordering::Relaxed)),
            );
            let sep_item = f_obj(menu_item_cls, sel_registerName(c"separatorItem".as_ptr()));
            let item_lang =
                create_menu_item("", c"toggleLanguage:".as_ptr(), target_instance, None);

            MENU_SUB_PTR.store(sub_menu as usize, Ordering::Relaxed);
            ITEM_SS_PTR.store(item_ss as usize, Ordering::Relaxed);
            ITEM_AD_PTR.store(item_ad as usize, Ordering::Relaxed);
            ITEM_CP_PTR.store(item_cp as usize, Ordering::Relaxed);
            ITEM_SP_PTR.store(item_sp as usize, Ordering::Relaxed);
            ITEM_LANG_PTR.store(item_lang as usize, Ordering::Relaxed);

            refresh_menu_titles(OPT_LANG_EN.load(Ordering::Relaxed));

            f_add_item(sub_menu, sel_add, item_ss);
            f_add_item(sub_menu, sel_add, item_ad);
            f_add_item(sub_menu, sel_add, item_cp);
            f_add_item(sub_menu, sel_add, item_sp);
            if !sep_item.is_null() {
                f_add_item(sub_menu, sel_add, sep_item);
            }
            f_add_item(sub_menu, sel_add, item_lang);

            f_add_item(
                top_item,
                sel_registerName(c"setSubmenu:".as_ptr()),
                sub_menu,
            );
            f_add_item(main_menu, sel_add, top_item);

            refresh_all_windows_sharing_type();
        });
    }
}

// * 8. 钩子统一扫描与挂载入口

static mut ORIG_FINISH_LAUNCHING: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)> = None;

unsafe extern "C" fn hooked_finish_launching(this: *mut c_void, sel: *mut c_void) {
    if let Some(orig) = unsafe { ORIG_FINISH_LAUNCHING } {
        unsafe { orig(this, sel) };
    }
    unsafe {
        ensure_patcher_menu_injected();
        refresh_all_windows_sharing_type();
    }
}

unsafe fn install_objc_hooks() {
    unsafe {
        // * 0. 优先 Hook NSFileManager.containerURLForSecurityApplicationGroupIdentifier: 彻底绕过 TCC 弹窗与闪退
        let fm_cls = objc_getClass(c"NSFileManager".as_ptr());
        if !fm_cls.is_null() {
            let m_url = class_getInstanceMethod(
                fm_cls,
                sel_registerName(c"containerURLForSecurityApplicationGroupIdentifier:".as_ptr()),
            );
            if !m_url.is_null() {
                method_setImplementation(m_url, hooked_container_url as *mut c_void);
            }
        }

        // * 1. Hook NSApplication.finishLaunching 以挂载顶部「⚡ 增强设置 / ⚡ Patcher」菜单
        let app_cls = objc_getClass(c"NSApplication".as_ptr());
        if !app_cls.is_null() {
            let m = class_getInstanceMethod(app_cls, sel_registerName(c"finishLaunching".as_ptr()));
            if !m.is_null() {
                ORIG_FINISH_LAUNCHING = Some(std::mem::transmute(method_getImplementation(m)));
                method_setImplementation(m, hooked_finish_launching as *mut c_void);
            }
        }

        // * 2. Hook NSWindow 的 setSharingType: 与 sharingType 破除防截屏
        let win_cls = objc_getClass(c"NSWindow".as_ptr());
        if !win_cls.is_null() {
            let m_set =
                class_getInstanceMethod(win_cls, sel_registerName(c"setSharingType:".as_ptr()));
            if !m_set.is_null() {
                ORIG_SET_SHARING_TYPE = Some(std::mem::transmute(method_getImplementation(m_set)));
                method_setImplementation(m_set, hooked_set_sharing_type as *mut c_void);
            }
            let m_get = class_getInstanceMethod(win_cls, sel_registerName(c"sharingType".as_ptr()));
            if !m_get.is_null() {
                ORIG_SHARING_TYPE = Some(std::mem::transmute(method_getImplementation(m_get)));
                method_setImplementation(m_get, hooked_sharing_type as *mut c_void);
            }
        }

        // * 3. Hook NSView 的 setAccessibilityProtectedContent:
        let view_cls = objc_getClass(c"NSView".as_ptr());
        if !view_cls.is_null() {
            let m_prot = class_getInstanceMethod(
                view_cls,
                sel_registerName(c"setAccessibilityProtectedContent:".as_ptr()),
            );
            if !m_prot.is_null() {
                ORIG_SET_PROTECTED_CONTENT =
                    Some(std::mem::transmute(method_getImplementation(m_prot)));
                method_setImplementation(m_prot, hooked_set_protected_content as *mut c_void);
            }
        }

        // * 4. Hook _TtC6ChatUI15ChatInteraction.init 与 _TtC7TGUIKit11ContextMenu
        let chat_inter_cls = objc_getClass(c"_TtC6ChatUI15ChatInteraction".as_ptr());
        if !chat_inter_cls.is_null() {
            let m_init =
                class_getInstanceMethod(chat_inter_cls, sel_registerName(c"init".as_ptr()));
            if !m_init.is_null() {
                ORIG_CHAT_INTERACTION_INIT =
                    Some(std::mem::transmute(method_getImplementation(m_init)));
                method_setImplementation(m_init, hooked_chat_interaction_init as *mut c_void);
            }
        }

        let ctx_menu_cls = objc_getClass(c"_TtC7TGUIKit11ContextMenu".as_ptr());
        if !ctx_menu_cls.is_null() {
            let m_pop = class_getInstanceMethod(
                ctx_menu_cls,
                sel_registerName(c"popUpContextMenu:withEvent:forView:".as_ptr()),
            );
            if !m_pop.is_null() {
                ORIG_CONTEXT_MENU_POPUP =
                    Some(std::mem::transmute(method_getImplementation(m_pop)));
                method_setImplementation(m_pop, hooked_context_menu_popup as *mut c_void);
            }
        }

        // * 5. Hook Sparkle 的 SUUpdater 防止自动更新弹窗覆盖补丁
        if OPT_DISABLE_SPARKLE.load(Ordering::Relaxed) {
            let sparkle_cls = objc_getClass(c"SUUpdater".as_ptr());
            if !sparkle_cls.is_null() {
                let m1 = class_getInstanceMethod(
                    sparkle_cls,
                    sel_registerName(c"checkForUpdates:".as_ptr()),
                );
                if !m1.is_null() {
                    method_setImplementation(m1, noop_sparkle_check as *mut c_void);
                }
                let m2 = class_getInstanceMethod(
                    sparkle_cls,
                    sel_registerName(c"checkForUpdatesInBackground".as_ptr()),
                );
                if !m2.is_null() {
                    method_setImplementation(m2, noop_sparkle_bg as *mut c_void);
                }
            }
        }

        // * 6. 动态遍历类列表，模糊匹配 ChatSponsoredView 并替换 layout
        let mut class_count: u32 = 0;
        let classes = objc_copyClassList(&mut class_count);
        if !classes.is_null() {
            for i in 0..class_count as usize {
                let cls = *classes.add(i);
                if cls.is_null() {
                    continue;
                }
                let name_ptr = class_getName(cls);
                if name_ptr.is_null() {
                    continue;
                }
                let name_bytes = CStr::from_ptr(name_ptr).to_bytes();
                if name_bytes.starts_with(b"_TtC6ChatUI")
                    && name_bytes.ends_with(b"ChatSponsoredView")
                {
                    let m_layout =
                        class_getInstanceMethod(cls, sel_registerName(c"layout".as_ptr()));
                    if !m_layout.is_null() {
                        ORIG_SPONSORED_LAYOUT =
                            Some(std::mem::transmute(method_getImplementation(m_layout)));
                        method_setImplementation(m_layout, hooked_sponsored_layout as *mut c_void);
                    }
                }
            }
            free(classes as *mut c_void);
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn init_tg_patch() {
    let prog = unsafe { getprogname() };
    if prog.is_null() {
        return;
    }
    let prog_bytes = unsafe { CStr::from_ptr(prog).to_bytes() };
    if prog_bytes != b"Telegram" {
        return;
    }

    load_runtime_config();
    unsafe {
        apply_adblock_memory_patches(OPT_HIDE_SPONSORED.load(Ordering::Relaxed));
        install_objc_hooks();
    }
}

#[used]
#[unsafe(link_section = "__DATA,__mod_init_func")]
pub static INIT_FUNC: unsafe extern "C" fn() = init_tg_patch;
