// * 纯 Rust 编写的 macOS 原生 Telegram 客户端注入动态库 (libtg_patch.dylib)
// * 数据目录重定向至 ~/Library/Application Support/ru.keepcoder.Telegram
// * 支持顶部菜单栏热切换、破防截屏、启动期 ARM64 去频道广告、解除禁止选中与真热切换禁用 Sparkle
use std::ffi::{CStr, CString, c_char, c_int, c_ulong, c_void};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};
use std::sync::{Once, OnceLock};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CGSize {
    pub width: f64,
    pub height: f64,
}

// * 运行时开关
static OPT_ALLOW_SCREENSHOT: AtomicBool = AtomicBool::new(true);
static OPT_HIDE_SPONSORED: AtomicBool = AtomicBool::new(true);
static OPT_UNLOCK_COPY: AtomicBool = AtomicBool::new(true);
static OPT_DISABLE_SPARKLE: AtomicBool = AtomicBool::new(true);
static OPT_LANG_EN: AtomicBool = AtomicBool::new(false);

// * 原函数指针存储（避免 Rust 2024 static mut 风险）
static ORIG_CONTAINER_URL: AtomicUsize = AtomicUsize::new(0);
static ORIG_FINISH_LAUNCHING: AtomicUsize = AtomicUsize::new(0);
static ORIG_SET_SHARING_TYPE: AtomicUsize = AtomicUsize::new(0);
static ORIG_SHARING_TYPE: AtomicUsize = AtomicUsize::new(0);
static ORIG_SET_PROTECTED_CONTENT: AtomicUsize = AtomicUsize::new(0);
static ORIG_CHAT_INTERACTION_INIT: AtomicUsize = AtomicUsize::new(0);
static ORIG_CONTEXT_MENU_POPUP: AtomicUsize = AtomicUsize::new(0);
static ORIG_SPARKLE_CHECK: AtomicUsize = AtomicUsize::new(0);
static ORIG_SPARKLE_BG: AtomicUsize = AtomicUsize::new(0);
static DISABLE_SELECT_IVAR_OFFSET: AtomicIsize = AtomicIsize::new(-1);
static SPONSORED_ORIG_IMPS: OnceLock<Vec<(usize, usize)>> = OnceLock::new();

// * 缓存菜单项指针以支持中英文实时切换
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
    fn objc_msgSend();
    fn objc_getClass(name: *const c_char) -> *mut c_void;
    fn object_getClass(obj: *mut c_void) -> *mut c_void;
    fn class_getSuperclass(cls: *mut c_void) -> *mut c_void;
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

#[inline]
fn msg_send_ptr() -> *const () {
    objc_msgSend as *const ()
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

// * 1. 数据根目录与配置文件路径（统一落在 ~/Library/Application Support/ru.keepcoder.Telegram）
fn get_data_root_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/Shared".to_string());
    let dir = PathBuf::from(format!(
        "{home}/Library/Application Support/ru.keepcoder.Telegram"
    ));
    let _ = fs::create_dir_all(&dir);
    dir
}

// * 兼容旧版目录：若新目录下尚未迁移数据且存在旧 TelegramPatcher，则启动时自动无损原地搬迁
fn migrate_legacy_dir_if_needed() {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/Shared".to_string());
    let old_root = PathBuf::from(format!(
        "{home}/Library/Application Support/TelegramPatcher"
    ));
    if !old_root.exists() {
        return;
    }
    let new_root = get_data_root_dir();
    let old_container = old_root.join("Container");
    if old_container.exists() {
        if let Ok(entries) = fs::read_dir(&old_container) {
            for entry in entries.flatten() {
                let dst = new_root.join(entry.file_name());
                if !dst.exists() {
                    let _ = fs::rename(entry.path(), dst);
                }
            }
        }
        let _ = fs::remove_dir(&old_container);
    }
    let old_conf = old_root.join("config.conf");
    let new_conf = new_root.join("patcher.conf");
    if old_conf.exists() && !new_conf.exists() {
        let _ = fs::rename(&old_conf, &new_conf);
    }
    let _ = fs::remove_dir(&old_root);
}

fn get_config_file_path() -> PathBuf {
    get_data_root_dir().join("patcher.conf")
}

// * 通过 macOS NSLocale.preferredLanguages 检测系统语言（图形界面启动同样生效）
unsafe fn detect_default_english() -> bool {
    unsafe {
        let cls = objc_getClass(c"NSLocale".as_ptr());
        if cls.is_null() {
            return false;
        }
        let f_obj: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
            std::mem::transmute(msg_send_ptr());
        let langs = f_obj(cls, sel_registerName(c"preferredLanguages".as_ptr()));
        if langs.is_null() {
            return false;
        }
        let f_count: unsafe extern "C" fn(*mut c_void, *mut c_void) -> usize =
            std::mem::transmute(msg_send_ptr());
        if f_count(langs, sel_registerName(c"count".as_ptr())) == 0 {
            return false;
        }
        let f_at: unsafe extern "C" fn(*mut c_void, *mut c_void, usize) -> *mut c_void =
            std::mem::transmute(msg_send_ptr());
        let first = f_at(langs, sel_registerName(c"objectAtIndex:".as_ptr()), 0);
        if first.is_null() {
            return false;
        }
        let f_utf8: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const c_char =
            std::mem::transmute(msg_send_ptr());
        let cstr = f_utf8(first, sel_registerName(c"UTF8String".as_ptr()));
        if cstr.is_null() {
            return false;
        }
        let bytes = CStr::from_ptr(cstr).to_bytes();
        !(bytes.len() >= 2
            && bytes[0].eq_ignore_ascii_case(&b'z')
            && bytes[1].eq_ignore_ascii_case(&b'h'))
    }
}

fn load_runtime_config() {
    let path = get_config_file_path();
    let Ok(content) = fs::read_to_string(path) else {
        OPT_LANG_EN.store(unsafe { detect_default_english() }, Ordering::Relaxed);
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

// * 2. 核心防闪退钩子：仅精准拦截 Telegram 的 Group Container，其余系统请求原样传递
unsafe extern "C" fn hooked_container_url(
    this: *mut c_void,
    sel: *mut c_void,
    group_id: *mut c_void,
) -> *mut c_void {
    let mut is_telegram_group = false;
    if !group_id.is_null() {
        unsafe {
            let f_utf8: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const c_char =
                std::mem::transmute(msg_send_ptr());
            let cstr = f_utf8(group_id, sel_registerName(c"UTF8String".as_ptr()));
            if !cstr.is_null() {
                let bytes = CStr::from_ptr(cstr).to_bytes();
                let needle = b"ru.keepcoder.Telegram";
                if bytes.windows(needle.len()).any(|w| w == needle) {
                    is_telegram_group = true;
                }
            }
        }
    }

    if !is_telegram_group {
        let orig = ORIG_CONTAINER_URL.load(Ordering::Acquire);
        if orig != 0 {
            unsafe {
                let f: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> *mut c_void =
                    std::mem::transmute(orig);
                return f(this, sel, group_id);
            }
        }
        return std::ptr::null_mut();
    }

    let container_dir = get_data_root_dir();
    let dir_str = container_dir.to_string_lossy();
    unsafe {
        let url_cls = objc_getClass(c"NSURL".as_ptr());
        let sel_url = sel_registerName(c"fileURLWithPath:isDirectory:".as_ptr());
        let f: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, i8) -> *mut c_void =
            std::mem::transmute(msg_send_ptr());
        let ns_path = make_nsstring(&dir_str);
        f(url_cls, sel_url, ns_path, 1)
    }
}

// * 3. 破除禁止截屏与录屏黑框限制
unsafe extern "C" fn hooked_set_sharing_type(
    this: *mut c_void,
    sel: *mut c_void,
    mut sharing_type: c_ulong,
) {
    if OPT_ALLOW_SCREENSHOT.load(Ordering::Relaxed) && sharing_type == 0 {
        sharing_type = 1;
    }
    let orig = ORIG_SET_SHARING_TYPE.load(Ordering::Acquire);
    if orig != 0 {
        unsafe {
            let f: unsafe extern "C" fn(*mut c_void, *mut c_void, c_ulong) =
                std::mem::transmute(orig);
            f(this, sel, sharing_type);
        }
    }
}

unsafe extern "C" fn hooked_sharing_type(this: *mut c_void, sel: *mut c_void) -> c_ulong {
    if OPT_ALLOW_SCREENSHOT.load(Ordering::Relaxed) {
        return 1;
    }
    let orig = ORIG_SHARING_TYPE.load(Ordering::Acquire);
    if orig != 0 {
        unsafe {
            let f: unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_ulong =
                std::mem::transmute(orig);
            return f(this, sel);
        }
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
    let orig = ORIG_SET_PROTECTED_CONTENT.load(Ordering::Acquire);
    if orig != 0 {
        unsafe {
            let f: unsafe extern "C" fn(*mut c_void, *mut c_void, i8) = std::mem::transmute(orig);
            f(this, sel, protected);
        }
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

// * 4. 启动期单线程 ARM64 指令修补（仅扫描 __text 代码节，杜绝运行时改写代码页触发崩溃）
struct AdPatchSpot {
    addr: usize,
    patch_insn: u32,
}

unsafe fn find_telegram_text_section() -> Option<(usize, usize, &'static [u32])> {
    unsafe {
        let count = _dyld_image_count();
        for i in 0..count {
            let name_ptr = _dyld_get_image_name(i);
            if name_ptr.is_null() {
                continue;
            }
            let name_bytes = CStr::from_ptr(name_ptr).to_bytes();
            if !name_bytes.ends_with(b"/MacOS/Telegram") {
                continue;
            }
            let base = _dyld_get_image_header(i) as usize;
            let ncmds = *((base + 16) as *const u32) as usize;
            let mut cur = base + 32;
            for _ in 0..ncmds {
                let cmd = *(cur as *const u32);
                let cmdsize = *((cur + 4) as *const u32) as usize;
                if cmd == 0x19 && cmdsize >= 72 {
                    let segname = std::slice::from_raw_parts((cur + 8) as *const u8, 16);
                    if segname.starts_with(b"__TEXT\0") {
                        let nsects = *((cur + 64) as *const u32) as usize;
                        let mut sec_cur = cur + 72;
                        for _ in 0..nsects {
                            if sec_cur + 80 > cur + cmdsize {
                                break;
                            }
                            let sectname = std::slice::from_raw_parts(sec_cur as *const u8, 16);
                            if sectname.starts_with(b"__text\0") {
                                let sec_size = *((sec_cur + 40) as *const u64) as usize;
                                let sec_off = *((sec_cur + 48) as *const u32) as usize;
                                let words = std::slice::from_raw_parts(
                                    (base + sec_off) as *const u32,
                                    sec_size / 4,
                                );
                                return Some((base, sec_off, words));
                            }
                            sec_cur += 80;
                        }
                    }
                }
                cur += cmdsize;
            }
        }
        None
    }
}

fn resolve_ad_patch_spots() -> Vec<AdPatchSpot> {
    let mut spots = Vec::new();
    let Some((base, sec_off, words)) = (unsafe { find_telegram_text_section() }) else {
        return spots;
    };

    // * 关卡 1: AdMessagesHistoryContextImpl.init 本地 5 分钟缓存广告分支 (b.le -> NOP)
    if let Some(idx) = words
        .windows(5)
        .position(|w| w[0] == 0x1e780108 && w[1] == 0x7104b108 && w[3] == 0x6b1b011f)
    {
        spots.push(AdPatchSpot {
            addr: base + sec_off + (idx + 4) * 4,
            patch_insn: 0xd503201f,
        });
    }

    // * 关卡 2: AdMessages 状态构建循环的广告数组长度 (ldr x27, [x19, #0x10] -> mov x27, #0)
    if let Some(idx) = words
        .windows(3)
        .position(|w| w[0] == 0xf9400a7b && w[1] == 0xd2800015 && w[2] == 0x92420b1c)
    {
        spots.push(AdPatchSpot {
            addr: base + sec_off + idx * 4,
            patch_insn: 0xd280001b,
        });
    }

    // * 关卡 3: AdMessagesHistoryContextImpl.activate 网络拉取广告入口 (tbz -> NOP)
    if let Some(idx) = words
        .windows(3)
        .position(|w| w[0] == 0x39420288 && (w[1] & 0xff00001f) == 0x36000008 && w[2] == 0xa9487bfd)
    {
        spots.push(AdPatchSpot {
            addr: base + sec_off + (idx + 1) * 4,
            patch_insn: 0xd503201f,
        });
    }

    spots
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

unsafe fn apply_startup_adblock_patches() {
    if !OPT_HIDE_SPONSORED.load(Ordering::Relaxed) {
        return;
    }
    for spot in resolve_ad_patch_spots() {
        unsafe { write_arm64_insn(spot.addr, spot.patch_insn) };
    }
}

unsafe extern "C" fn hooked_sponsored_layout(this: *mut c_void, sel: *mut c_void) {
    if !this.is_null()
        && let Some(map) = SPONSORED_ORIG_IMPS.get()
    {
        unsafe {
            let mut cur_cls = object_getClass(this);
            while !cur_cls.is_null() {
                let key = cur_cls as usize;
                if let Some(&(_, orig)) = map.iter().find(|&&(c, _)| c == key) {
                    let f: unsafe extern "C" fn(*mut c_void, *mut c_void) =
                        std::mem::transmute(orig);
                    f(this, sel);
                    break;
                }
                cur_cls = class_getSuperclass(cur_cls);
            }
        }
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

// * 5. 解除受限群组/频道的禁止选中限制（缓存 Ivar 偏移）
unsafe fn clear_disable_select_ability(instance: *mut c_void) {
    if instance.is_null() || !OPT_UNLOCK_COPY.load(Ordering::Relaxed) {
        return;
    }
    let offset = DISABLE_SELECT_IVAR_OFFSET.load(Ordering::Relaxed);
    if offset > 0 && offset < 4096 {
        unsafe {
            let field_ptr = (instance as *mut u8).offset(offset);
            *field_ptr = 0;
        }
    }
}

unsafe extern "C" fn hooked_chat_interaction_init(
    this: *mut c_void,
    sel: *mut c_void,
) -> *mut c_void {
    let orig = ORIG_CHAT_INTERACTION_INIT.load(Ordering::Acquire);
    let obj = if orig != 0 {
        unsafe {
            let f: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
                std::mem::transmute(orig);
            f(this, sel)
        }
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
    let orig = ORIG_CONTEXT_MENU_POPUP.load(Ordering::Acquire);
    if orig != 0 {
        unsafe {
            let f: unsafe extern "C" fn(
                *mut c_void,
                *mut c_void,
                *mut c_void,
                *mut c_void,
                *mut c_void,
            ) = std::mem::transmute(orig);
            f(this, sel, menu, event, view);
        }
    }
}

// * 6. 拦截 Sparkle 自动更新检查（支持运行时真热切换开关）
unsafe extern "C" fn hooked_sparkle_check(
    this: *mut c_void,
    sel: *mut c_void,
    sender: *mut c_void,
) {
    if OPT_DISABLE_SPARKLE.load(Ordering::Relaxed) {
        return;
    }
    let orig = ORIG_SPARKLE_CHECK.load(Ordering::Acquire);
    if orig != 0 {
        unsafe {
            let f: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) =
                std::mem::transmute(orig);
            f(this, sel, sender);
        }
    }
}

unsafe extern "C" fn hooked_sparkle_bg(this: *mut c_void, sel: *mut c_void) {
    if OPT_DISABLE_SPARKLE.load(Ordering::Relaxed) {
        return;
    }
    let orig = ORIG_SPARKLE_BG.load(Ordering::Acquire);
    if orig != 0 {
        unsafe {
            let f: unsafe extern "C" fn(*mut c_void, *mut c_void) = std::mem::transmute(orig);
            f(this, sel);
        }
    }
}

// * 7. 顶部系统菜单栏「⚡ 增强设置 / ⚡ Patcher」
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
    unsafe { set_menu_item_state(sender, next) };
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
                "Block Channel Sponsored Ads (Restart App)",
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
                "屏蔽频道官方赞助广告 (重启生效)",
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
unsafe extern "C" fn hooked_finish_launching(this: *mut c_void, sel: *mut c_void) {
    let orig = ORIG_FINISH_LAUNCHING.load(Ordering::Acquire);
    if orig != 0 {
        unsafe {
            let f: unsafe extern "C" fn(*mut c_void, *mut c_void) = std::mem::transmute(orig);
            f(this, sel);
        }
    }
    unsafe {
        ensure_patcher_menu_injected();
        refresh_all_windows_sharing_type();
    }
}

unsafe fn install_objc_hooks() {
    unsafe {
        // * 0. Hook NSFileManager.containerURLForSecurityApplicationGroupIdentifier:
        let fm_cls = objc_getClass(c"NSFileManager".as_ptr());
        if !fm_cls.is_null() {
            let m_url = class_getInstanceMethod(
                fm_cls,
                sel_registerName(c"containerURLForSecurityApplicationGroupIdentifier:".as_ptr()),
            );
            if !m_url.is_null() {
                ORIG_CONTAINER_URL
                    .store(method_getImplementation(m_url) as usize, Ordering::Release);
                method_setImplementation(m_url, hooked_container_url as *mut c_void);
            }
        }

        // * 1. Hook NSApplication.finishLaunching
        let app_cls = objc_getClass(c"NSApplication".as_ptr());
        if !app_cls.is_null() {
            let m = class_getInstanceMethod(app_cls, sel_registerName(c"finishLaunching".as_ptr()));
            if !m.is_null() {
                ORIG_FINISH_LAUNCHING
                    .store(method_getImplementation(m) as usize, Ordering::Release);
                method_setImplementation(m, hooked_finish_launching as *mut c_void);
            }
        }

        // * 2. Hook NSWindow 的 setSharingType: 与 sharingType
        let win_cls = objc_getClass(c"NSWindow".as_ptr());
        if !win_cls.is_null() {
            let m_set =
                class_getInstanceMethod(win_cls, sel_registerName(c"setSharingType:".as_ptr()));
            if !m_set.is_null() {
                ORIG_SET_SHARING_TYPE
                    .store(method_getImplementation(m_set) as usize, Ordering::Release);
                method_setImplementation(m_set, hooked_set_sharing_type as *mut c_void);
            }
            let m_get = class_getInstanceMethod(win_cls, sel_registerName(c"sharingType".as_ptr()));
            if !m_get.is_null() {
                ORIG_SHARING_TYPE
                    .store(method_getImplementation(m_get) as usize, Ordering::Release);
                method_setImplementation(m_get, hooked_sharing_type as *mut c_void);
            }
        }

        // * 3. Hook NSView.setAccessibilityProtectedContent:
        let view_cls = objc_getClass(c"NSView".as_ptr());
        if !view_cls.is_null() {
            let m_prot = class_getInstanceMethod(
                view_cls,
                sel_registerName(c"setAccessibilityProtectedContent:".as_ptr()),
            );
            if !m_prot.is_null() {
                ORIG_SET_PROTECTED_CONTENT
                    .store(method_getImplementation(m_prot) as usize, Ordering::Release);
                method_setImplementation(m_prot, hooked_set_protected_content as *mut c_void);
            }
        }

        // * 4. Hook _TtC6ChatUI15ChatInteraction.init（提前缓存 ivar 偏移）与 ContextMenu
        let chat_inter_cls = objc_getClass(c"_TtC6ChatUI15ChatInteraction".as_ptr());
        if !chat_inter_cls.is_null() {
            let ivar = class_getInstanceVariable(chat_inter_cls, c"disableSelectAbility".as_ptr());
            if !ivar.is_null() {
                DISABLE_SELECT_IVAR_OFFSET.store(ivar_getOffset(ivar), Ordering::Relaxed);
            }
            let m_init =
                class_getInstanceMethod(chat_inter_cls, sel_registerName(c"init".as_ptr()));
            if !m_init.is_null() {
                ORIG_CHAT_INTERACTION_INIT
                    .store(method_getImplementation(m_init) as usize, Ordering::Release);
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
                ORIG_CONTEXT_MENU_POPUP
                    .store(method_getImplementation(m_pop) as usize, Ordering::Release);
                method_setImplementation(m_pop, hooked_context_menu_popup as *mut c_void);
            }
        }

        // * 5. 始终 Hook Sparkle SUUpdater 并保存原实现，由原子开关控制实时放行或拦截
        let sparkle_cls = objc_getClass(c"SUUpdater".as_ptr());
        if !sparkle_cls.is_null() {
            let m1 = class_getInstanceMethod(
                sparkle_cls,
                sel_registerName(c"checkForUpdates:".as_ptr()),
            );
            if !m1.is_null() {
                ORIG_SPARKLE_CHECK.store(method_getImplementation(m1) as usize, Ordering::Release);
                method_setImplementation(m1, hooked_sparkle_check as *mut c_void);
            }
            let m2 = class_getInstanceMethod(
                sparkle_cls,
                sel_registerName(c"checkForUpdatesInBackground".as_ptr()),
            );
            if !m2.is_null() {
                ORIG_SPARKLE_BG.store(method_getImplementation(m2) as usize, Ordering::Release);
                method_setImplementation(m2, hooked_sparkle_bg as *mut c_void);
            }
        }

        // * 6. 动态匹配所有 ChatSponsoredView 并按类分别保存原始 layout 实现
        let mut class_count: u32 = 0;
        let classes = objc_copyClassList(&mut class_count);
        let mut sponsored_imps = Vec::new();
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
                        let orig = method_getImplementation(m_layout) as usize;
                        sponsored_imps.push((cls as usize, orig));
                        method_setImplementation(m_layout, hooked_sponsored_layout as *mut c_void);
                    }
                }
            }
            free(classes as *mut c_void);
        }
        let _ = SPONSORED_ORIG_IMPS.set(sponsored_imps);
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
    migrate_legacy_dir_if_needed();
    load_runtime_config();
    unsafe {
        apply_startup_adblock_patches();
        install_objc_hooks();
    }
}

#[used]
#[unsafe(link_section = "__DATA,__mod_init_func")]
pub static INIT_FUNC: unsafe extern "C" fn() = init_tg_patch;
