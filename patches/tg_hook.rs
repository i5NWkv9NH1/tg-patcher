// * 纯 Rust 编写的 macOS 原生 Telegram 客户端注入动态库 (libtg_patch.dylib)
// * 提供顶部系统菜单栏「⚡ 增强设置」实时热切换、防截屏破除、去频道底部广告、解除受限群复制选中限制与屏蔽自动更新

use std::ffi::{CStr, CString, c_char, c_int, c_ulong, c_void};
use std::fs;
use std::path::PathBuf;
use std::sync::Once;
use std::sync::atomic::{AtomicBool, Ordering};

// * 1. 核心数据结构与几何类型定义

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CGPoint {
    pub x: f64,
    pub y: f64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CGSize {
    pub width: f64,
    pub height: f64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CGRect {
    pub origin: CGPoint,
    pub size: CGSize,
}

// * 2. 运行时热切换全局原子开关（默认全部开启，支持在顶部菜单栏实时切换并落盘）

static OPT_ALLOW_SCREENSHOT: AtomicBool = AtomicBool::new(true);
static OPT_HIDE_SPONSORED: AtomicBool = AtomicBool::new(true);
static OPT_UNLOCK_COPY: AtomicBool = AtomicBool::new(true);
static OPT_DISABLE_SPARKLE: AtomicBool = AtomicBool::new(true);
static OPT_LOCAL_PREMIUM_FLAG: AtomicBool = AtomicBool::new(false);

static MENU_INJECTED: Once = Once::new();

// * 3. Objective-C Runtime 与系统底层 C 接口声明

unsafe extern "C" {
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

// * 获取 objc_msgSend 函数指针，供不同签名按需转换
#[inline]
unsafe fn msg_send_ptr() -> *mut c_void {
    unsafe { dlsym(RTLD_DEFAULT, c"objc_msgSend".as_ptr()) }
}

// * 辅助函数：将 Rust 字符串转为 NSString 对象
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

// * 4. 本地配置文件读写（持久化保存菜单栏热切换状态）

fn get_config_file_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/Shared".to_string());
    let dir = PathBuf::from(format!(
        "{home}/Library/Application Support/TelegramPatcher"
    ));
    let _ = fs::create_dir_all(&dir);
    dir.join("config.conf")
}

fn load_runtime_config() {
    let path = get_config_file_path();
    let Ok(content) = fs::read_to_string(path) else {
        save_runtime_config();
        return;
    };
    for line in content.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let enabled = v.trim() == "1" || v.trim().eq_ignore_ascii_case("true");
        match k.trim() {
            "allow_screenshot" => OPT_ALLOW_SCREENSHOT.store(enabled, Ordering::Relaxed),
            "hide_sponsored" => OPT_HIDE_SPONSORED.store(enabled, Ordering::Relaxed),
            "unlock_copy" => OPT_UNLOCK_COPY.store(enabled, Ordering::Relaxed),
            "disable_sparkle" => OPT_DISABLE_SPARKLE.store(enabled, Ordering::Relaxed),
            "local_premium_flag" => OPT_LOCAL_PREMIUM_FLAG.store(enabled, Ordering::Relaxed),
            _ => {}
        }
    }
}

fn save_runtime_config() {
    let path = get_config_file_path();
    let body = format!(
        "allow_screenshot={}\nhide_sponsored={}\nunlock_copy={}\ndisable_sparkle={}\nlocal_premium_flag={}\n",
        usize::from(OPT_ALLOW_SCREENSHOT.load(Ordering::Relaxed)),
        usize::from(OPT_HIDE_SPONSORED.load(Ordering::Relaxed)),
        usize::from(OPT_UNLOCK_COPY.load(Ordering::Relaxed)),
        usize::from(OPT_DISABLE_SPARKLE.load(Ordering::Relaxed)),
        usize::from(OPT_LOCAL_PREMIUM_FLAG.load(Ordering::Relaxed)),
    );
    let _ = fs::write(path, body);
}

// * 5. 功能模块一：破除禁止截屏与录屏黑框限制 (NSWindow.sharingType & CaptureProtectedContentLayer)

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
    // ! NSWindowSharingNone = 0, NSWindowSharingReadOnly = 1
    // ! 开启「允许截屏」时，强制将 0 (禁止截屏) 改写为 1 (允许读写截屏)
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

// * 实时刷新当前已打开的所有 Telegram 窗口的截屏权限
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

// * 6. 功能模块二：屏蔽频道底部官方赞助商广告 (ChatSponsoredView)

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

// * 7. 功能模块三：解除受限群组/频道的禁止选中与右键菜单限制 (ChatInteraction & CopyProtectionRequestView)

static mut ORIG_CHAT_INTERACTION_INIT: Option<
    unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void,
> = None;
static mut ORIG_CONTEXT_MENU_POPUP: Option<
    unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void, *mut c_void),
> = None;

// * 将 ChatInteraction 实例内部的 disableSelectAbility 布尔成员变量清零
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
    // * 弹出右键菜单前触发一次顶层菜单栏注入检查
    unsafe { ensure_patcher_menu_injected() };
    if let Some(orig) = unsafe { ORIG_CONTEXT_MENU_POPUP } {
        unsafe { orig(this, sel, menu, event, view) };
    }
}

// * 8. 功能模块四：拦截 Sparkle 自动更新检查（防止后台自动更新冲掉补丁）

unsafe extern "C" fn noop_sparkle_check(
    _this: *mut c_void,
    _sel: *mut c_void,
    _sender: *mut c_void,
) {
}

unsafe extern "C" fn noop_sparkle_bg(_this: *mut c_void, _sel: *mut c_void) {}

// * 9. 顶部系统菜单栏「⚡ 增强设置」动态挂载与实时响应

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

unsafe fn create_checkable_item(
    title: &str,
    action_sel_name: *const c_char,
    target: *mut c_void,
    initial_state: bool,
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
        set_menu_item_state(item, initial_state);
        item
    }
}

// * 在 Telegram 顶部系统菜单栏挂载「⚡ 增强设置」下拉菜单
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
            // * 注册自定义 ObjC 菜单事件接收类 TGPatcherMenuHandler
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

            // * 创建顶层 NSMenuItem 与子菜单 NSMenu
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

            let item_ss = create_checkable_item(
                "强制允许截屏与录屏 (破除黑框)",
                c"toggleScreenshot:".as_ptr(),
                target_instance,
                OPT_ALLOW_SCREENSHOT.load(Ordering::Relaxed),
            );
            let item_ad = create_checkable_item(
                "屏蔽频道底部官方赞助广告",
                c"toggleSponsored:".as_ptr(),
                target_instance,
                OPT_HIDE_SPONSORED.load(Ordering::Relaxed),
            );
            let item_cp = create_checkable_item(
                "解除受限群文字选中与复制限制",
                c"toggleUnlockCopy:".as_ptr(),
                target_instance,
                OPT_UNLOCK_COPY.load(Ordering::Relaxed),
            );
            let item_sp = create_checkable_item(
                "拦截 Sparkle 自动更新弹窗",
                c"toggleDisableSparkle:".as_ptr(),
                target_instance,
                OPT_DISABLE_SPARKLE.load(Ordering::Relaxed),
            );

            f_add_item(sub_menu, sel_add, item_ss);
            f_add_item(sub_menu, sel_add, item_ad);
            f_add_item(sub_menu, sel_add, item_cp);
            f_add_item(sub_menu, sel_add, item_sp);

            // * 绑定子菜单并追加到 NSApp.mainMenu 末尾
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

// * 10. 钩子统一扫描与挂载入口

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
        // * 1. Hook NSApplication.finishLaunching 以挂载顶部「⚡ 增强设置」菜单
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

        // * 6. 动态遍历类列表，模糊匹配带有私密哈希的 ChatSponsoredView 并替换 layout
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
                // ! 忽略中间随版本变动的 P33_... 私有哈希，直接匹配前缀 _TtC6ChatUI 与后缀 ChatSponsoredView
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
    // ! 仅针对 Telegram 主进程生效，跳过 TelegramShare 等插件子进程
    if prog_bytes != b"Telegram" {
        return;
    }

    load_runtime_config();
    unsafe { install_objc_hooks() };

    // * 启动守护协程：在主界面加载完毕后兜底确保顶部菜单栏「⚡ 增强设置」成功显示
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_millis(1200));
        unsafe {
            ensure_patcher_menu_injected();
            refresh_all_windows_sharing_type();
        }
    });
}

// * 注册 Mach-O 构造函数入口
#[used]
#[unsafe(link_section = "__DATA,__mod_init_func")]
pub static INIT_FUNC: unsafe extern "C" fn() = init_tg_patch;
