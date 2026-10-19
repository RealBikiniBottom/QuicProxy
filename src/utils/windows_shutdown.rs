//! Graceful shutdown on Windows: console close / logoff / shutdown events and the
//! session-end window messages become a shutdown request, and the process is kept
//! alive until cleanup finishes, because Windows terminates it as soon as the
//! handler returns.
//!
//! Two paths are needed. Console processes get `CTRL_*_EVENT` through
//! `SetConsoleCtrlHandler`, but not `CTRL_LOGOFF_EVENT`/`CTRL_SHUTDOWN_EVENT` once
//! user32.dll is loaded, and a process started without a console gets no console
//! events at all; those only see `WM_QUERYENDSESSION`/`WM_ENDSESSION`, delivered to
//! top-level windows, so a hidden one is created for them.

use std::sync::{Condvar, LazyLock, Mutex, Once};
use std::time::Duration;
use tokio::sync::Notify;
use tracing::{info, warn};
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::Console::{
    CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
    SetConsoleCtrlHandler,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, MSG, RegisterClassW,
    TranslateMessage, WM_ENDSESSION, WM_QUERYENDSESSION, WNDCLASSW,
};
use windows_sys::core::BOOL;

/// Windows gives a console handler about 5 s for close/logoff/shutdown and a
/// window about 5 s after `WM_ENDSESSION`; stay under that so the cleanup that did
/// finish is not cut off mid-write.
const CLEANUP_BUDGET: Duration = Duration::from_millis(4500);

static INSTALL: Once = Once::new();
static REQUESTED: LazyLock<Notify> = LazyLock::new(Notify::new);
static DONE: LazyLock<(Mutex<bool>, Condvar)> =
    LazyLock::new(|| (Mutex::new(false), Condvar::new()));

/// Resolves on Ctrl-C/Ctrl-Break, console close, logoff or system shutdown.
pub async fn wait_for_exit_signal() {
    INSTALL.call_once(install);
    REQUESTED.notified().await;
}

/// Lets a blocked close/logoff/shutdown handler return; call once cleanup is done.
pub fn notify_cleanup_done() {
    let (done, cvar) = &*DONE;
    *done.lock().unwrap_or_else(|e| e.into_inner()) = true;
    cvar.notify_all();
}

fn install() {
    // SAFETY: registers a plain `extern "system"` function that lives for the whole process.
    if unsafe { SetConsoleCtrlHandler(Some(console_handler), 1) } == 0 {
        warn!(
            "SetConsoleCtrlHandler failed: {}",
            std::io::Error::last_os_error()
        );
    }
    if let Err(e) = std::thread::Builder::new()
        .name("session-end".into())
        .spawn(run_session_end_window)
    {
        warn!("Failed to start session-end listener: {e}");
    }
}

fn request_and_wait(reason: &str) {
    info!("Received {reason}");
    REQUESTED.notify_one();
    let (done, cvar) = &*DONE;
    let guard = done.lock().unwrap_or_else(|e| e.into_inner());
    let (guard, timeout) = cvar
        .wait_timeout_while(guard, CLEANUP_BUDGET, |done| !*done)
        .unwrap_or_else(|e| e.into_inner());
    if timeout.timed_out() && !*guard {
        warn!("Cleanup did not finish within {CLEANUP_BUDGET:?}, letting Windows end the process");
    }
}

unsafe extern "system" fn console_handler(ctrl_type: u32) -> BOOL {
    match ctrl_type {
        // The process keeps running after these, so no need to block here.
        CTRL_C_EVENT | CTRL_BREAK_EVENT => {
            info!("Received Ctrl-C");
            REQUESTED.notify_one();
        }
        CTRL_CLOSE_EVENT => request_and_wait("console close"),
        CTRL_LOGOFF_EVENT => request_and_wait("logoff"),
        CTRL_SHUTDOWN_EVENT => request_and_wait("system shutdown"),
        _ => return 0,
    }
    1
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        // Never veto the session end.
        WM_QUERYENDSESSION => 1,
        WM_ENDSESSION => {
            if wparam != 0 {
                request_and_wait("session end");
            }
            0
        }
        // SAFETY: forwarding the arguments we were called with.
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

fn run_session_end_window() {
    let class_name: Vec<u16> = "QuicProxySessionEnd\0".encode_utf16().collect();
    // SAFETY: plain Win32 calls; every pointer passed is valid for the call, and the
    // class name outlives the window because this thread never returns while it exists.
    unsafe {
        let instance = GetModuleHandleW(std::ptr::null());
        let class = WNDCLASSW {
            style: 0,
            lpfnWndProc: Some(window_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: instance,
            hIcon: std::ptr::null_mut(),
            hCursor: std::ptr::null_mut(),
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null(),
            lpszClassName: class_name.as_ptr(),
        };
        if RegisterClassW(&class) == 0 {
            warn!(
                "RegisterClassW failed: {}",
                std::io::Error::last_os_error()
            );
            return;
        }
        // A hidden top-level window, not a message-only one (HWND_MESSAGE): message-only
        // windows do not receive the WM_QUERYENDSESSION/WM_ENDSESSION broadcast.
        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            class_name.as_ptr(),
            0,
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            instance,
            std::ptr::null(),
        );
        if hwnd.is_null() {
            warn!(
                "CreateWindowExW failed: {}",
                std::io::Error::last_os_error()
            );
            return;
        }
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}
