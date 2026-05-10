use block2::RcBlock;
use objc2::runtime::AnyObject;
use std::ffi::c_void;
use std::sync::Once;
use tokio::sync::broadcast;

#[link(name = "Network", kind = "framework")]
unsafe extern "C" {
    fn nw_path_monitor_create() -> *mut AnyObject;
    fn nw_path_monitor_set_update_handler(monitor: *mut AnyObject, handler: *mut c_void);
    fn nw_path_monitor_set_queue(monitor: *mut AnyObject, queue: *mut AnyObject);
    fn nw_path_monitor_start(monitor: *mut AnyObject);
    fn nw_path_monitor_cancel(monitor: *mut AnyObject);
}

#[link(name = "System", kind = "dylib")]
unsafe extern "C" {
    fn dispatch_get_global_queue(identifier: isize, flags: usize) -> *mut AnyObject;
}

static START: Once = Once::new();
static mut MONITOR: Option<*mut AnyObject> = None;
static mut BLOCK: Option<RcBlock<dyn Fn(*mut AnyObject)>> = None;

pub(crate) fn start_monitor(tx: broadcast::Sender<()>) -> Option<tokio::task::JoinHandle<()>> {
    unsafe {
        START.call_once(|| {
            let monitor = nw_path_monitor_create();
            if monitor.is_null() {
                tracing::error!("Failed to create NWPathMonitor");
                return;
            }
            MONITOR = Some(monitor);

            let queue = dispatch_get_global_queue(0x11, 0);
            nw_path_monitor_set_queue(monitor, queue);

            let block = RcBlock::new(move |_path: *mut AnyObject| {
                tracing::debug!("NWPathMonitor: Path changed");
                let _ = tx.send(());
            });

            let block_ptr = &*block as *const _ as *mut c_void;
            nw_path_monitor_set_update_handler(monitor, block_ptr);
            BLOCK = Some(block);
            nw_path_monitor_start(monitor);
            tracing::info!("NWPathMonitor started");
        });
    }

    None
}

pub(crate) fn stop_monitor() {
    unsafe {
        if let Some(monitor) = MONITOR {
            nw_path_monitor_cancel(monitor);
            MONITOR = None;
            BLOCK = None;
            tracing::info!("NWPathMonitor stopped");
        }
    }
}
