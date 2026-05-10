use std::ptr;
use tokio::sync::broadcast;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::IpHelper::NotifyAddrChange;

pub(crate) fn start_monitor(tx: broadcast::Sender<()>) -> Option<tokio::task::JoinHandle<()>> {
    std::thread::spawn(move || {
        if let Err(e) = monitor_windows(tx) {
            tracing::error!("Network monitor failed: {}", e);
        }
    });
    None
}

pub(crate) fn stop_monitor() {}

fn monitor_windows(tx: broadcast::Sender<()>) -> std::io::Result<()> {
    loop {
        let mut handle: HANDLE = std::ptr::null_mut();
        let ret = unsafe { NotifyAddrChange(&mut handle, ptr::null_mut()) };

        if ret != 0 {
            return Err(std::io::Error::from_raw_os_error(ret as i32));
        }

        tracing::debug!("Network change detected (NotifyAddrChange)");
        let _ = tx.send(());
    }
}
