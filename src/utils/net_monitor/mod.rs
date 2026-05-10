use tokio::sync::broadcast;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux::{start_monitor as start_platform_monitor, stop_monitor as stop_platform_monitor};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos::{start_monitor as start_platform_monitor, stop_monitor as stop_platform_monitor};

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows::{start_monitor as start_platform_monitor, stop_monitor as stop_platform_monitor};

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn start_platform_monitor(_: broadcast::Sender<()>) -> Option<tokio::task::JoinHandle<()>> {
    None
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn stop_platform_monitor() {}

pub fn start_network_monitor() -> (Option<tokio::task::JoinHandle<()>>, broadcast::Sender<()>) {
    let (tx, _) = broadcast::channel(8);
    let handle = start_platform_monitor(tx.clone());
    (handle, tx)
}

pub fn stop_network_monitor() {
    stop_platform_monitor();
}
