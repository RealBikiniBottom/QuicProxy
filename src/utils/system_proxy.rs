#[allow(unused_imports)]
use crate::utils::new_io_other_error;
#[allow(unused_imports)]
use std::process::Command;
#[allow(unused_imports)]
use std::sync::Mutex;
#[allow(unused_imports)]
use tracing::{info, warn};

#[derive(Clone)]
struct ActiveSystemProxy {
    service: String,
    host: String,
    port: u16,
}

static ACTIVE_SYSTEM_PROXY: Mutex<Option<ActiveSystemProxy>> = Mutex::new(None);

#[cfg(target_os = "macos")]
pub fn set_system_proxy(service: &str, enable: bool, host: &str, port: u16) -> std::io::Result<()> {
    if enable {
        info!("Enabling system proxy for service: {}", service);
        let proxies = ["webproxy", "securewebproxy", "socksfirewallproxy"];

        for proxy_type in &proxies {
            let output = Command::new("networksetup")
                .arg(format!("-set{}", proxy_type))
                .arg(service)
                .arg(host)
                .arg(port.to_string())
                .output()?;

            if !output.status.success() {
                warn!(
                    "Failed to enable {}: {}",
                    proxy_type,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    } else {
        info!("Disabling system proxy for service: {}", service);
        let proxy_types = ["webproxy", "securewebproxy", "socksfirewallproxy"];

        for proxy_type in &proxy_types {
            let output = Command::new("networksetup")
                .arg(format!("-set{}state", proxy_type))
                .arg(service)
                .arg("off")
                .output()?;

            if !output.status.success() {
                warn!(
                    "Failed to disable {}: {}",
                    proxy_type,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }

    Ok(())
}

#[cfg(target_os = "windows")]
pub fn set_system_proxy(
    _service: &str,
    enable: bool,
    host: &str,
    port: u16,
) -> std::io::Result<()> {
    let hkcu = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

    if enable {
        info!("Enabling system proxy");
        let proxy_server = format!("{}:{}", host, port);

        // ProxyEnable = 1
        Command::new("reg")
            .args(&[
                "add",
                hkcu,
                "/v",
                "ProxyEnable",
                "/t",
                "REG_DWORD",
                "/d",
                "1",
                "/f",
            ])
            .output()?;

        // ProxyServer = host:port
        Command::new("reg")
            .args(&[
                "add",
                hkcu,
                "/v",
                "ProxyServer",
                "/t",
                "REG_SZ",
                "/d",
                &proxy_server,
                "/f",
            ])
            .output()?;

        // ProxyOverride = <local>
        Command::new("reg")
            .args(&[
                "add",
                hkcu,
                "/v",
                "ProxyOverride",
                "/t",
                "REG_SZ",
                "/d",
                "<local>",
                "/f",
            ])
            .output()?;
    } else {
        info!("Disabling system proxy");
        // ProxyEnable = 0
        Command::new("reg")
            .args(&[
                "add",
                hkcu,
                "/v",
                "ProxyEnable",
                "/t",
                "REG_DWORD",
                "/d",
                "0",
                "/f",
            ])
            .output()?;
    }

    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn set_system_proxy(
    _service: &str,
    _enable: bool,
    _host: &str,
    _port: u16,
) -> std::io::Result<()> {
    warn!("System proxy setting is not supported on this platform");
    Ok(())
}

pub struct SystemProxyGuard {
    service: String,
    host: String,
    port: u16,
}

impl SystemProxyGuard {
    pub fn new(service: String, host: String, port: u16) -> Self {
        remember_system_proxy(service.clone(), host.clone(), port);
        Self {
            service,
            host,
            port,
        }
    }
}

impl Drop for SystemProxyGuard {
    fn drop(&mut self) {
        disable_system_proxy(self.service.clone(), self.host.clone(), self.port, false);
    }
}

pub fn clear_system_proxy() {
    let proxy = {
        let mut lock = ACTIVE_SYSTEM_PROXY
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        lock.take()
    };

    if let Some(proxy) = proxy {
        disable_system_proxy(proxy.service, proxy.host, proxy.port, true);
    }
}

fn remember_system_proxy(service: String, host: String, port: u16) {
    let mut lock = ACTIVE_SYSTEM_PROXY
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    *lock = Some(ActiveSystemProxy {
        service,
        host,
        port,
    });
}

fn disable_system_proxy(service: String, host: String, port: u16, restore_on_failure: bool) {
    if let Err(e) = set_system_proxy(&service, false, &host, port) {
        tracing::error!("Failed to disable system proxy: {}", e);
        if restore_on_failure {
            remember_system_proxy(service, host, port);
        }
    } else {
        clear_matching_system_proxy(&service, &host, port);
    }
}

fn clear_matching_system_proxy(service: &str, host: &str, port: u16) {
    let mut lock = ACTIVE_SYSTEM_PROXY
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let should_clear = lock
        .as_ref()
        .map(|proxy| proxy.service == service && proxy.host == host && proxy.port == port)
        == Some(true);

    if should_clear {
        *lock = None;
    }
}
