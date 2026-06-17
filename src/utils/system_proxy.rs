#[allow(unused_imports)]
use crate::utils::new_io_other_error;
#[allow(unused_imports)]
use std::process::Command;
#[allow(unused_imports)]
use tracing::{info, warn};

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
        Self {
            service,
            host,
            port,
        }
    }
}

impl Drop for SystemProxyGuard {
    fn drop(&mut self) {
        if let Err(e) = set_system_proxy(&self.service, false, &self.host, self.port) {
            tracing::error!("Failed to disable system proxy: {}", e);
        }
    }
}
