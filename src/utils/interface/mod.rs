use crate::utils::net_monitor::stop_network_monitor;
use anyhow::bail;
use default_net;
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::broadcast;
use tracing::{debug, error, info, trace};

use super::shutdown;

#[cfg(target_os = "macos")]
#[path = "platform_macos.rs"]
mod platform;
#[cfg(target_os = "windows")]
#[path = "platform_windows.rs"]
mod platform;
#[cfg(target_os = "linux")]
#[path = "platform_linux.rs"]
mod platform;
#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
#[path = "platform_other.rs"]
mod platform;

#[derive(Debug, Clone, Serialize)]
pub struct InterfaceInfo {
    pub index: u32,
    pub name: String,
    pub friendly_name: Option<String>,
    pub description: Option<String>,
    pub mac_addr: Option<String>,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub gateway: Option<String>,
    pub is_loopback: bool,
    pub is_up: bool,
    pub is_multicast: bool,
}

impl InterfaceInfo {
    pub fn display_name(&self) -> String {
        let friendly = self.friendly_name.as_deref().unwrap_or("");

        format!(
            "{} ({} {} {} {})",
            friendly,
            self.name,
            self.index.to_string(),
            self.gateway.as_deref().unwrap_or(""),
            self.is_usable(),
        )
    }

    pub fn has_ipv4(&self) -> bool {
        !self.ipv4.is_empty()
    }

    pub fn has_ipv6(&self) -> bool {
        !self.ipv6.is_empty()
    }

    pub fn is_usable(&self) -> bool {
        let ok = self.is_up && !self.is_loopback && (self.has_ipv4() || self.has_ipv6());
        #[cfg(windows)]
        {
            if ok {
                return self.gateway.is_some();
            }
        }
        return ok;
    }

    pub fn set_dns(&self, dns: &[IpAddr]) -> std::io::Result<()> {
        if dns.is_empty() {
            return self.restore_dns();
        }
        platform::set_dns(self, dns)
    }

    pub fn get_dns(&self) -> std::io::Result<Vec<IpAddr>> {
        platform::get_dns(self)
    }

    pub fn restore_dns(&self) -> std::io::Result<()> {
        platform::restore_dns(self)
    }

    pub fn set_metric(&self, metric: u32) -> std::io::Result<()> {
        #[cfg(windows)]
        {
            platform::set_metric(self, metric)
        }
        #[cfg(not(windows))]
        {
            let _ = metric;
            Ok(())
        }
    }
}

static DEFAULT_INTERFACE: RwLock<Option<Arc<InterfaceInfo>>> = RwLock::new(None);
static MONITOR_HANDLE: Mutex<Option<tokio::task::JoinHandle<()>>> = Mutex::new(None);
static NETWORK_CHANGE_TX: RwLock<Option<broadcast::Sender<()>>> = RwLock::new(None);

pub struct InterfaceManager;

impl InterfaceManager {
    fn notify_change() {
        if let Ok(guard) = NETWORK_CHANGE_TX.read() {
            if let Some(tx) = &*guard {
                let _ = tx.send(());
            }
        }
    }

    pub fn shutdown() {
        stop_network_monitor();
        if let Ok(mut lock) = MONITOR_HANDLE.lock() {
            if let Some(handle) = lock.take() {
                handle.abort();
                tracing::info!("Network monitor task aborted.");
            }
        }
    }

    pub fn list_ifaces() -> Vec<Arc<InterfaceInfo>> {
        let interfaces = default_net::get_interfaces();
        let list_ctx = platform::ListContext::new();

        interfaces
            .into_iter()
            .map(|iface| {
                let ipv4: Vec<String> = iface.ipv4.iter().map(|ip| ip.addr.to_string()).collect();
                let ipv6: Vec<String> = iface.ipv6.iter().map(|ip| ip.addr.to_string()).collect();

                let mac_addr = iface.mac_addr.as_ref().map(|mac| mac.to_string());
                let mut gateway = iface.gateway.as_ref().map(|gw| gw.ip_addr.to_string());

                let is_loopback = iface.is_loopback();
                let is_up = iface.is_up();
                let is_multicast = iface.is_multicast();

                #[allow(unused_mut)]
                let mut friendly_name = iface.friendly_name;

                platform::enhance_interface(
                    &list_ctx,
                    &iface.name,
                    &mut friendly_name,
                    &mut gateway,
                );

                Arc::new(InterfaceInfo {
                    index: iface.index,
                    name: iface.name,
                    friendly_name,
                    description: iface.description,
                    mac_addr,
                    ipv4,
                    ipv6,
                    gateway,
                    is_loopback,
                    is_up,
                    is_multicast,
                })
            })
            .collect()
    }

    pub fn init() {
        Self::update_iface();

        let (change_tx, _change_rx) = broadcast::channel(8);
        if let Ok(mut lock) = NETWORK_CHANGE_TX.write() {
            *lock = Some(change_tx);
        }

        let (handle, monitor_tx) = crate::utils::net_monitor::start_network_monitor();

        if let Some(h) = handle {
            if let Ok(mut lock) = MONITOR_HANDLE.lock() {
                *lock = Some(h);
            }
        }

        let mut rx = monitor_tx.subscribe();

        shutdown::spawn(async move {
            while let Ok(_) = rx.recv().await {
                Self::update_iface();
            }
        });
    }

    pub fn update_iface() {
        if let Some(iface) = Self::select_iface() {
            let mut writer = DEFAULT_INTERFACE.write().unwrap_or_else(|e| {
                tracing::error!("DEFAULT_INTERFACE RwLock poisoned: {:?}", e);
                e.into_inner()
            });

            let changed = match &*writer {
                Some(current) => current.index != iface.index,
                None => true,
            };

            if changed {
                info!(
                    "Selected iface: {} (IPv4: {:?}, IPv6: {:?}, DNS: {:?})",
                    iface.display_name(),
                    iface.ipv4,
                    iface.ipv6,
                    iface.get_dns()
                );
                *writer = Some(iface.clone());
                Self::notify_change();
            }
        } else {
            let mut writer = DEFAULT_INTERFACE.write().unwrap_or_else(|e| {
                tracing::error!("DEFAULT_INTERFACE RwLock poisoned: {:?}", e);
                e.into_inner()
            });
            if writer.is_some() {
                error!("Selected iface lost.");
                *writer = None;
                Self::notify_change();
            }
        }
    }

    pub fn selected_iface() -> Option<Arc<InterfaceInfo>> {
        DEFAULT_INTERFACE
            .read()
            .unwrap_or_else(|e| {
                tracing::error!("DEFAULT_INTERFACE RwLock poisoned: {:?}", e);
                e.into_inner()
            })
            .clone()
    }

    pub fn subscribe() -> Option<broadcast::Receiver<()>> {
        if let Ok(guard) = NETWORK_CHANGE_TX.read() {
            if let Some(tx) = &*guard {
                return Some(tx.subscribe());
            }
        }
        None
    }

    pub fn select_iface() -> Option<Arc<InterfaceInfo>> {
        let interfaces = Self::list_ifaces();
        debug!("found {} ifaces", interfaces.len());

        for iface in &interfaces {
            trace!("ifaces {:?}", iface.display_name());
            if !iface.is_usable() || Self::is_likely_vpn(&iface.name) {
                continue;
            }

            return Some(iface.clone());
        }

        None
    }

    fn is_likely_vpn(name: &str) -> bool {
        let n = name.to_lowercase();
        return n.contains("tun")
            || n.contains("tap")
            || n.contains("ppp")
            || n.contains("wg")
            || n.contains("ipsec")
            || n.contains("awdl")
            || n.contains("llw");
    }
}

pub fn resolve_iface(name: &str, addr: Option<Ipv4Addr>) -> anyhow::Result<Arc<InterfaceInfo>> {
    let a = match addr {
        Some(t) => t.to_string(),
        None => "".to_string(),
    };

    let interfaces = InterfaceManager::list_ifaces();

    for iface in interfaces {
        if iface.name == name || iface.ipv4.iter().any(|ip| ip != "" && ip == &a) {
            return Ok(iface);
        }
    }

    bail!("TUN interface not found by name={} or ipv4={}", name, a)
}
