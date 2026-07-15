use crate::utils::net_monitor::stop_network_monitor;
use anyhow::bail;
use netdev;
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

pub type InterfaceInfo = netdev::Interface;

pub trait InterfaceInfoExt {
    fn display_name(&self) -> String;
    fn is_usable(&self) -> bool;
    fn set_dns(&self, dns: &[IpAddr]) -> std::io::Result<()>;
    fn get_dns(&self) -> std::io::Result<Vec<IpAddr>>;
    fn restore_dns(&self) -> std::io::Result<()>;
    fn set_metric(&self, metric: u32) -> std::io::Result<()>;
}

impl InterfaceInfoExt for netdev::Interface {
    fn display_name(&self) -> String {
        let friendly = self.friendly_name.as_deref().unwrap_or("");
        format!(
            "{} {} Index: {} Gateway: {:?}, IPv4: {:?}, IPv6: {:?}, DNS: {:?}, Default: {:?}, Usable: {}",
            friendly,
            self.name,
            self.index,
            self.gateway,
            self.ipv4,
            self.ipv6,
            self.dns_servers,
            self.default,
            self.is_usable(),
        )
    }

    fn is_usable(&self) -> bool {
        let ok = self.is_up()
            && !self.is_loopback()
            && (self.has_ipv4() || self.has_ipv6())
            && !self.is_tun()
            && self.is_physical()
            && self.is_running();

        #[cfg(any(target_os = "windows", target_os = "macos"))]
        {
            if ok {
                return self.gateway.is_some();
            }
        }

        ok
    }

    fn set_dns(&self, dns: &[IpAddr]) -> std::io::Result<()> {
        if dns.is_empty() {
            return self.restore_dns();
        }
        platform::set_dns(self, dns)
    }

    fn get_dns(&self) -> std::io::Result<Vec<IpAddr>> {
        Ok(self.dns_servers.clone())
    }

    fn restore_dns(&self) -> std::io::Result<()> {
        platform::restore_dns(self)
    }

    fn set_metric(&self, metric: u32) -> std::io::Result<()> {
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

static DEFAULT_INTERFACE: RwLock<Option<Arc<netdev::Interface>>> = RwLock::new(None);
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

    pub fn list_ifaces() -> Vec<Arc<netdev::Interface>> {
        let mut interfaces = netdev::get_interfaces();
        interfaces.sort_by_key(|iface| !iface.default);
        interfaces.into_iter().map(Arc::new).collect()
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
                    "Selected iface: {}",iface.display_name(),
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

    pub fn selected_iface() -> Option<Arc<netdev::Interface>> {
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

    pub fn select_iface() -> Option<Arc<netdev::Interface>> {
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

pub fn resolve_iface(name: &str, addr: Option<Ipv4Addr>) -> anyhow::Result<Arc<netdev::Interface>> {
    let a = match addr {
        Some(t) => t.to_string(),
        None => "".to_string(),
    };

    let interfaces = InterfaceManager::list_ifaces();

    for iface in interfaces {
        if iface.name == name || iface.ipv4.iter().any(|net| net.addr().to_string() == a) {
            return Ok(iface);
        }
    }

    bail!("TUN interface not found by name={} or ipv4={}", name, a)
}
