pub mod anytls;
pub mod http;
pub mod mix;
pub mod shadowquic;
pub mod socks5;
pub mod trojan;

#[cfg(feature = "premium")]
pub use crate::premium::tun;
#[cfg(feature = "premium")]
use crate::premium::tun::tun::TunInbound;

use crate::config::Config;
use crate::proxy::inbound::anytls::AnytlsInbound;
use crate::proxy::inbound::http::HttpInbound;
use crate::proxy::inbound::mix::MixInbound;
use crate::proxy::inbound::shadowquic::ShadowQuicInbound;
use crate::proxy::inbound::socks5::Socks5Inbound;
use crate::proxy::inbound::trojan::TrojanInbound;
use crate::proxy::observe::get_observer;
use crate::utils::interface::InterfaceManager;
use crate::utils::shutdown;
use crate::utils::system_proxy::{SystemProxyGuard, set_system_proxy};
use anyhow::bail;
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::error;

pub fn init_inbounds(cfg: &Config) -> anyhow::Result<()> {
    for (name, item) in cfg.inbounds.iter() {
        let protocol = item.protocol_type.clone().to_lowercase();
        let name_clone = name.clone();

        let inbound: Arc<dyn AnyInbound> = match protocol.as_str() {
            "shadowquic" => Arc::new(ShadowQuicInbound::new(name_clone, item)?),
            "socks5" => Arc::new(Socks5Inbound::new(name_clone, item)?),
            "http" => Arc::new(HttpInbound::new(name_clone, item)?),
            "mix" => Arc::new(MixInbound::new(name_clone, item)?),
            "trojan" => Arc::new(TrojanInbound::new(name_clone, item)?),
            "anytls" => Arc::new(AnytlsInbound::new(name_clone, item)?),
            #[cfg(feature = "premium")]
            "tun" => Arc::new(TunInbound::new(name_clone, item)),
            #[cfg(not(feature = "premium"))]
            "tun" => {
                bail!("TUN support is not compiled in. Enable the 'premium' feature to use TUN.")
            }
            _ => {
                bail!("Unknown inbound type: {}", protocol)
            }
        };

        if let Some(observer) = get_observer() {
            observer.register_inbound(name, inbound.protocol());
        }

        let name_for_log = name.clone();
        shutdown::spawn(async move {
            if let Err(e) = inbound.listen().await {
                error!(
                    "Inbound '{}' error: {:?}",
                    name_for_log,
                    anyhow::Error::from(e)
                );
                std::process::exit(1);
            }
        });
    }

    Ok(())
}

/// 创建TCP监听器，支持IPv4/IPv6双栈
pub async fn create_tcp_listener(addr: SocketAddr) -> anyhow::Result<TcpListener> {
    let socket = socket2::Socket::new(
        if addr.is_ipv6() {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        },
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;

    if addr.is_ipv6() {
        socket.set_only_v6(false)?;
    }
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;

    let listener = TcpListener::from_std(socket.into())?;
    Ok(listener)
}

/// 设置系统代理（如果启用），返回代理Guard
pub fn setup_system_proxy(
    set_proxy: bool,
    address: &str,
    port: u16,
) -> anyhow::Result<Option<SystemProxyGuard>> {
    if !set_proxy {
        return Ok(None);
    }

    let host = if address == "0.0.0.0" || address == "::" {
        "127.0.0.1"
    } else {
        address
    };

    let service = InterfaceManager::selected_iface()
        .and_then(|iface| iface.friendly_name.clone())
        .unwrap_or_default();

    if let Err(e) = set_system_proxy(&service, true, host, port) {
        error!("Failed to enable system proxy: {}", e);
        Ok(None)
    } else {
        Ok(Some(SystemProxyGuard::new(service, host.to_string(), port)))
    }
}

#[async_trait]
pub trait AnyInbound: Send + Sync {
    fn protocol(&self) -> &str;

    fn idle_timeout(&self) -> Duration;

    async fn listen(&self) -> anyhow::Result<()>;
}
