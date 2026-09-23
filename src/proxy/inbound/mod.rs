pub mod anytls;
pub mod http;
pub mod mix;
pub mod shadowquic;
pub mod socks5;
pub mod trojan;
pub mod vmess;

#[cfg(feature = "premium")]
pub use crate::premium::tun;
#[cfg(feature = "premium")]
use crate::premium::tun::tun::TunInbound;

use crate::config::{AuthUser, Config};
use crate::proxy::inbound::anytls::AnytlsInbound;
use crate::proxy::inbound::http::HttpInbound;
use crate::proxy::inbound::mix::MixInbound;
use crate::proxy::inbound::shadowquic::ShadowQuicInbound;
use crate::proxy::inbound::socks5::Socks5Inbound;
use crate::proxy::inbound::trojan::TrojanInbound;
use crate::proxy::inbound::vmess::VmessInbound;
use crate::proxy::observe::get_observer;
use crate::utils::interface::InterfaceManager;
use crate::utils::shutdown;
pub use crate::utils::socket::socket_helpers::try_create_dualstack_tcplistener as create_tcp_listener;
use crate::utils::system_proxy::{SystemProxyGuard, set_system_proxy};
use anyhow::bail;
use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tracing::error;

pub fn init_inbounds(cfg: &Config) -> anyhow::Result<()> {
    let observer = get_observer();
    for (name, item) in cfg.inbounds.iter() {
        let protocol = item.protocol_type.clone().to_lowercase();
        let name_clone = name.clone();
        let mut merged_users = item.merged_auth_users(&cfg.users);
        if let Some(observer) = &observer {
            for user in observer.persisted_users() {
                if merged_users.iter().any(|u| u.username == user.username) {
                    continue;
                }
                if crate::proxy::observe::credential_hash(&protocol, &user.username, &user.password)
                    .is_ok()
                {
                    merged_users.push(user);
                }
            }
        }

        let inbound: Arc<dyn AnyInbound> = match protocol.as_str() {
            "shadowquic" => Arc::new(ShadowQuicInbound::new(
                name_clone,
                item,
                merged_users.clone(),
            )?),
            "socks5" => Arc::new(Socks5Inbound::new(name_clone, item)?),
            "http" => Arc::new(HttpInbound::new(name_clone, item)?),
            "mix" => Arc::new(MixInbound::new(name_clone, item)?),
            "trojan" => Arc::new(TrojanInbound::new(name_clone, item, merged_users.clone())?),
            "anytls" => Arc::new(AnytlsInbound::new(name_clone, item, merged_users.clone())?),
            "vmess" => Arc::new(VmessInbound::new(name_clone, item, merged_users.clone())?),
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

        register_inbound(name, inbound.clone());

        if let Some(observer) = &observer {
            observer.register_inbound(name, inbound.protocol());
            if inbound.supports_users() {
                for user in &merged_users {
                    observer.upsert_user(&user.username);
                    observer.set_user_password(&user.username, &user.password);
                    if let Ok(credential) =
                        crate::proxy::observe::credential_hash(inbound.protocol(), &user.username, &user.password)
                    {
                        observer.set_user_credential(name, &user.username, credential);
                    }
                }
            }
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

    /// Whether this inbound keeps its own user list that must be refreshed when
    /// users are added or removed at runtime.
    fn supports_users(&self) -> bool {
        false
    }

    /// Add or update a user on this inbound at runtime.
    async fn add_user(&self, _user: &AuthUser) -> anyhow::Result<()> {
        Ok(())
    }

    /// Remove a user from this inbound at runtime.
    async fn remove_user(&self, _username: &str) -> anyhow::Result<()> {
        Ok(())
    }
}

static INBOUNDS: LazyLock<DashMap<String, Arc<dyn AnyInbound>>> = LazyLock::new(DashMap::new);

pub fn register_inbound(tag: &str, inbound: Arc<dyn AnyInbound>) {
    INBOUNDS.insert(tag.to_string(), inbound);
}

pub fn shutdown_inbounds() {
    INBOUNDS.clear();
}

/// Apply a user change to every inbound that supports user management.
pub async fn apply_user_change(user: &AuthUser, remove: bool) -> anyhow::Result<()> {
    let targets: Vec<(String, Arc<dyn AnyInbound>)> = INBOUNDS
        .iter()
        .filter(|e| e.value().supports_users())
        .map(|e| (e.key().clone(), e.value().clone()))
        .collect();
    for (tag, inbound) in &targets {
        let result = if remove {
            inbound.remove_user(&user.username).await
        } else {
            inbound.add_user(user).await
        };
        if let Err(e) = result {
            anyhow::bail!("apply user to inbound '{}' failed: {}", tag, e);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::create_tcp_listener;
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn unspecified_ipv6_listener_accepts_both_ip_families() {
        let listener = create_tcp_listener("[::]:0".parse().unwrap()).unwrap();
        let port = listener.local_addr().unwrap().port();

        TcpStream::connect(("::1", port)).await.unwrap();
        TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    }

    #[tokio::test]
    async fn unspecified_ipv4_listener_stays_ipv4() {
        let listener = create_tcp_listener("0.0.0.0:0".parse().unwrap()).unwrap();

        assert!(listener.local_addr().unwrap().is_ipv4());
    }
}
