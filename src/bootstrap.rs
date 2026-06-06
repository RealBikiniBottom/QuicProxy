use crate::cache::{init_cache, shutdown_cache};
use crate::config::Config;
use crate::proxy::inbound::init_inbounds;
use crate::proxy::observe::init_observer;
use crate::proxy::outbound::init_outbounds;
use crate::proxy::router::geoip::init_geoip;
use crate::proxy::router::geoip_db::init_geoip_db;
use crate::proxy::router::init_router;
use crate::utils::interface::InterfaceManager;
use crate::utils::logging;
use crate::utils::shutdown;
use crate::{api::init_api, dns::init_dns};
use anyhow::{Context, Result};
use std::future::Future;
use tracing::{error, info};

pub async fn run_with_signal<F>(config: Config, signal: F) -> Result<()>
where
    F: Future<Output = Result<()>>,
{
    let (_reload_handle, _file_guard) = logging::init_logging(&config.log);
    std::mem::forget(_reload_handle);
    std::mem::forget(_file_guard);

    let _ = rustls::crypto::ring::default_provider().install_default();

    InterfaceManager::init();

    let mut shutdown_rx = init_app(config).await?;

    let api_shutdown = async {
        if let Some(ref mut rx) = shutdown_rx {
            rx.recv().await
        } else {
            std::future::pending().await
        }
    };

    info!("Init ok. Running...");

    tokio::select! {
        res = signal => {
            if let Err(e) = res {
                error!("Error waiting for signal: {}", e);
                return Err(e);
            }
            info!("Received external signal, shutting down...");
        }
        _ = api_shutdown => {
            info!("Received API shutdown signal, shutting down...");
        }
    }
    info!("Stopping inbound listeners...");

    InterfaceManager::shutdown();

    // 必须在 abort 任务之前关闭缓存数据库，确保 redb 文件锁释放
    shutdown_cache();

    shutdown::abort_all_and_wait().await;

    info!("All Exited.");
    Ok(())
}

pub async fn init_app(mut config: Config) -> Result<Option<tokio::sync::mpsc::Receiver<()>>> {
    init_cache(&config).context("Failed to init cache")?;

    init_observer(&config).context("Failed to init observer")?;

    init_outbounds(&config).context("Failed to init outbounds")?;

    init_dns(&config).context("Failed to init dns")?;

    init_geoip_db(&config)
        .await
        .context("Failed to init geoip db")?;

    init_geoip(&config).await.context("Failed to init geoip")?;

    init_router(&config).context("Failed to init router")?;

    init_inbounds(&config).context("Failed to init inbounds")?;

    init_api(&mut config).await.context("Failed to init API")
}
