use crate::cache::{init_cache, shutdown_cache};
use crate::config::Config;
use crate::proxy::inbound::init_inbounds;
use crate::proxy::observe::{init_observer, shutdown_observer};
use crate::proxy::outbound::{init_outbounds, shutdown_outbounds};
use crate::proxy::router::geoip::{init_geoip, shutdown_geoip};
use crate::proxy::router::geoip_db::{init_geoip_db, shutdown_geoip_db};
use crate::proxy::router::{init_router, shutdown_router};
use crate::utils::interface::InterfaceManager;
use crate::utils::logging;
use crate::utils::shutdown;
use crate::{
    api::init_core_api,
    dns::{init_dns, shutdown_dns},
};
use anyhow::{Context, Result};
use std::future::Future;
use tracing::{debug, error, info};

pub async fn run_with_signal<F>(config: Config, signal: F) -> Result<()>
where
    F: Future<Output = Result<()>>,
{
    let (_reload_handle, _file_guard) = logging::init_logging(&config.log);
    std::mem::forget(_reload_handle);
    std::mem::forget(_file_guard);

    let _ = rustls::crypto::ring::default_provider().install_default();

    InterfaceManager::init();

    let mut shutdown_rx = match init_app(config).await {
        Ok(shutdown_rx) => shutdown_rx,
        Err(error) => {
            // Initialization can fail after some global components have already been installed.
            // Tear them down so a later Android start can retry in the same process.
            shutdown_app().await;
            return Err(error);
        }
    };

    let api_shutdown = async {
        if let Some(ref mut rx) = shutdown_rx {
            rx.recv().await
        } else {
            std::future::pending().await
        }
    };

    info!("Init ok. Running...");

    let run_result = tokio::select! {
        res = signal => {
            if let Err(e) = res {
                error!("Error waiting for signal: {}", e);
                Err(e)
            } else {
                info!("Received external signal, shutting down...");
                Ok(())
            }
        }
        _ = api_shutdown => {
            info!("Received API shutdown signal, shutting down...");
            Ok(())
        }
    };
    info!("Stopping inbound listeners...");

    shutdown_app().await;

    run_result?;

    info!("All Exited.");
    Ok(())
}

pub async fn shutdown_app() {
    InterfaceManager::shutdown();

    shutdown::abort_all_and_wait().await;

    shutdown_router();
    shutdown_dns();
    shutdown_geoip();
    shutdown_geoip_db();
    shutdown_outbounds();
    shutdown_observer();
    shutdown_cache();
}

pub async fn init_app(mut config: Config) -> Result<Option<tokio::sync::mpsc::Receiver<()>>> {
    init_cache(&config).context("Failed to init cache")?;
    debug!("init_cache");

    init_observer(&config).context("Failed to init observer")?;
    debug!("init_observer");

    init_outbounds(&config).context("Failed to init outbounds")?;
    debug!("init_outbounds");

    init_dns(&config).context("Failed to init dns")?;
    debug!("init_dns");

    init_geoip_db(&config)
        .await
        .context("Failed to init geoip db")?;
    debug!("init_geoip_db");

    init_geoip(&config).await.context("Failed to init geoip")?;
    debug!("init_geoip");

    init_router(&config).context("Failed to init router")?;
    debug!("init_router");

    init_inbounds(&config).context("Failed to init inbounds")?;
    debug!("init_inbounds");

    init_core_api(&mut config)
        .await
        .context("Failed to init API")
}
