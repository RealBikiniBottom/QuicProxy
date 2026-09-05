//! quicproxy 桌面端入口
//!
//! 两种运行模式：
//! 1. 核心模式（默认）：`quicproxy -c config.json` — 运行代理核心
//! 2. 管理模式：`quicproxy --manage --port 8080` — 管理服务器，可启停核心

use anyhow::{Context, Result};
use axum::{Router, response::Json, routing::get};
use clap::Parser;
use quicproxy::bootstrap;
use quicproxy::config::Config;
use quicproxy::utils::elevate::{self, ElevateConfig};
use quicproxy::{
    api::{
        common::cors_middleware,
        core_manager::CoreManager,
        management::{self, ManagementState},
        persist_handler::{self, PersistHandlerState},
        persist_store::PersistStore,
        static_files,
    },
    proxy::inbound::create_tcp_listener,
};
use serde_json::json;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process;
use tracing::info;

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "snmalloc")]
#[global_allocator]
static GLOBAL: snmalloc_rs::SnMalloc = snmalloc_rs::SnMalloc;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    config: Option<PathBuf>,

    #[arg(long)]
    elevate: bool,

    #[arg(long)]
    elevate_no_show_window: bool,

    #[arg(long)]
    manage: bool,

    #[arg(long, default_value = "::")]
    host: String,

    #[arg(long, default_value = "8080")]
    port: u16,

    #[arg(long)]
    core_path: Option<String>,

    #[arg(long)]
    work_dir: Option<PathBuf>,

    #[arg(long, default_value = "persist.json")]
    persist_file: String,

    #[arg(long, default_value = "")]
    password: String,

    #[arg(long)]
    web_dir: Option<PathBuf>,
}

fn main() -> Result<()> {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();

    let runtime = builder.build().context("Failed to build tokio runtime")?;
    runtime.block_on(async_main())
}

async fn async_main() -> Result<()> {
    let args = Args::parse();

    if args.manage {
        return run_manage(args).await;
    }

    if args.elevate {
        if !elevate::is_elevated() {
            eprintln!("Requesting administrator privileges...");

            let elevate_config = ElevateConfig {
                prompt_title: "QuicProxy".to_string(),
                prompt_message:
                    "QuicProxy requires administrator privileges to configure network interfaces."
                        .to_string(),
                show_window: !args.elevate_no_show_window,
                preserve_env_vars: vec![
                    "PATH".to_string(),
                    "HOME".to_string(),
                    "USER".to_string(),
                    "RUST_LOG".to_string(),
                    "RUST_BACKTRACE".to_string(),
                ],
                ..ElevateConfig::default()
            };

            let program_args = elevate::reconstruct_args();

            let executable =
                elevate::current_executable().context("Failed to get current executable path")?;
            if let Err(e) = elevate::elevate_command(
                executable.to_str().unwrap_or(""),
                &program_args,
                &elevate_config,
            ) {
                eprintln!("Failed to elevate privileges: {:#}", e);
                process::exit(1);
            }

            return Ok(());
        }
    }

    let config = match Config::load(args.config) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Error loading configuration:");
            eprintln!("  {:#}", e);
            process::exit(1);
        }
    };

    if elevate::is_elevated() {
        info!("Running with elevated privileges");
    } else {
        info!("Running without elevated privileges");
    }

    if let Err(e) = bootstrap::run_with_signal(config, async {
        info!("Proxy started. Press Ctrl-C to stop.");
        let _ = tokio::signal::ctrl_c().await;
        Ok(())
    })
    .await
    {
        eprintln!("Application error: {:#}", e);
        process::exit(1);
    }

    Ok(())
}

async fn run_manage(args: Args) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "quicproxy=info".into()))
        .with_file(true)
        .with_line_number(true)
        .with_target(false)
        .without_time()
        .init();

    let current_executable = std::env::current_exe().ok();

    let work_dir = args.work_dir.unwrap_or_else(|| {
        current_executable
            .as_ref()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."))
    });

    let core_path = args.core_path.unwrap_or_else(|| {
        current_executable
            .as_ref()
            .and_then(|p| p.to_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "./quicproxy".to_string())
    });

    let persist_path = work_dir.join(&args.persist_file);
    let persist_path_display = persist_path.display().to_string();
    let persist_store = PersistStore::new(Some(persist_path));
    let core_manager = CoreManager::new(core_path.clone(), work_dir.clone());

    let core_path_display = core_manager.status().core_path;
    let work_dir_display = core_manager.status().work_dir;
    let web_dir = args.web_dir.clone();

    let mgmt_router = management::router().with_state(ManagementState {
        core_manager: core_manager.clone(),
        password: args.password.clone(),
    });

    let persist_router = persist_handler::router().with_state(PersistHandlerState {
        persist_store: persist_store.clone(),
        password: args.password.clone(),
    });

    let cm = core_manager.clone();
    let ps = persist_store.clone();
    let health_route = Router::new().route(
        "/api/health",
        get(move || async move {
            let status = cm.status();
            Json(json!({
                "status": "ok",
                "persist_entries": ps.len(),
                "core_running": status.running,
                "core_pid": status.pid,
            }))
        }),
    );

    let core_api_router = Router::new()
        .merge(mgmt_router)
        .merge(persist_router)
        .merge(health_route);

    let app = if let Some(ref dir) = web_dir {
        core_api_router
            .merge(static_files::spa_router(dir.clone())?)
            .layer(axum::middleware::from_fn(cors_middleware))
    } else {
        core_api_router.layer(axum::middleware::from_fn(cors_middleware))
    };

    let addr = SocketAddr::new(args.host.parse::<IpAddr>()?, args.port);
    let listener = create_tcp_listener(addr)?;

    info!("Manage server listening on {}", addr);
    info!("core_path: {}", core_path_display);
    info!("work_dir: {}", work_dir_display);
    info!("persist file: {}", persist_path_display);
    if let Some(ref dir) = web_dir {
        info!("web_dir: {}", dir.display());
    }

    axum::serve(listener, app).await?;
    Ok(())
}
