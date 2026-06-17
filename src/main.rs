//! quicproxy 入口
//!
//! 两种运行模式：
//! 1. 核心模式（默认）：`quicproxy -c config.json` — 运行代理核心
//! 2. 管理模式：`quicproxy --manage --port 8080` — 管理服务器，可启停核心

use anyhow::{Context, Result};
use axum::{Router, extract::State, response::Json, routing::get};
use clap::Parser;
use quicproxy::api::{
    common::cors_middleware,
    core_manager::CoreManager,
    management::{self, ManagementState},
    persist_handler::{self, PersistHandlerState},
    persist_store::PersistStore,
    reverse_proxy::{self, ProxyState},
    static_files,
    sysinfo_api::{self, SysInfoState},
};
use quicproxy::bootstrap;
use quicproxy::config::Config;
use quicproxy::utils::elevate::{self, ElevateConfig};
use reqwest::Client;
use serde_json::json;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process;
use tracing::{debug, info};

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "snmalloc")]
#[global_allocator]
static GLOBAL: snmalloc_rs::SnMalloc = snmalloc_rs::SnMalloc;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    // ─── 核心模式 ───
    /// 配置文件路径（核心模式）
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// 提权运行
    #[arg(long)]
    elevate: bool,

    #[arg(long)]
    elevate_no_show_window: bool,

    // ─── 管理模式 ───
    /// 以管理服务器模式运行
    #[arg(long)]
    manage: bool,

    /// 管理服务器监听地址
    #[arg(long, default_value = "0.0.0.0")]
    host: String,

    /// 管理服务器监听端口
    #[arg(long, default_value = "8080")]
    port: u16,

    /// quicproxy 核心可执行文件路径（默认自身）
    #[arg(long)]
    core_path: Option<String>,

    /// 工作目录
    #[arg(long)]
    work_dir: Option<PathBuf>,

    /// 持久化数据文件名
    #[arg(long, default_value = "persist.json")]
    persist_file: String,

    /// API 密码
    #[arg(long, default_value = "")]
    password: String,

    /// Flutter Web 构建产物目录
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

    // ─── 管理模式 ───
    if args.manage {
        return run_manage(args).await;
    }

    // ─── 核心模式 ───

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
        debug!("Running without elevated privileges");
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

// ─── 管理模式 ───

async fn run_manage(args: Args) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "quicproxy=info".into()))
        .init();

    let work_dir = args.work_dir.unwrap_or_else(|| {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."))
    });

    let core_path = args.core_path.unwrap_or_else(|| {
        std::env::current_exe()
            .ok()
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

    // ─── 构建 Router ───
    let proxy_state = ProxyState {
        core_manager: core_manager.clone(),
        client: Client::new(),
    };

    // 核心 API 反向代理路由
    let proxy_routes = Router::new()
        .route("/observe", get(reverse_proxy::proxy_to_core))
        .route("/outbounds", get(reverse_proxy::proxy_to_core))
        .route(
            "/mode",
            get(reverse_proxy::proxy_to_core).put(reverse_proxy::proxy_to_core),
        )
        .route(
            "/connections",
            get(reverse_proxy::proxy_to_core).delete(reverse_proxy::proxy_to_core),
        )
        .route(
            "/selector",
            get(reverse_proxy::proxy_to_core).put(reverse_proxy::proxy_to_core),
        )
        .route("/trace", get(reverse_proxy::proxy_to_core))
        .route("/request", get(reverse_proxy::proxy_to_core))
        .route("/quit", get(reverse_proxy::proxy_to_core))
        .route("/traffic", get(reverse_proxy::proxy_to_core))
        .with_state(proxy_state);

    // 管理 API 路由
    let mgmt_router = management::router().with_state(ManagementState {
        core_manager: core_manager.clone(),
        password: args.password.clone(),
    });

    // 持久化 API 路由
    let persist_router = persist_handler::router().with_state(PersistHandlerState {
        persist_store: persist_store.clone(),
        password: args.password.clone(),
    });

    // 系统信息 API 路由
    use std::sync::{Arc, Mutex};
    use sysinfo::{Disks, System};
    let sysinfo_router = sysinfo_api::router().with_state(SysInfoState {
        password: args.password.clone(),
        system: Arc::new(Mutex::new(System::new_all())),
        disks: Arc::new(Mutex::new(Disks::new_with_refreshed_list())),
    });

    // 健康检查（lambda 捕获 clone）
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

    let core_api_router = proxy_routes
        .merge(mgmt_router)
        .merge(persist_router)
        .merge(sysinfo_router)
        .merge(health_route);

    // SPA fallback
    #[derive(Clone)]
    struct FallbackState {
        web_dir: Option<PathBuf>,
    }

    let fallback_state = FallbackState {
        web_dir: web_dir.clone(),
    };

    let app = if web_dir.is_some() {
        core_api_router
            .fallback(
                |State(s): State<FallbackState>, req: axum::extract::Request| async move {
                    let dir = s
                        .web_dir
                        .as_ref()
                        .expect("web_dir must be set for SPA fallback");
                    static_files::serve_static_from(dir, req).await
                },
            )
            .layer(axum::middleware::from_fn(cors_middleware))
            .with_state(fallback_state)
    } else {
        core_api_router
            .layer(axum::middleware::from_fn(cors_middleware))
            .with_state(fallback_state)
    };

    let addr: SocketAddr = format!("{}:{}", args.host, args.port).parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;

    info!("Manage server listening on {}", addr);
    info!("  core_path: {}", core_path_display);
    info!("  work_dir: {}", work_dir_display);
    info!("  persist file: {}", persist_path_display);
    if let Some(ref dir) = web_dir {
        info!("  web_dir: {}", dir.display());
    }

    axum::serve(listener, app).await?;
    Ok(())
}
