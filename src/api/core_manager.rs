use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, RwLock};
use tracing::{error, info, warn};

/// 核心进程管理器
///
/// 前端通过 API 下发 core 配置 JSON，管理器写入文件后启动 quicproxy 核心进程。
/// 配置和 core 路径均可在运行时通过 API 动态设置，持久化到 store 中。
#[derive(Clone)]
pub struct CoreManager {
    inner: Arc<CoreManagerInner>,
}

struct CoreManagerInner {
    /// 当前运行的子进程
    process: RwLock<Option<Child>>,
    /// quicproxy 二进制路径（可运行时修改）
    core_path: RwLock<String>,
    /// 工作目录（core 在该目录下运行，config/data 放在这里）
    work_dir: PathBuf,
    /// 当前 core 配置 JSON（前端通过 API 下发）
    config_json: RwLock<Option<String>>,
    /// 从 config_json 中解析出的 api_port
    config_api_port: RwLock<u16>,
    /// 滚动日志
    logs: Mutex<VecDeque<CoreLogEntry>>,
    max_log_lines: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct CoreLogEntry {
    pub timestamp: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CoreStatus {
    pub running: bool,
    pub pid: Option<u32>,
    pub core_path: String,
    pub work_dir: String,
    pub config_api_port: u16,
}

impl CoreManager {
    pub fn new(core_path: String, work_dir: PathBuf) -> Self {
        // 确保工作目录存在
        let _ = std::fs::create_dir_all(&work_dir);

        Self {
            inner: Arc::new(CoreManagerInner {
                process: RwLock::new(None),
                core_path: RwLock::new(core_path),
                work_dir,
                config_json: RwLock::new(None),
                config_api_port: RwLock::new(1235),
                logs: Mutex::new(VecDeque::new()),
                max_log_lines: 500,
            }),
        }
    }

    /// 设置 core 二进制路径
    pub async fn set_core_path(&self, path: String) {
        *self.inner.core_path.write().await = path;
    }

    /// 获取 core 配置文件路径
    pub fn config_file_path(&self) -> PathBuf {
        self.inner.work_dir.join("config.json")
    }

    /// 设置 core 配置 JSON（前端通过 API 下发）
    /// 同时解析其中的 api.port 用于后续 /quit 信号
    pub async fn set_config(&self, json: String) -> anyhow::Result<()> {
        // 验证是有效 JSON
        let parsed: serde_json::Value = serde_json::from_str(&json)
            .map_err(|e| anyhow::anyhow!("Invalid config JSON: {}", e))?;

        // 提取 api.port
        if let Some(port) = parsed["api"]["port"].as_u64() {
            *self.inner.config_api_port.write().await = port as u16;
            info!("Config api.port detected: {}", port);
        }

        *self.inner.config_json.write().await = Some(json);
        Ok(())
    }

    /// 启动 core 进程
    /// 1. 将当前 config_json 写入 config 文件
    /// 2. 启动 core 二进制
    pub async fn start(&self) -> anyhow::Result<()> {
        // 先停止正在运行的
        if self.is_running() {
            self.stop().await?;
        }

        let config_json = self
            .inner
            .config_json
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow::anyhow!("No config set. Use PUT /api/core/config first."))?;

        let config_path = self.config_file_path();
        let core_path = self.inner.core_path.read().await.clone();

        // 写入配置文件
        info!("Writing core config to {}", config_path.display());
        std::fs::write(&config_path, &config_json)
            .map_err(|e| anyhow::anyhow!("Failed to write config file: {}", e))?;

        // 启动核心
        info!(
            "Starting core: {} -c {} --work-dir {}",
            core_path,
            config_path.display(),
            self.inner.work_dir.display()
        );

        let mut child = Command::new(&core_path)
            .arg("-c")
            .arg(&config_path)
            .current_dir(&self.inner.work_dir)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| anyhow::anyhow!("Failed to spawn core process: {}", e))?;

        let pid = child.id();
        info!("Core started with PID: {:?}", pid);

        // 收集 stdout
        if let Some(stdout) = child.stdout.take() {
            let cm = self.clone();
            tokio::spawn(async move {
                use tokio::io::AsyncBufReadExt;
                let reader = tokio::io::BufReader::new(stdout);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    cm.push_log(line);
                }
            });
        }

        // 收集 stderr
        if let Some(stderr) = child.stderr.take() {
            let cm = self.clone();
            tokio::spawn(async move {
                use tokio::io::AsyncBufReadExt;
                let reader = tokio::io::BufReader::new(stderr);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    cm.push_log(line);
                }
            });
        }

        *self.inner.process.write().await = Some(child);
        Ok(())
    }

    /// 停止 core 进程
    pub async fn stop(&self) -> anyhow::Result<()> {
        let api_port = *self.inner.config_api_port.read().await;

        // 优先通过 API 优雅退出
        match reqwest::get(format!("http://127.0.0.1:{}/quit", api_port)).await {
            Ok(_) => {
                info!("Sent quit signal to core via API port {}", api_port);
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
            Err(e) => {
                warn!("Failed to send quit via API ({}), will kill process", e);
            }
        }

        let mut proc_guard = self.inner.process.write().await;
        if let Some(mut child) = proc_guard.take() {
            match child.try_wait() {
                Ok(Some(status)) => {
                    info!("Core process already exited: {:?}", status);
                }
                Ok(None) => {
                    info!("Killing core process...");
                    if let Err(e) = child.kill().await {
                        error!("Failed to kill core process: {}", e);
                        let _ = child.start_kill();
                    }
                    let _ =
                        tokio::time::timeout(std::time::Duration::from_secs(5), child.wait()).await;
                }
                Err(e) => {
                    error!("Failed to check core process status: {}", e);
                }
            }
        }
        Ok(())
    }

    /// 重启 core（应用新配置）
    pub async fn restart(&self) -> anyhow::Result<()> {
        self.stop().await?;
        self.start().await
    }

    fn is_running(&self) -> bool {
        self.inner
            .process
            .try_read()
            .ok()
            .and_then(|g| g.as_ref().map(|_| true))
            .unwrap_or(false)
    }

    pub fn status(&self) -> CoreStatus {
        let pid = self
            .inner
            .process
            .try_read()
            .ok()
            .and_then(|guard| guard.as_ref().and_then(|c| c.id()));

        let config_api_port = self
            .inner
            .config_api_port
            .try_read()
            .ok()
            .map(|g| *g)
            .unwrap_or(0);

        CoreStatus {
            running: pid.is_some(),
            pid,
            core_path: self
                .inner
                .core_path
                .try_read()
                .map(|v| v.clone())
                .unwrap_or_default(),
            work_dir: self.inner.work_dir.display().to_string(),
            config_api_port,
        }
    }

    pub async fn get_logs(&self, tail: Option<usize>) -> Vec<CoreLogEntry> {
        let logs = self.inner.logs.lock().await;
        let limit = tail.unwrap_or(200);
        let skip = if logs.len() > limit {
            logs.len() - limit
        } else {
            0
        };
        logs.iter().skip(skip).cloned().collect()
    }

    fn push_log(&self, message: String) {
        let timestamp = {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            format!("{}", now.as_millis())
        };
        if let Ok(mut logs) = self.inner.logs.try_lock() {
            logs.push_back(CoreLogEntry { timestamp, message });
            while logs.len() > self.inner.max_log_lines {
                logs.pop_front();
            }
        }
    }
}

// ─── API 请求类型 ───

#[derive(Deserialize)]
pub struct SetConfigRequest {
    /// core 配置 JSON 字符串（CoreConfig.build() 的输出）
    pub config: String,
}

#[derive(Deserialize)]
pub struct SetCorePathRequest {
    pub core_path: String,
}
