use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io::{Read, Seek, SeekFrom};
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
    /// 当前 core API 的认证密码（来自配置）
    config_api_password: RwLock<String>,
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
pub struct CoreLogContent {
    pub content: String,
    pub position: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CoreStatus {
    pub running: bool,
    pub pid: Option<u32>,
    pub core_path: String,
    pub work_dir: String,
    pub config_api_port: u16,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
pub struct StartCoreRequest {
    #[serde(default, rename = "isNeedElevate")]
    pub is_need_elevate: bool,
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
                config_api_password: RwLock::new(String::new()),
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
        if let Some(password) = parsed["api"]["password"].as_str() {
            *self.inner.config_api_password.write().await = password.to_string();
        }

        *self.inner.config_json.write().await = Some(json);
        Ok(())
    }

    /// 启动 core 进程
    /// 1. 将当前 config_json 写入 config 文件
    /// 2. 启动 core 二进制
    pub async fn start(&self, request: StartCoreRequest) -> anyhow::Result<()> {
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
            "Starting core: {} -c {} --work-dir {} elevate={}",
            core_path,
            config_path.display(),
            self.inner.work_dir.display(),
            request.is_need_elevate
        );

        let mut command = Command::new(&core_path);
        command
            .arg("-c")
            .arg(&config_path)
            .current_dir(&self.inner.work_dir)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);

        if request.is_need_elevate {
            command.arg("--elevate").arg("--elevate-no-show-window");
        }

        let mut child = command
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
                    println!("[core] {}", line);
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
                    eprintln!("[core] {}", line);
                    cm.push_log(line);
                }
            });
        }

        *self.inner.process.write().await = Some(child);
        Ok(())
    }

    /// 停止 core 进程
    pub async fn stop(&self) -> anyhow::Result<()> {
        let mut proc_guard = self.inner.process.write().await;
        let Some(mut child) = proc_guard.take() else {
            info!("Core process not running, skip stop");
            return Ok(());
        };
        drop(proc_guard);

        match child.try_wait() {
            Ok(Some(status)) => {
                info!("Core process already exited: {:?}", status);
                return Ok(());
            }
            Ok(None) => {}
            Err(e) => {
                error!("Failed to check core process status: {}", e);
            }
        }

        let api_port = *self.inner.config_api_port.read().await;
        let api_password = self.inner.config_api_password.read().await.clone();

        // 优先通过 API 优雅退出
        let client = reqwest::Client::new();
        let mut request = client.get(format!("http://127.0.0.1:{}/quit", api_port));
        if !api_password.is_empty() {
            request = request.header("Authorization", api_password);
        }

        match request.send().await {
            Ok(response) if response.status().is_success() => {
                info!("Sent quit signal to core via API port {}", api_port);
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
            Ok(response) => {
                warn!(
                    "Failed to send quit via API (status: {}), will kill process",
                    response.status()
                );
            }
            Err(e) => {
                warn!("Failed to send quit via API ({}), will kill process", e);
            }
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                info!("Core process exited after quit signal: {:?}", status);
            }
            Ok(None) => {
                info!("Killing core process...");
                if let Err(e) = child.kill().await {
                    error!("Failed to kill core process: {}", e);
                    let _ = child.start_kill();
                }
                let _ = tokio::time::timeout(std::time::Duration::from_secs(5), child.wait()).await;
            }
            Err(e) => {
                error!("Failed to check core process status: {}", e);
            }
        }
        Ok(())
    }

    /// 重启 core（应用新配置）
    pub async fn restart(&self, request: StartCoreRequest) -> anyhow::Result<()> {
        self.stop().await?;
        self.start(request).await
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

    /// 按字节位置增量读取 core 日志文件。
    /// Web 端用此方法复用桌面端 `readLog` 的文件读取语义。
    pub async fn read_log(&self, position: u64) -> std::io::Result<CoreLogContent> {
        let log_path = self.log_file_path().await;
        tokio::task::spawn_blocking(move || read_log_from(&log_path, position))
            .await
            .map_err(std::io::Error::other)?
    }

    async fn log_file_path(&self) -> PathBuf {
        let configured_path = self
            .inner
            .config_json
            .read()
            .await
            .as_deref()
            .and_then(|json| serde_json::from_str::<serde_json::Value>(json).ok())
            .and_then(|config| config["log"]["path"].as_str().map(PathBuf::from));

        match configured_path {
            Some(path) if path.is_absolute() => path,
            Some(path) => self.inner.work_dir.join(path),
            None => self.inner.work_dir.join("quicproxy.log"),
        }
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

fn read_log_from(path: &std::path::Path, position: u64) -> std::io::Result<CoreLogContent> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CoreLogContent {
                content: String::new(),
                position: 0,
            });
        }
        Err(error) => return Err(error),
    };

    let file_length = file.seek(SeekFrom::End(0))?;
    let read_start = if position > file_length { 0 } else { position };
    file.seek(SeekFrom::Start(read_start))?;

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(CoreLogContent {
        position: read_start + bytes.len() as u64,
        content: String::from_utf8_lossy(&bytes).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[tokio::test]
    async fn read_log_returns_incremental_file_content() {
        let temp_dir = tempfile::tempdir().unwrap();
        let manager = CoreManager::new("quicproxy".into(), temp_dir.path().to_path_buf());
        let log_path = temp_dir.path().join("quicproxy.log");
        std::fs::write(&log_path, "first\n").unwrap();

        let first_read = manager.read_log(0).await.unwrap();
        assert_eq!(first_read.content, "first\n");

        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .unwrap();
        write!(file, "second\n").unwrap();

        let second_read = manager.read_log(first_read.position).await.unwrap();
        assert_eq!(second_read.content, "second\n");
        assert!(second_read.position > first_read.position);
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
