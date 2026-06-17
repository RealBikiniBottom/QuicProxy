use dashmap::DashMap;
use serde::Deserialize;
use std::path::PathBuf;
use tracing::{info, warn};

/// 持久化存储：内存 HashMap + 可选文件持久化
/// 作为 core 的陪伴进程使用，为 Web 前端提供跨标签页/跨设备的状态共享
#[derive(Clone)]
pub struct PersistStore {
    inner: std::sync::Arc<PersistStoreInner>,
}

struct PersistStoreInner {
    data: DashMap<String, String>,
    file_path: Option<PathBuf>,
}

impl PersistStore {
    pub fn new(file_path: Option<PathBuf>) -> Self {
        let inner = PersistStoreInner {
            data: DashMap::new(),
            file_path,
        };
        let store = Self {
            inner: std::sync::Arc::new(inner),
        };
        store.load_from_disk();
        store
    }

    fn load_from_disk(&self) {
        if let Some(ref path) = self.inner.file_path {
            if path.exists() {
                match std::fs::read_to_string(path) {
                    Ok(content) => match serde_json::from_str::<Vec<(String, String)>>(&content) {
                        Ok(entries) => {
                            for (k, v) in entries {
                                self.inner.data.insert(k, v);
                            }
                            info!(
                                "PersistStore: loaded {} entries from {}",
                                self.inner.data.len(),
                                path.display()
                            );
                        }
                        Err(e) => {
                            warn!("PersistStore: failed to parse persist file: {}", e);
                        }
                    },
                    Err(e) => {
                        warn!("PersistStore: failed to read persist file: {}", e);
                    }
                }
            }
        }
    }

    pub fn flush_to_disk(&self) {
        if let Some(ref path) = self.inner.file_path {
            let entries: Vec<(String, String)> = self
                .inner
                .data
                .iter()
                .map(|entry| (entry.key().clone(), entry.value().clone()))
                .collect();

            if let Some(parent) = path.parent() {
                if !parent.exists() {
                    let _ = std::fs::create_dir_all(parent);
                }
            }

            let tmp_path = path.with_extension("tmp");
            match serde_json::to_string(&entries) {
                Ok(json) => {
                    if let Err(e) = std::fs::write(&tmp_path, &json) {
                        warn!("PersistStore: failed to write tmp file: {}", e);
                        return;
                    }
                    if let Err(e) = std::fs::rename(&tmp_path, path) {
                        warn!("PersistStore: failed to rename tmp file: {}", e);
                    }
                }
                Err(e) => {
                    warn!("PersistStore: failed to serialize persist data: {}", e);
                }
            }
        }
    }

    pub fn get(&self, key: &str) -> Option<String> {
        self.inner.data.get(key).map(|v| v.clone())
    }

    pub fn set_and_flush(&self, key: String, value: String) {
        self.inner.data.insert(key, value);
        self.flush_to_disk();
    }

    pub fn delete_and_flush(&self, key: &str) -> bool {
        let removed = self.inner.data.remove(key).is_some();
        if removed {
            self.flush_to_disk();
        }
        removed
    }

    pub fn delete_multi_and_flush<I>(&self, keys: I)
    where
        I: IntoIterator<Item = String>,
    {
        for key in keys {
            self.inner.data.remove(&key);
        }
        self.flush_to_disk();
    }

    pub fn len(&self) -> usize {
        self.inner.data.len()
    }
}

// ─── 请求/响应类型 ───

#[derive(Deserialize)]
pub struct SetValueRequest {
    pub value: String,
}
