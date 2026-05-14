use anyhow::Context;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tokio::time::timeout;

pub struct KeyedNotify {
    notifiers: DashMap<String, Arc<Notify>>,
}

impl KeyedNotify {
    pub fn new() -> Self {
        Self {
            notifiers: DashMap::new(),
        }
    }

    pub fn get_or_create(&self, key: &str) -> Arc<Notify> {
        self.notifiers
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone()
    }

    pub fn notify(&self, key: &str) {
        let notifier = self.get_or_create(key);
        notifier.notify_waiters();
    }

    pub async fn wait(&self, key: &str, wait_timeout: Duration) -> anyhow::Result<()> {
        let notifier = self.get_or_create(key);
        timeout(wait_timeout, notifier.notified())
            .await
            .context("notify timeout")?;
        self.notifiers.remove(key);
        Ok(())
    }

    pub fn remove(&self, key: &str) {
        if let Some((_, notifier)) = self.notifiers.remove(key) {
            notifier.notify_waiters();
        }
    }
}

impl Default for KeyedNotify {
    fn default() -> Self {
        Self::new()
    }
}
