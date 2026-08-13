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
        self.remove(key);
    }

    pub async fn wait_until<T, F>(
        &self,
        key: &str,
        wait_timeout: Duration,
        mut condition: F,
    ) -> anyhow::Result<T>
    where
        F: FnMut() -> Option<T>,
    {
        let result = timeout(wait_timeout, async {
            loop {
                let notifier = self.get_or_create(key);
                let notified = notifier.notified();
                tokio::pin!(notified);

                // Register before checking the condition so notify cannot be
                // lost between the condition check and await.
                notified.as_mut().enable();

                if let Some(value) = condition() {
                    return value;
                }

                notified.await;
            }
        })
        .await
        .context("notify timeout");

        // Wake another waiter sharing this key so it can re-check its condition.
        self.remove(key);
        result
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    async fn wait_until_registered(notify: &KeyedNotify, key: &str) {
        timeout(Duration::from_secs(1), async {
            while !notify.notifiers.contains_key(key) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("waiter was not registered");
    }

    #[test]
    fn notify_without_waiter_does_not_create_notifier() {
        let notify = KeyedNotify::new();

        notify.notify("no-waiter");

        assert!(notify.notifiers.is_empty());
    }

    #[tokio::test]
    async fn wait_until_is_woken_and_notifier_is_removed() {
        let notify = Arc::new(KeyedNotify::new());
        let ready = Arc::new(AtomicBool::new(false));
        let key = "wait-until";

        let waiter = tokio::spawn({
            let notify = notify.clone();
            let ready = ready.clone();
            async move {
                notify
                    .wait_until(key, Duration::from_secs(1), || {
                        ready.load(Ordering::Acquire).then_some(42)
                    })
                    .await
            }
        });

        wait_until_registered(&notify, key).await;
        ready.store(true, Ordering::Release);
        notify.notify(key);

        assert_eq!(waiter.await.unwrap().unwrap(), 42);
        assert!(notify.notifiers.is_empty());
    }

    #[tokio::test]
    async fn timeout_removes_notifier() {
        let notify = KeyedNotify::new();

        let result = notify
            .wait_until("timeout", Duration::from_millis(10), || None::<()>)
            .await;

        assert!(result.is_err());
        assert!(notify.notifiers.is_empty());
    }
}
