use super::fetch::{fetch_telegram_config, TelegramConfig};
use arc_swap::ArcSwap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

const MIN_BACKOFF: Duration = Duration::from_secs(30);

pub struct TelegramConfigCache {
    inner: ArcSwap<TelegramConfig>,
    refresh_interval: Duration,
}

impl TelegramConfigCache {
    pub async fn bootstrap(refresh_interval: Duration) -> Result<Arc<Self>, String> {
        let initial = fetch_telegram_config()
            .await
            .map_err(|e| format!("initial telegram config fetch failed: {e}"))?;
        Ok(Arc::new(Self {
            inner: ArcSwap::from_pointee(initial),
            refresh_interval,
        }))
    }

    pub fn get(&self) -> Arc<TelegramConfig> {
        self.inner.load_full()
    }

    async fn refresh_once(&self) -> Result<(), String> {
        let new = fetch_telegram_config()
            .await
            .map_err(|e| format!("{e}"))?;
        self.inner.store(Arc::new(new));
        Ok(())
    }

    pub async fn spawn_refresher(self: Arc<Self>, shutdown: CancellationToken) {
        tokio::spawn(async move {
            let mut backoff = MIN_BACKOFF;
            loop {
                let wait = self.refresh_interval;
                tokio::select! {
                    _ = sleep(wait) => {}
                    _ = shutdown.cancelled() => return,
                }
                match self.refresh_once().await {
                    Ok(()) => {
                        info!(next_in_secs = self.refresh_interval.as_secs(), "telegram config refreshed");
                        backoff = MIN_BACKOFF;
                    }
                    Err(e) => {
                        warn!(error = %e, retry_in_secs = backoff.as_secs(),
                              "telegram config refresh failed, keeping stale copy");
                        tokio::select! {
                            _ = sleep(backoff) => {}
                            _ = shutdown.cancelled() => return,
                        }
                        backoff = (backoff * 2).min(self.refresh_interval);
                    }
                }
            }
        });
    }
}
