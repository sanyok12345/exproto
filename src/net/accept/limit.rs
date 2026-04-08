use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub struct ConnectionLimiter {
    global_count: AtomicU64,
    global_max: u64,
    per_secret: Vec<SecretCounter>,
}

struct SecretCounter {
    count: AtomicU64,
    max: u64,
}

pub struct ConnectionGuard {
    limiter: Arc<ConnectionLimiter>,
    secret_idx: Option<usize>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.limiter.global_count.fetch_sub(1, Ordering::Relaxed);
        if let Some(idx) = self.secret_idx {
            if let Some(sc) = self.limiter.per_secret.get(idx) {
                sc.count.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
}

impl ConnectionLimiter {
    pub fn new(global_max: u64, secret_limits: Vec<u64>) -> Self {
        let per_secret = secret_limits
            .into_iter()
            .map(|max| SecretCounter { count: AtomicU64::new(0), max })
            .collect();
        Self {
            global_count: AtomicU64::new(0),
            global_max,
            per_secret,
        }
    }

    pub fn try_acquire(self: &Arc<Self>, secret_idx: usize) -> Option<ConnectionGuard> {
        if self.global_max > 0 {
            let current = self.global_count.fetch_add(1, Ordering::Relaxed);
            if current >= self.global_max {
                self.global_count.fetch_sub(1, Ordering::Relaxed);
                return None;
            }
        } else {
            self.global_count.fetch_add(1, Ordering::Relaxed);
        }

        let mut held_idx = None;
        if let Some(sc) = self.per_secret.get(secret_idx) {
            if sc.max > 0 {
                let current = sc.count.fetch_add(1, Ordering::Relaxed);
                if current >= sc.max {
                    sc.count.fetch_sub(1, Ordering::Relaxed);
                    self.global_count.fetch_sub(1, Ordering::Relaxed);
                    return None;
                }
            } else {
                sc.count.fetch_add(1, Ordering::Relaxed);
            }
            held_idx = Some(secret_idx);
        }

        Some(ConnectionGuard {
            limiter: Arc::clone(self),
            secret_idx: held_idx,
        })
    }

    pub fn active_connections(&self) -> u64 {
        self.global_count.load(Ordering::Relaxed)
    }

    pub fn active_for_secret(&self, idx: usize) -> u64 {
        self.per_secret.get(idx).map(|sc| sc.count.load(Ordering::Relaxed)).unwrap_or(0)
    }
}
