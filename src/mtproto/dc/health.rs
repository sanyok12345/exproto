use super::addr::TELEGRAM_DC_ADDRS;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct DcHealth {
    pub dc_id: usize,
    pub addr: &'static str,
    pub alive: bool,
    pub latency_ms: u64,
}

pub async fn check_all_dcs(timeout_secs: u64) -> Vec<DcHealth> {
    let timeout = Duration::from_secs(timeout_secs);
    let mut results = Vec::new();

    let mut handles = Vec::new();
    for (i, addr) in TELEGRAM_DC_ADDRS.iter().enumerate().skip(1) {
        let addr = *addr;
        handles.push(tokio::spawn(async move {
            let start = Instant::now();
            let alive = tokio::time::timeout(timeout, TcpStream::connect(addr))
                .await
                .map(|r| r.is_ok())
                .unwrap_or(false);
            let latency_ms = start.elapsed().as_millis() as u64;
            DcHealth { dc_id: i, addr, alive, latency_ms }
        }));
    }

    for handle in handles {
        if let Ok(health) = handle.await {
            if health.alive {
                info!(dc = health.dc_id, latency_ms = health.latency_ms, "DC {} ok", health.addr);
            } else {
                warn!(dc = health.dc_id, "DC {} unreachable", health.addr);
            }
            results.push(health);
        }
    }

    results
}
