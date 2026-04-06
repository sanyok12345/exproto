use super::dispatch;
use super::limit::ConnectionLimiter;
use crate::cli::Config;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

pub async fn serve(
    cfg_rx: watch::Receiver<Arc<Config>>,
    limiter: Arc<ConnectionLimiter>,
    shutdown: CancellationToken,
) {
    let addr = cfg_rx.borrow().listen_addr;
    let listener = TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("exproto: failed to bind {addr}: {e}"));

    info!(addr = %addr, "accepting connections");

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, peer) = match result {
                    Ok(v) => v,
                    Err(e) => { error!("accept: {e}"); continue; }
                };
                let cfg = cfg_rx.borrow().clone();
                let lim = limiter.clone();
                tokio::spawn(dispatch::handle_connection(stream, peer, cfg, lim));
            }
            _ = shutdown.cancelled() => {
                info!(
                    active = limiter.active_connections(),
                    "shutdown: stopped accepting, waiting for active connections to drain"
                );
                break;
            }
        }
    }

    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(30);
    while limiter.active_connections() > 0 {
        if tokio::time::Instant::now() >= deadline {
            info!(remaining = limiter.active_connections(), "shutdown: deadline reached, dropping remaining connections");
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
}
