use crate::cli::TlsFallbackConfig;
use rand::Rng;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, copy_bidirectional};
use tokio::net::TcpStream;
use tracing::{debug, warn};

pub async fn relay_to_fallback(
    mut client: TcpStream,
    already_read: &[u8],
    cfg: &TlsFallbackConfig,
) {
    let host = &cfg.hosts[rand::rng().random_range(0..cfg.hosts.len())];
    debug!(host, "fallback: connecting");

    let timeout = Duration::from_millis(cfg.timeout);
    let upstream = match tokio::time::timeout(timeout, TcpStream::connect(host)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => { warn!(host, "fallback connect failed: {e}"); return; }
        Err(_) => { warn!(host, "fallback connect timeout"); return; }
    };

    let mut upstream = upstream;
    let _ = upstream.set_nodelay(true);

    if upstream.write_all(already_read).await.is_err() { return; }

    let _ = copy_bidirectional(&mut client, &mut upstream).await;
    debug!(host, "fallback: done");
}
