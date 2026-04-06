use tokio_util::sync::CancellationToken;
use tracing::info;

pub fn spawn_shutdown_handler(token: CancellationToken) {
    tokio::spawn(async move {
        wait_for_signal().await;
        token.cancel();

        tokio::signal::ctrl_c().await.ok();
        info!("forced shutdown");
        std::process::exit(0);
    });
}

async fn wait_for_signal() {
    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("exproto: failed to register SIGTERM");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => info!("SIGINT received, shutting down..."),
            _ = sigterm.recv() => info!("SIGTERM received, shutting down..."),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.ok();
        info!("SIGINT received, shutting down...");
    }
}
