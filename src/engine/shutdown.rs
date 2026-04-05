use tokio_util::sync::CancellationToken;
use tracing::info;

pub fn spawn_shutdown_handler(token: CancellationToken) {
    tokio::spawn(async move {
        let ctrl_c = tokio::signal::ctrl_c();
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("exproto: failed to register SIGTERM");

        tokio::select! {
            _ = ctrl_c => info!("SIGINT received, shutting down..."),
            _ = sigterm.recv() => info!("SIGTERM received, shutting down..."),
        }

        token.cancel();

        tokio::signal::ctrl_c().await.ok();
        info!("forced shutdown");
        std::process::exit(0);
    });
}
