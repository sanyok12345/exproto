use crate::cli::{Config, Secret};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::watch;
use tracing::{info, warn};

pub fn spawn_sighup_handler(tx: watch::Sender<Arc<Config>>) {
    #[cfg(not(unix))]
    let _ = tx;

    #[cfg(unix)]
    {
        let config_path = std::env::args()
            .position(|a| a == "-c" || a == "--config")
            .and_then(|i| std::env::args().nth(i + 1))
            .map(PathBuf::from);

        let Some(path) = config_path else { return };

        tokio::spawn(async move {
            let mut sig = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
                .expect("exproto: failed to register SIGHUP");
            loop {
                sig.recv().await;
                info!("SIGHUP received, reloading {}", path.display());
                match load_config(&path) {
                    Ok(cfg) => {
                        info!(secrets = cfg.secrets.len(), "config reloaded");
                        let _ = tx.send(Arc::new(cfg));
                    }
                    Err(e) => warn!("reload failed: {e}"),
                }
            }
        });
    }
}

fn load_config(path: &std::path::Path) -> Result<Config, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;

    #[derive(serde::Deserialize, Default)]
    struct File {
        #[serde(default)] server: Server,
        #[serde(default)] secrets: Vec<Entry>,
        #[serde(default)] tls: Tls,
        #[serde(default)] logging: Log,
    }
    #[derive(serde::Deserialize, Default)]
    struct Server { bind: Option<String>, port: Option<u16>, #[serde(alias = "max-workers")] workers: Option<usize>, proxy_tag: Option<String> }
    #[derive(serde::Deserialize)]
    struct Entry { name: Option<String>, secret: String, domain: Option<String> }
    #[derive(serde::Deserialize, Default)]
    struct Tls { domain: Option<String> }
    #[derive(serde::Deserialize, Default)]
    struct Log { level: Option<String> }

    let f: File = serde_yaml::from_str(&content).map_err(|e| format!("parse: {e}"))?;

    let bind = f.server.bind.unwrap_or_else(|| "0.0.0.0".into());
    let port = f.server.port.unwrap_or(8443);
    let listen_addr = format!("{bind}:{port}").parse().map_err(|e| format!("addr: {e}"))?;

    let mut secrets = Vec::new();
    for (i, e) in f.secrets.iter().enumerate() {
        let raw = hex::decode(&e.secret).map_err(|err| format!("secret #{}: {err}", i + 1))?;
        let key: [u8; 16] = match raw.len() {
            16 => raw.try_into().unwrap(),
            17 => raw[1..].try_into().unwrap(),
            n => return Err(format!("secret #{}: expected 16 bytes, got {n}", i + 1)),
        };
        secrets.push(Secret {
            name: e.name.clone().unwrap_or_else(|| format!("s{}", i + 1)),
            key,
            domain: e.domain.clone(),
            mode: crate::cli::ProxyMode::Direct,
            upstream: None,
            max_connections: 0,
            ad_tag: None,
        });
    }

    if secrets.is_empty() {
        return Err("no secrets in config".into());
    }

    let ad_tag = f.server.proxy_tag.and_then(|h| {
        let raw = hex::decode(&h).ok()?;
        (raw.len() == 16).then(|| raw.try_into().unwrap())
    });

    Ok(Config {
        secrets,
        listen_addr,
        ad_tag,
        workers: f.server.workers.unwrap_or(0),
        tls_domain: f.tls.domain.unwrap_or_else(|| "www.google.com".into()),
        log_level: f.logging.level.unwrap_or_else(|| "info".into()),
        aes_pwd: None,
        upstream: crate::cli::UpstreamConfig::default(),
        max_connections: 0,
        healthcheck: crate::cli::HealthcheckConfig::default(),
    })
}
