pub mod error;
mod version;
mod config;
mod shutdown;

pub use error::{Error, Result};
pub use version::{VERSION, CODENAME};

use crate::cli::{self, Action};
use crate::mtproto::dc::{self, TelegramConfigCache};
use crate::net;
use crate::net::accept::limit::ConnectionLimiter;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{info, debug, error};

pub async fn run() {
    match cli::parse_args() {
        Action::Run(cfg) => run_server(*cfg).await,
        Action::Links { secrets, tls_domain, port } => print_links(&secrets, &tls_domain, port),
        Action::Check { secrets, tls_domain } => run_check(&secrets, &tls_domain).await,
        Action::GenerateSecret => generate_secret(),
    }
}

async fn run_server(cfg: cli::Config) {
    let filter = tracing_subscriber::EnvFilter::from_default_env()
        .add_directive(format!("exproto={}", cfg.log_level).parse().unwrap());

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true)
        .with_file(false)
        .with_line_number(false)
        .init();

    info!(
        version = VERSION,
        codename = CODENAME,
        addr = %cfg.listen_addr,
        secrets = cfg.secrets.len(),
        "ExProto starting"
    );

    for secret in &cfg.secrets {
        debug!(name = secret.name, "secret registered");
    }

    if cfg.healthcheck.enabled {
        info!("running DC healthcheck...");
        dc::check_all_dcs(cfg.healthcheck.timeout).await;
    }

    let secret_limits: Vec<(String, u64)> = cfg.secrets.iter()
        .map(|s| (s.name.clone(), s.max_connections))
        .collect();
    let limiter = Arc::new(ConnectionLimiter::new(cfg.max_connections, secret_limits));

    let shutdown_token = CancellationToken::new();
    shutdown::spawn_shutdown_handler(shutdown_token.clone());

    let refresh_interval = Duration::from_secs(cfg.telegram.config_refresh_secs);
    info!(interval_secs = refresh_interval.as_secs(), "bootstrapping Telegram config cache");
    let tg_cache = match TelegramConfigCache::bootstrap(refresh_interval).await {
        Ok(c) => c,
        Err(e) => {
            error!("{e}");
            return;
        }
    };
    tg_cache.clone().spawn_refresher(shutdown_token.clone()).await;

    let worker_count = resolve_worker_count(cfg.workers);
    let listen_addr = cfg.listen_addr;

    let (cfg_tx, cfg_rx) = watch::channel(Arc::new(cfg));
    config::spawn_sighup_handler(cfg_tx);

    info!(workers = worker_count, addr = %listen_addr, "spawning worker pool (SO_REUSEPORT)");

    let core_ids = core_affinity::get_core_ids().unwrap_or_default();
    let mut worker_threads = Vec::with_capacity(worker_count);
    for worker_id in 0..worker_count {
        let cfg_rx = cfg_rx.clone();
        let limiter = limiter.clone();
        let tg_cache = tg_cache.clone();
        let shutdown = shutdown_token.clone();
        let pin_core = core_ids.get(worker_id % core_ids.len().max(1)).copied();
        let handle = std::thread::Builder::new()
            .name(format!("exproto-worker-{worker_id}"))
            .spawn(move || {
                if let Some(core) = pin_core {
                    if core_affinity::set_for_current(core) {
                        debug!(worker = worker_id, core = core.id, "pinned worker to core");
                    }
                }
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build worker runtime");
                rt.block_on(async move {
                    let listener = match crate::net::socket::build_reuseport_listener(listen_addr) {
                        Ok(l) => l,
                        Err(e) => {
                            error!(worker = worker_id, "failed to bind {listen_addr}: {e}");
                            return;
                        }
                    };
                    net::accept::listener::serve_on(listener, worker_id, cfg_rx, limiter, tg_cache, shutdown).await;
                });
            })
            .expect("spawn worker thread");
        worker_threads.push(handle);
    }

    shutdown_token.cancelled().await;
    info!("master: shutdown signaled, joining workers");
    for h in worker_threads {
        let _ = h.join();
    }

    info!("ExProto stopped");
}

fn print_links(secrets: &[cli::Secret], tls_domain: &str, port: u16) {
    for secret in secrets {
        let h = hex::encode(secret.key);
        let domain = secret.domain.as_deref().unwrap_or(tls_domain);
        println!(
            "{}: tg://proxy?server=HOST&port={}&secret=ee{}{}",
            secret.name, port, h, hex::encode(domain.as_bytes()),
        );
    }
}

async fn run_check(secrets: &[cli::Secret], tls_domain: &str) {
    println!("ExProto v{} ({})", VERSION, CODENAME);
    println!();
    println!("secrets: {}", secrets.len());
    for s in secrets {
        let domain = s.domain.as_deref().unwrap_or(tls_domain);
        println!("  {} domain={} mode={:?}", s.name, domain, s.mode);
    }
    println!();
    println!("DC healthcheck:");
    let results = dc::check_all_dcs(5).await;
    for r in &results {
        if r.alive {
            println!("  DC {} ({}) — {}ms", r.dc_id, r.addr, r.latency_ms);
        } else {
            println!("  DC {} ({}) — UNREACHABLE", r.dc_id, r.addr);
        }
    }
    let alive = results.iter().filter(|r| r.alive).count();
    println!();
    println!("{}/{} DCs reachable", alive, results.len());
}

fn resolve_worker_count(configured: usize) -> usize {
    if configured > 0 {
        return configured;
    }
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

fn generate_secret() {
    let secret: [u8; 16] = rand::random::<[u8; 16]>();
    println!("{}", hex::encode(secret));
}
