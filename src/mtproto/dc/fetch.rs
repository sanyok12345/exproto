use std::collections::HashMap;
use std::io::Read;
use std::net::SocketAddr;
use tracing::info;

const PROXY_SECRET_URL: &str = "https://core.telegram.org/getProxySecret";
const PROXY_CONFIG_URL: &str = "https://core.telegram.org/getProxyConfig";

pub struct TelegramConfig {
    pub proxy_secret: Vec<u8>,
    pub middle_proxies: HashMap<i16, Vec<SocketAddr>>,
}

pub async fn fetch_telegram_config() -> Result<TelegramConfig, Box<dyn std::error::Error + Send + Sync>> {
    let cfg = tokio::task::spawn_blocking(fetch_sync).await??;
    info!(
        secret_len = cfg.proxy_secret.len(),
        dc_count = cfg.middle_proxies.len(),
        "fetched telegram config"
    );
    Ok(cfg)
}

fn fetch_sync() -> Result<TelegramConfig, Box<dyn std::error::Error + Send + Sync>> {
    let agent = ureq::Agent::new_with_defaults();

    let mut secret_body = Vec::new();
    agent.get(PROXY_SECRET_URL)
        .call()?
        .body_mut()
        .as_reader()
        .read_to_end(&mut secret_body)?;

    let config_text = agent.get(PROXY_CONFIG_URL)
        .call()?
        .body_mut()
        .read_to_string()?;

    let mut map: HashMap<i16, Vec<SocketAddr>> = HashMap::new();
    for line in config_text.lines() {
        let line = line.trim();
        if !line.starts_with("proxy_for") { continue; }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 { continue; }
        let dc_idx: i16 = match parts[1].parse() { Ok(v) => v, Err(_) => continue };
        let addr: SocketAddr = match parts[2].trim_end_matches(';').parse() { Ok(v) => v, Err(_) => continue };
        map.entry(dc_idx).or_default().push(addr);
    }

    Ok(TelegramConfig { proxy_secret: secret_body, middle_proxies: map })
}

pub fn load_proxy_secret_from_file(path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    Ok(std::fs::read(path)?)
}
