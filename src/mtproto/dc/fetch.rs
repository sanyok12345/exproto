use std::collections::HashMap;
use std::net::SocketAddr;
use tracing::info;

const PROXY_SECRET_URL: &str = "https://core.telegram.org/getProxySecret";
const PROXY_CONFIG_URL: &str = "https://core.telegram.org/getProxyConfig";

pub struct TelegramConfig {
    pub proxy_secret: Vec<u8>,
    pub middle_proxies: HashMap<i16, Vec<SocketAddr>>,
}

pub async fn fetch_telegram_config() -> Result<TelegramConfig, Box<dyn std::error::Error + Send + Sync>> {
    let (secret_result, config_result) = tokio::join!(
        fetch_proxy_secret(),
        fetch_proxy_config()
    );

    let proxy_secret = secret_result?;
    let middle_proxies = config_result?;

    info!(
        secret_len = proxy_secret.len(),
        dc_count = middle_proxies.len(),
        "fetched telegram config"
    );

    Ok(TelegramConfig { proxy_secret, middle_proxies })
}

async fn fetch_proxy_secret() -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let resp = reqwest::get(PROXY_SECRET_URL).await?;
    Ok(resp.bytes().await?.to_vec())
}

async fn fetch_proxy_config() -> Result<HashMap<i16, Vec<SocketAddr>>, Box<dyn std::error::Error + Send + Sync>> {
    let resp = reqwest::get(PROXY_CONFIG_URL).await?;
    let text = resp.text().await?;

    let mut map: HashMap<i16, Vec<SocketAddr>> = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with("proxy_for") { continue; }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 { continue; }
        let dc_idx: i16 = match parts[1].parse() { Ok(v) => v, Err(_) => continue };
        let addr: SocketAddr = match parts[2].trim_end_matches(';').parse() { Ok(v) => v, Err(_) => continue };
        map.entry(dc_idx).or_default().push(addr);
    }
    Ok(map)
}

pub fn load_proxy_secret_from_file(path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    Ok(std::fs::read(path)?)
}
