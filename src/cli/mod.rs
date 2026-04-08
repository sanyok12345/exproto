use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;

pub struct Config {
    pub secrets: Vec<Secret>,
    pub listen_addr: SocketAddr,
    pub ad_tag: Option<[u8; 16]>,
    pub workers: usize,
    pub tls_domain: String,
    pub log_level: String,
    pub aes_pwd: Option<PathBuf>,
    pub upstream: UpstreamConfig,
    pub max_connections: u64,
    pub healthcheck: HealthcheckConfig,
    pub tls: TlsConfig,
    pub timeouts: TimeoutConfig,
    pub telegram: TelegramConfigCfg,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TelegramConfigCfg {
    #[serde(default = "default_config_refresh_secs", alias = "config-refresh-secs")]
    pub config_refresh_secs: u64,
}

impl Default for TelegramConfigCfg {
    fn default() -> Self { Self { config_refresh_secs: 3600 } }
}

fn default_config_refresh_secs() -> u64 { 3600 }

#[derive(Debug, Clone, Deserialize)]
pub struct TimeoutConfig {
    #[serde(default = "default_10")]
    pub handshake: u64,
    #[serde(default = "default_10")]
    pub connect: u64,
    #[serde(default = "default_1800")]
    pub idle: u64,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self { handshake: 10, connect: 10, idle: 1800 }
    }
}

fn default_10() -> u64 { 10 }
fn default_1800() -> u64 { 1800 }

#[derive(Debug, Clone, Deserialize, Default)]
pub struct TlsConfig {
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub handshake: TlsHandshakeConfig,
    #[serde(default)]
    pub stream: TlsStreamConfig,
    #[serde(default)]
    pub fallback: Option<TlsFallbackConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsHandshakeConfig {
    #[serde(default = "default_true")]
    pub fragment: bool,
}

impl Default for TlsHandshakeConfig {
    fn default() -> Self { Self { fragment: true } }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsStreamConfig {
    #[serde(default = "default_max_record_size")]
    pub max_record_size: usize,
    #[serde(default = "default_record_jitter")]
    pub record_jitter: f64,
}

impl Default for TlsStreamConfig {
    fn default() -> Self {
        Self { max_record_size: 16640, record_jitter: 0.03 }
    }
}

fn default_max_record_size() -> usize { 16640 }
fn default_record_jitter() -> f64 { 0.03 }

#[derive(Debug, Clone, Deserialize)]
pub struct TlsFallbackConfig {
    pub hosts: Vec<String>,
    #[serde(default = "default_fallback_timeout")]
    pub timeout: u64,
}

fn default_fallback_timeout() -> u64 { 5000 }

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyMode {
    #[default]
    Direct,
    MiddleProxy,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum UpstreamConfig {
    Direct {
        #[serde(default)]
        bind: Option<String>,
    },
    Socks5 {
        address: String,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
    },
}

impl Default for UpstreamConfig {
    fn default() -> Self { Self::Direct { bind: None } }
}

#[derive(Debug, Clone, Deserialize)]
pub struct HealthcheckConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_30")]
    pub interval: u64,
    #[serde(default = "default_5")]
    pub timeout: u64,
}

impl Default for HealthcheckConfig {
    fn default() -> Self { Self { enabled: true, interval: 30, timeout: 5 } }
}

fn default_true() -> bool { true }
fn default_30() -> u64 { 30 }
fn default_5() -> u64 { 5 }

#[derive(Debug, Clone)]
pub struct Secret {
    pub name: String,
    pub key: [u8; 16],
    pub domain: Option<String>,
    pub mode: ProxyMode,
    pub upstream: Option<UpstreamConfig>,
    pub max_connections: u64,
    pub ad_tag: Option<[u8; 16]>,
}

#[derive(Parser)]
#[command(name = "exproto", version, about = "High-performance MTProto proxy")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Run(RunArgs),
    Links(CommonArgs),
    Check(CommonArgs),
    Secret,
}

#[derive(Parser)]
struct RunArgs {
    #[arg(short = 'H', long = "port", default_value = "8443")]
    port: u16,

    #[arg(long = "bind", default_value = "0.0.0.0")]
    bind: String,

    #[arg(short = 'S', long = "secret", action = clap::ArgAction::Append)]
    secrets: Vec<String>,

    #[arg(short = 'P', long = "proxy-tag")]
    proxy_tag: Option<String>,

    #[arg(short = 'M', long = "max-workers", default_value = "0")]
    workers: usize,

    #[arg(short = 'c', long = "config")]
    config: Option<PathBuf>,

    #[arg(long = "tls-domain", default_value = "www.google.com")]
    tls_domain: String,

    #[arg(long = "log-level", default_value = "info")]
    log_level: String,

    #[arg(long = "aes-pwd")]
    aes_pwd: Option<PathBuf>,
}

#[derive(Parser)]
struct CommonArgs {
    #[arg(short = 'c', long = "config")]
    config: Option<PathBuf>,

    #[arg(short = 'S', long = "secret", action = clap::ArgAction::Append)]
    secrets: Vec<String>,

    #[arg(short = 'H', long = "port", default_value = "8443")]
    port: u16,

    #[arg(long = "tls-domain", default_value = "www.google.com")]
    tls_domain: String,
}


#[derive(Deserialize, Default)]
struct ConfigFile {
    #[serde(default)]
    server: ServerCfg,
    #[serde(default)]
    secrets: Vec<SecretEntry>,
    #[serde(default)]
    tls: TlsConfig,
    #[serde(default)]
    logging: LogCfg,
    #[serde(default)]
    upstream: Option<UpstreamConfig>,
    #[serde(default, alias = "max-connections")]
    max_connections: Option<u64>,
    #[serde(default)]
    healthcheck: Option<HealthcheckConfig>,
    #[serde(default)]
    timeouts: TimeoutConfig,
    #[serde(default)]
    telegram: Option<TelegramConfigCfg>,
}

#[derive(Deserialize, Default)]
struct ServerCfg {
    bind: Option<String>,
    port: Option<u16>,
    #[serde(alias = "max-workers")]
    workers: Option<usize>,
    proxy_tag: Option<String>,
}

#[derive(Deserialize)]
struct SecretEntry {
    name: Option<String>,
    secret: String,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    mode: Option<ProxyMode>,
    #[serde(default)]
    upstream: Option<UpstreamConfig>,
    #[serde(default, alias = "max-connections")]
    max_connections: Option<u64>,
    #[serde(default, alias = "ad-tag")]
    ad_tag: Option<String>,
}

#[derive(Deserialize, Default)]
struct LogCfg { level: Option<String> }


fn decode_secret(s: &str) -> Result<[u8; 16], String> {
    let raw = hex::decode(s).map_err(|e| format!("invalid hex: {e}"))?;
    match raw.len() {
        16 => Ok(raw.try_into().unwrap()),
        17 => Ok(raw[1..].try_into().unwrap()),
        n => Err(format!("expected 16 bytes, got {n}")),
    }
}

fn decode_tag(s: &str) -> Option<[u8; 16]> {
    let raw = hex::decode(s).ok()?;
    (raw.len() == 16).then(|| raw.try_into().unwrap())
}

fn load_config_file(path: &PathBuf) -> ConfigFile {
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("exproto: {}: {e}", path.display());
        std::process::exit(1);
    });
    serde_yaml::from_str(&content).unwrap_or_else(|e| {
        eprintln!("exproto: config error: {e}");
        std::process::exit(1);
    })
}

fn build_secrets_from_file(entries: &[SecretEntry]) -> Vec<Secret> {
    entries.iter().enumerate().map(|(i, entry)| {
        let key = decode_secret(&entry.secret).unwrap_or_else(|e| {
            eprintln!("exproto: secret #{}: {e}", i + 1);
            std::process::exit(1);
        });
        Secret {
            name: entry.name.clone().unwrap_or_else(|| format!("s{}", i + 1)),
            key,
            domain: entry.domain.clone(),
            mode: entry.mode.clone().unwrap_or_default(),
            upstream: entry.upstream.clone(),
            max_connections: entry.max_connections.unwrap_or(0),
            ad_tag: entry.ad_tag.as_deref().and_then(decode_tag),
        }
    }).collect()
}

fn build_secrets_from_cli(hex_list: &[String]) -> Vec<Secret> {
    hex_list.iter().enumerate().map(|(i, s)| {
        let key = decode_secret(s).unwrap_or_else(|e| {
            eprintln!("exproto: -S #{}: {e}", i + 1);
            std::process::exit(1);
        });
        Secret {
            name: format!("s{}", i + 1), key, domain: None,
            mode: ProxyMode::Direct, upstream: None, max_connections: 0, ad_tag: None,
        }
    }).collect()
}

fn resolve_secrets(file: Option<&ConfigFile>, cli_secrets: &[String]) -> Vec<Secret> {
    let mut secrets = file.map(|f| build_secrets_from_file(&f.secrets)).unwrap_or_default();
    if secrets.is_empty() {
        secrets = build_secrets_from_cli(cli_secrets);
    }
    if secrets.is_empty() {
        eprintln!("exproto: no secrets. use -S <hex> or -c <config.yaml>");
        std::process::exit(1);
    }
    secrets
}


pub enum Action {
    Run(Box<Config>),
    Links { secrets: Vec<Secret>, tls_domain: String, port: u16 },
    Check { secrets: Vec<Secret>, tls_domain: String },
    GenerateSecret,
}

pub fn parse_args() -> Action {
    let cli = Cli::parse();

    match cli.command {
        Command::Run(args) => Action::Run(Box::new(build_config(args))),
        Command::Links(args) => {
            let file = args.config.as_ref().map(load_config_file);
            let secrets = resolve_secrets(file.as_ref(), &args.secrets);
            let tls_domain = file.as_ref().and_then(|f| f.tls.domain.clone()).unwrap_or(args.tls_domain);
            Action::Links { secrets, tls_domain, port: args.port }
        }
        Command::Check(args) => {
            let file = args.config.as_ref().map(load_config_file);
            let secrets = resolve_secrets(file.as_ref(), &args.secrets);
            let tls_domain = file.as_ref().and_then(|f| f.tls.domain.clone()).unwrap_or(args.tls_domain);
            Action::Check { secrets, tls_domain }
        }
        Command::Secret => Action::GenerateSecret,
    }
}

fn build_config(args: RunArgs) -> Config {
    let file = args.config.as_ref().map(load_config_file);

    let bind = file.as_ref().and_then(|f| f.server.bind.clone()).unwrap_or(args.bind);
    let port = file.as_ref().and_then(|f| f.server.port).unwrap_or(args.port);
    let workers = file.as_ref().and_then(|f| f.server.workers).unwrap_or(args.workers);
    let tls_domain = args.tls_domain;
    let log_level = file.as_ref().and_then(|f| f.logging.level.clone()).unwrap_or(args.log_level);
    let upstream = file.as_ref().and_then(|f| f.upstream.clone()).unwrap_or_default();
    let max_connections = file.as_ref().and_then(|f| f.max_connections).unwrap_or(0);
    let healthcheck = file.as_ref().and_then(|f| f.healthcheck.clone()).unwrap_or_default();

    let listen_addr: SocketAddr = format!("{bind}:{port}").parse().unwrap_or_else(|e| {
        eprintln!("exproto: bad address: {e}");
        std::process::exit(1);
    });

    let secrets = resolve_secrets(file.as_ref(), &args.secrets);

    let tag_hex = file.as_ref().and_then(|f| f.server.proxy_tag.clone()).or(args.proxy_tag);
    let ad_tag = tag_hex.as_deref().and_then(decode_tag);

    let tls = file.as_ref().map(|f| f.tls.clone()).unwrap_or_default();
    let tls_domain = tls.domain.clone().unwrap_or(tls_domain);
    let timeouts = file.as_ref().map(|f| f.timeouts.clone()).unwrap_or_default();
    let telegram = file.as_ref().and_then(|f| f.telegram.clone()).unwrap_or_default();

    Config {
        secrets, listen_addr, ad_tag, workers, tls_domain, log_level,
        aes_pwd: args.aes_pwd, upstream, max_connections, healthcheck, tls, timeouts, telegram,
    }
}
