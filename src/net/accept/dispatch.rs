use crate::cli::{Config, ProxyMode, UpstreamConfig};
use crate::engine::error::ProtocolError;
use crate::mtproto::conn::state::TransportMode;
use crate::mtproto::handshake;
use crate::mtproto::init;
use crate::mtproto::dc::TelegramConfigCache;
use crate::net::accept::limit::ConnectionLimiter;
use crate::net::pipe;
use crate::net::pipe::middle::MiddleRelayCtx;
use crate::net::socket::configure_socket;
use crate::rpc::conn::MiddleProxyConn;
use crate::tls::hello;
use crate::tls::record;
use crate::tls::record::writer::RecordWriteConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{warn, debug, instrument};

#[allow(clippy::borrowed_box)]
fn is_probe_noise(e: &Box<dyn std::error::Error + Send + Sync>) -> bool {
    if e.downcast_ref::<ProtocolError>().is_some_and(|p| p.is_probe_noise()) {
        return true;
    }
    let msg = e.to_string();
    msg.contains("no matching secret") || msg.contains("connection limit") || msg.contains("init too short")
}

const TLS_PREFIX: [u8; 3] = [0x16, 0x03, 0x01];

fn detect_mode(peek: &[u8; 3]) -> TransportMode {
    if *peek == TLS_PREFIX { TransportMode::FakeTls } else { TransportMode::Classic }
}

fn resolve_bind_addr<'a>(secret: &'a crate::cli::Secret, config: &'a Config) -> Option<&'a str> {
    let upstream = secret.upstream.as_ref().unwrap_or(&config.upstream);
    match upstream {
        UpstreamConfig::Direct { bind } => bind.as_deref(),
        _ => None,
    }
}

#[instrument(skip_all, fields(peer = %peer))]
pub async fn handle_connection(
    mut client: TcpStream,
    peer: SocketAddr,
    config: Arc<Config>,
    limiter: Arc<ConnectionLimiter>,
    tg_cache: Arc<TelegramConfigCache>,
) {
    configure_socket(&client);

    let hs_timeout = Duration::from_secs(config.timeouts.handshake);
    let mut peek = [0u8; 3];
    if timeout(hs_timeout, client.read_exact(&mut peek)).await.is_err() || peek == [0; 3] {
        return;
    }

    let result = match detect_mode(&peek) {
        TransportMode::FakeTls => handle_faketls(client, peer, &config, &peek, &limiter, &tg_cache).await,
        TransportMode::Classic => handle_classic(client, peer, &config, &peek, &limiter, &tg_cache).await,
    };

    if let Err(e) = result {
        if is_probe_noise(&e) {
            debug!("{e}");
        } else {
            warn!("{e}");
        }
    }
}

async fn handle_faketls(
    mut client: TcpStream,
    peer: SocketAddr,
    config: &Config,
    peek: &[u8; 3],
    limiter: &Arc<ConnectionLimiter>,
    tg_cache: &Arc<TelegramConfigCache>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let hs_timeout = Duration::from_secs(config.timeouts.handshake);
    let conn_timeout = Duration::from_secs(config.timeouts.connect);

    let raw = timeout(hs_timeout, hello::read_client_hello(&mut client, peek))
        .await
        .map_err(|_| "handshake timeout reading ClientHello")??;

    let mut hello_result = None;
    let mut matched_secret_idx = 0;

    for (i, secret) in config.secrets.iter().enumerate() {
        if let Some(result) = hello::verify_for_secret(&raw, &secret.key) {
            hello_result = Some(result);
            matched_secret_idx = i;
            break;
        }
    }

    let hello_result = match hello_result {
        Some(r) => r,
        None => {
            if let Some(ref fb) = config.tls.fallback {
                debug!(peer = %peer, "no matching secret, falling back");
                pipe::fallback::relay_to_fallback(client, &raw.handshake, fb).await;
                return Ok(());
            }
            return Err("no matching secret for ClientHello".into());
        }
    };
    let secret = &config.secrets[matched_secret_idx];

    let _guard = limiter.try_acquire(matched_secret_idx)
        .ok_or("connection limit reached")?;

    debug!(secret = secret.name, "fake-TLS handshake verified");

    let hello = hello::build_server_hello(&secret.key, &hello_result.digest, &hello_result.session_id);
    if config.tls.handshake.fragment {
        client.write_all(&hello.handshake).await?;
        client.flush().await?;
        client.write_all(&hello.change_cipher).await?;
        client.flush().await?;
        client.write_all(&hello.app_data).await?;
        client.flush().await?;
    } else {
        client.write_all(&hello.handshake).await?;
        client.write_all(&hello.change_cipher).await?;
        client.write_all(&hello.app_data).await?;
        client.flush().await?;
    }

    let init_data = timeout(hs_timeout, record::read_record(&mut client))
        .await
        .map_err(|_| "handshake timeout reading MTProto init")??;
    if init_data.len() < 64 {
        return Err(format!("init too short ({} bytes)", init_data.len()).into());
    }

    let mut init_buf = [0u8; 64];
    init_buf.copy_from_slice(&init_data[..64]);
    let parsed = init::parse_init(&init_buf, &secret.key)?;
    let extra = if init_data.len() > 64 { Some(init_data[64..].to_vec()) } else { None };
    let bind_addr = resolve_bind_addr(secret, config);

    debug!(dc = parsed.dc_id, proto = %parsed.proto, secret = secret.name, mode = "fake-tls", "session established");

    let idle = Duration::from_secs(config.timeouts.idle);

    match secret.mode {
        ProxyMode::Direct => {
            let (upstream, dc_cipher) = timeout(conn_timeout, handshake::connect_to_dc(parsed.dc_id, parsed.proto, bind_addr))
                .await
                .map_err(|_| "connect timeout to DC")??;
            debug!(dc = parsed.dc_id, "upstream connected (direct)");
            let write_cfg = RecordWriteConfig {
                max_record_size: config.tls.stream.max_record_size,
                record_jitter: config.tls.stream.record_jitter,
            };
            pipe::tls::relay(client, upstream, parsed.cipher, dc_cipher, extra, write_cfg, idle).await;
        }
        ProxyMode::MiddleProxy => {
            let tg_cfg = tg_cache.get();
            let addrs = tg_cfg.middle_proxies.get(&parsed.dc_id)
                .ok_or_else(|| format!("no middle-proxy for dc {}", parsed.dc_id))?;
            let idx = rand::random::<u32>() as usize % addrs.len();
            let middle = timeout(conn_timeout, MiddleProxyConn::connect(addrs[idx], &tg_cfg.proxy_secret))
                .await
                .map_err(|_| "connect timeout to middle-proxy")??;
            let conn_id: [u8; 8] = rand::random::<[u8; 16]>()[..8].try_into().unwrap();
            let our_addr = client.local_addr()?;
            let ctx = MiddleRelayCtx {
                conn_id: &conn_id, peer, our_addr,
                proto_tag: parsed.proto.to_raw(),
                ad_tag: secret.ad_tag.as_ref().or(config.ad_tag.as_ref()),
            };
            debug!(dc = parsed.dc_id, "upstream connected (middle-proxy)");
            pipe::middle::relay_faketls(client, middle, parsed.cipher, &ctx, extra, idle).await;
        }
    }

    debug!("session closed");
    Ok(())
}

async fn handle_classic(
    mut client: TcpStream,
    peer: SocketAddr,
    config: &Config,
    peek: &[u8; 3],
    limiter: &Arc<ConnectionLimiter>,
    tg_cache: &Arc<TelegramConfigCache>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let hs_timeout = Duration::from_secs(config.timeouts.handshake);
    let conn_timeout = Duration::from_secs(config.timeouts.connect);

    let mut init_buf = [0u8; 64];
    init_buf[..3].copy_from_slice(peek);
    timeout(hs_timeout, client.read_exact(&mut init_buf[3..]))
        .await
        .map_err(|_| "handshake timeout reading classic init")??;

    let parsed = init::parse_init_multi(&init_buf, &config.secrets)?;

    let secret_idx = config.secrets.iter().position(|s| s.name == parsed.secret_name);
    let _guard = limiter.try_acquire(secret_idx.unwrap_or(usize::MAX))
        .ok_or("connection limit reached")?;

    let secret = secret_idx.map(|i| &config.secrets[i]);
    let mode = secret.map(|s| &s.mode).unwrap_or(&ProxyMode::Direct);
    let bind_addr = secret.map(|s| resolve_bind_addr(s, config)).unwrap_or(None);

    debug!(dc = parsed.dc_id, proto = %parsed.proto, secret = parsed.secret_name, mode = ?mode, "session established");

    let idle = Duration::from_secs(config.timeouts.idle);

    match mode {
        ProxyMode::Direct => {
            let (upstream, dc_cipher) = timeout(conn_timeout, handshake::connect_to_dc(parsed.dc_id, parsed.proto, bind_addr))
                .await
                .map_err(|_| "connect timeout to DC")??;
            debug!(dc = parsed.dc_id, "upstream connected (direct)");
            pipe::classic::relay(client, upstream, parsed.cipher, dc_cipher, idle).await;
        }
        ProxyMode::MiddleProxy => {
            let tg_cfg = tg_cache.get();
            let addrs = tg_cfg.middle_proxies.get(&parsed.dc_id)
                .ok_or_else(|| format!("no middle-proxy for dc {}", parsed.dc_id))?;
            let idx = rand::random::<u32>() as usize % addrs.len();
            let middle = timeout(conn_timeout, MiddleProxyConn::connect(addrs[idx], &tg_cfg.proxy_secret))
                .await
                .map_err(|_| "connect timeout to middle-proxy")??;
            let conn_id: [u8; 8] = rand::random::<[u8; 16]>()[..8].try_into().unwrap();
            let our_addr = client.local_addr()?;
            let ctx = MiddleRelayCtx {
                conn_id: &conn_id, peer, our_addr,
                proto_tag: parsed.proto.to_raw(),
                ad_tag: secret.and_then(|s| s.ad_tag.as_ref()).or(config.ad_tag.as_ref()),
            };
            debug!(dc = parsed.dc_id, "upstream connected (middle-proxy)");
            pipe::middle::relay_classic(client, middle, parsed.cipher, &ctx, idle).await;
        }
    }

    debug!("session closed");
    Ok(())
}
