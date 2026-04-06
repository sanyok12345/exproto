use crate::cli::{Config, ProxyMode, UpstreamConfig};
use crate::mtproto::conn::state::TransportMode;
use crate::mtproto::handshake;
use crate::mtproto::init;
use crate::mtproto::dc;
use crate::net::accept::limit::ConnectionLimiter;
use crate::net::pipe;
use crate::net::pipe::middle::MiddleRelayCtx;
use crate::rpc::conn::MiddleProxyConn;
use crate::tls::hello;
use crate::tls::record;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{warn, debug, instrument};

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
pub async fn handle_connection(mut client: TcpStream, peer: SocketAddr, config: Arc<Config>, limiter: Arc<ConnectionLimiter>) {
    let _ = client.set_nodelay(true);

    let mut peek = [0u8; 3];
    if client.read_exact(&mut peek).await.is_err() {
        return;
    }

    let result = match detect_mode(&peek) {
        TransportMode::FakeTls => handle_faketls(client, peer, &config, &peek, &limiter).await,
        TransportMode::Classic => handle_classic(client, peer, &config, &peek, &limiter).await,
    };

    if let Err(e) = result {
        warn!("{e}");
    }
}

async fn handle_faketls(
    mut client: TcpStream,
    peer: SocketAddr,
    config: &Config,
    peek: &[u8; 3],
    limiter: &Arc<ConnectionLimiter>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let raw = hello::read_client_hello(&mut client, peek).await?;

    let mut hello_result = None;
    let mut matched_secret_idx = 0;

    for (i, secret) in config.secrets.iter().enumerate() {
        if let Some(result) = hello::verify_for_secret(&raw, &secret.key) {
            hello_result = Some(result);
            matched_secret_idx = i;
            break;
        }
    }

    let hello_result = hello_result.ok_or("no matching secret for ClientHello")?;
    let secret = &config.secrets[matched_secret_idx];

    let _guard = limiter.try_acquire(&secret.name)
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
    }

    let init_data = record::read_record(&mut client).await?;
    if init_data.len() < 64 {
        return Err(format!("init too short ({} bytes)", init_data.len()).into());
    }

    let mut init_buf = [0u8; 64];
    init_buf.copy_from_slice(&init_data[..64]);
    let parsed = init::parse_init(&init_buf, &secret.key)?;
    let extra = if init_data.len() > 64 { Some(init_data[64..].to_vec()) } else { None };
    let bind_addr = resolve_bind_addr(secret, config);

    debug!(dc = parsed.dc_id, proto = %parsed.proto, secret = secret.name, mode = "fake-tls", "session established");

    match secret.mode {
        ProxyMode::Direct => {
            let (upstream, dc_cipher) = handshake::connect_to_dc(parsed.dc_id, parsed.proto, bind_addr).await?;
            debug!(dc = parsed.dc_id, "upstream connected (direct)");
            pipe::tls::relay(client, upstream, parsed.cipher, dc_cipher, extra).await;
        }
        ProxyMode::MiddleProxy => {
            let tg_cfg = dc::fetch_telegram_config().await
                .map_err(|e| format!("fetch telegram config: {e}"))?;
            let addrs = tg_cfg.middle_proxies.get(&parsed.dc_id)
                .ok_or_else(|| format!("no middle-proxy for dc {}", parsed.dc_id))?;
            let idx = rand::random::<u32>() as usize % addrs.len();
            let mut middle = MiddleProxyConn::connect(addrs[idx], &tg_cfg.proxy_secret).await?;
            let conn_id: [u8; 8] = rand::random::<[u8; 16]>()[..8].try_into().unwrap();
            let our_addr = client.local_addr()?;
            let ctx = MiddleRelayCtx {
                conn_id: &conn_id, peer, our_addr,
                proto_tag: parsed.proto.to_raw(),
                ad_tag: secret.ad_tag.as_ref().or(config.ad_tag.as_ref()),
            };
            debug!(dc = parsed.dc_id, "upstream connected (middle-proxy)");
            pipe::middle::relay_faketls(&mut client, &mut middle, parsed.cipher, &ctx, extra).await;
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
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut init_buf = [0u8; 64];
    init_buf[..3].copy_from_slice(peek);
    client.read_exact(&mut init_buf[3..]).await?;

    let parsed = init::parse_init_multi(&init_buf, &config.secrets)?;

    let _guard = limiter.try_acquire(&parsed.secret_name)
        .ok_or("connection limit reached")?;

    let secret = config.secrets.iter().find(|s| s.name == parsed.secret_name);
    let mode = secret.map(|s| &s.mode).unwrap_or(&ProxyMode::Direct);
    let bind_addr = secret.map(|s| resolve_bind_addr(s, config)).unwrap_or(None);

    debug!(dc = parsed.dc_id, proto = %parsed.proto, secret = parsed.secret_name, mode = ?mode, "session established");

    match mode {
        ProxyMode::Direct => {
            let (upstream, dc_cipher) = handshake::connect_to_dc(parsed.dc_id, parsed.proto, bind_addr).await?;
            debug!(dc = parsed.dc_id, "upstream connected (direct)");
            pipe::classic::relay(client, upstream, parsed.cipher, dc_cipher).await;
        }
        ProxyMode::MiddleProxy => {
            let tg_cfg = dc::fetch_telegram_config().await
                .map_err(|e| format!("fetch telegram config: {e}"))?;
            let addrs = tg_cfg.middle_proxies.get(&parsed.dc_id)
                .ok_or_else(|| format!("no middle-proxy for dc {}", parsed.dc_id))?;
            let idx = rand::random::<u32>() as usize % addrs.len();
            let mut middle = MiddleProxyConn::connect(addrs[idx], &tg_cfg.proxy_secret).await?;
            let conn_id: [u8; 8] = rand::random::<[u8; 16]>()[..8].try_into().unwrap();
            let our_addr = client.local_addr()?;
            let ctx = MiddleRelayCtx {
                conn_id: &conn_id, peer, our_addr,
                proto_tag: parsed.proto.to_raw(),
                ad_tag: secret.and_then(|s| s.ad_tag.as_ref()).or(config.ad_tag.as_ref()),
            };
            debug!(dc = parsed.dc_id, "upstream connected (middle-proxy)");
            pipe::middle::relay_classic(client, &mut middle, parsed.cipher, &ctx).await;
        }
    }

    debug!("session closed");
    Ok(())
}
