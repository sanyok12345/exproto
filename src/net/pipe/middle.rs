use crate::crypto::stream::cipher::ObfuscatedCipher;
use crate::rpc::conn::MiddleProxyConn;
use crate::tls::record::{read_record, write_record};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, trace};

pub struct MiddleRelayCtx<'a> {
    pub conn_id: &'a [u8; 8],
    pub peer: SocketAddr,
    pub our_addr: SocketAddr,
    pub proto_tag: u32,
    pub ad_tag: Option<&'a [u8; 16]>,
}

pub async fn relay_classic(
    client: TcpStream,
    middle: MiddleProxyConn,
    client_cipher: ObfuscatedCipher,
    ctx: &MiddleRelayCtx<'_>,
    idle: Duration,
) {
    let (mut client_dec, mut client_enc) = client_cipher.into_halves();
    let (mut cr, mut cw) = client.into_split();
    let (mut mr, mut mw) = middle.into_halves();

    let conn_id = *ctx.conn_id;
    let peer = ctx.peer;
    let our_addr = ctx.our_addr;
    let proto_tag = ctx.proto_tag;
    let ad_tag = ctx.ad_tag.copied();

    let c2m = tokio::spawn(async move {
        let mut buf = [0u8; 16384];
        let mut total: u64 = 0;
        while let Ok(Ok(n @ 1..)) = timeout(idle, cr.read(&mut buf)).await {
            client_dec.apply(&mut buf[..n]);
            if mw.send_proxy_req(&conn_id, peer, our_addr, proto_tag, ad_tag.as_ref(), &buf[..n]).await.is_err() { break; }
            total += n as u64;
            trace!(bytes = n, total, "relay: client -> middle");
        }
        debug!(total_bytes = total, "relay: client -> middle done");
    });

    let m2c = tokio::spawn(async move {
        let mut total: u64 = 0;
        loop {
            match timeout(idle, mr.recv_proxy_ans()).await {
                Ok(Ok(Some(mut data))) => {
                    client_enc.apply(&mut data);
                    if cw.write_all(&data).await.is_err() { break; }
                    total += data.len() as u64;
                    trace!(bytes = data.len(), total, "relay: middle -> client");
                }
                Ok(Ok(None)) => {}
                _ => break,
            }
        }
        debug!(total_bytes = total, "relay: middle -> client done");
    });

    let _ = tokio::join!(c2m, m2c);
}

pub async fn relay_faketls(
    client: TcpStream,
    middle: MiddleProxyConn,
    mut client_cipher: ObfuscatedCipher,
    ctx: &MiddleRelayCtx<'_>,
    initial_extra: Option<Vec<u8>>,
    idle: Duration,
) {
    let (mut mr, mut mw) = middle.into_halves();

    if let Some(mut extra) = initial_extra {
        client_cipher.decrypt_in_place(&mut extra);
        if mw.send_proxy_req(ctx.conn_id, ctx.peer, ctx.our_addr, ctx.proto_tag, ctx.ad_tag, &extra).await.is_err() { return; }
    }

    let (mut client_dec, mut client_enc) = client_cipher.into_halves();
    let (mut cr, mut cw) = client.into_split();

    let conn_id = *ctx.conn_id;
    let peer = ctx.peer;
    let our_addr = ctx.our_addr;
    let proto_tag = ctx.proto_tag;
    let ad_tag = ctx.ad_tag.copied();

    let c2m = tokio::spawn(async move {
        let mut total: u64 = 0;
        loop {
            match timeout(idle, read_record(&mut cr)).await {
                Ok(Ok(data)) if !data.is_empty() => {
                    let mut buf = data;
                    client_dec.apply(&mut buf);
                    if mw.send_proxy_req(&conn_id, peer, our_addr, proto_tag, ad_tag.as_ref(), &buf).await.is_err() { break; }
                    total += buf.len() as u64;
                    trace!(bytes = buf.len(), total, "relay: client[tls] -> middle");
                }
                _ => break,
            }
        }
        debug!(total_bytes = total, "relay: client[tls] -> middle done");
    });

    let m2c = tokio::spawn(async move {
        let mut total: u64 = 0;
        loop {
            match timeout(idle, mr.recv_proxy_ans()).await {
                Ok(Ok(Some(mut data))) => {
                    client_enc.apply(&mut data);
                    if write_record(&mut cw, &data).await.is_err() { break; }
                    total += data.len() as u64;
                    trace!(bytes = data.len(), total, "relay: middle -> client[tls]");
                }
                Ok(Ok(None)) => {}
                _ => break,
            }
        }
        debug!(total_bytes = total, "relay: middle -> client[tls] done");
    });

    let _ = tokio::join!(c2m, m2c);
}
