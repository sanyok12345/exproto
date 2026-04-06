use crate::crypto::stream::cipher::ObfuscatedCipher;
use crate::rpc::conn::MiddleProxyConn;
use crate::tls::record::{read_record, write_record};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::trace;

pub struct MiddleRelayCtx<'a> {
    pub conn_id: &'a [u8; 8],
    pub peer: SocketAddr,
    pub our_addr: SocketAddr,
    pub proto_tag: u32,
    pub ad_tag: Option<&'a [u8; 16]>,
}

pub async fn relay_classic(
    mut client: TcpStream,
    middle: &mut MiddleProxyConn,
    mut client_cipher: ObfuscatedCipher,
    ctx: &MiddleRelayCtx<'_>,
) {
    let mut buf = [0u8; 16384];
    loop {
        tokio::select! {
            result = client.read(&mut buf) => {
                match result {
                    Ok(n @ 1..) => {
                        client_cipher.decrypt_in_place(&mut buf[..n]);
                        if middle.send_proxy_req(ctx.conn_id, ctx.peer, ctx.our_addr, ctx.proto_tag, ctx.ad_tag, &buf[..n]).await.is_err() { break; }
                        trace!(bytes = n, "relay: client -> middle");
                    }
                    _ => break,
                }
            }
            result = middle.recv_proxy_ans() => {
                match result {
                    Ok(Some(data)) => {
                        let mut out = data;
                        client_cipher.encrypt_in_place(&mut out);
                        if client.write_all(&out).await.is_err() { break; }
                        trace!(bytes = out.len(), "relay: middle -> client");
                    }
                    Ok(None) => {}
                    Err(_) => break,
                }
            }
        }
    }
}

pub async fn relay_faketls(
    client: &mut TcpStream,
    middle: &mut MiddleProxyConn,
    mut client_cipher: ObfuscatedCipher,
    ctx: &MiddleRelayCtx<'_>,
    initial_extra: Option<Vec<u8>>,
) {
    if let Some(mut extra) = initial_extra {
        client_cipher.decrypt_in_place(&mut extra);
        if middle.send_proxy_req(ctx.conn_id, ctx.peer, ctx.our_addr, ctx.proto_tag, ctx.ad_tag, &extra).await.is_err() { return; }
    }

    loop {
        tokio::select! {
            result = read_record(client) => {
                match result {
                    Ok(data) if !data.is_empty() => {
                        let mut buf = data;
                        client_cipher.decrypt_in_place(&mut buf);
                        if middle.send_proxy_req(ctx.conn_id, ctx.peer, ctx.our_addr, ctx.proto_tag, ctx.ad_tag, &buf).await.is_err() { break; }
                        trace!(bytes = buf.len(), "relay: client[tls] -> middle");
                    }
                    _ => break,
                }
            }
            result = middle.recv_proxy_ans() => {
                match result {
                    Ok(Some(data)) => {
                        let mut out = data;
                        client_cipher.encrypt_in_place(&mut out);
                        if write_record(client, &out).await.is_err() { break; }
                        trace!(bytes = out.len(), "relay: middle -> client[tls]");
                    }
                    Ok(None) => {}
                    Err(_) => break,
                }
            }
        }
    }
}
