use crate::crypto::stream::cipher::ObfuscatedCipher;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, trace};

const BUF_SIZE: usize = 16384;

pub async fn relay(
    client: TcpStream,
    upstream: TcpStream,
    client_cipher: ObfuscatedCipher,
    dc_cipher: ObfuscatedCipher,
    idle: Duration,
) {
    let (mut client_dec, mut client_enc) = client_cipher.into_halves();
    let (mut dc_dec, mut dc_enc) = dc_cipher.into_halves();
    let (mut cr, mut cw) = client.into_split();
    let (mut ur, mut uw) = upstream.into_split();

    let c2s = tokio::spawn(async move {
        let mut buf = [0u8; BUF_SIZE];
        let mut total: u64 = 0;
        while let Ok(Ok(n @ 1..)) = timeout(idle, cr.read(&mut buf)).await {
            client_dec.apply(&mut buf[..n]);
            dc_enc.apply(&mut buf[..n]);
            if uw.write_all(&buf[..n]).await.is_err() { break; }
            total += n as u64;
            trace!(bytes = n, total, "relay: client -> DC");
        }
        debug!(total_bytes = total, "relay: client -> DC done");
    });

    let s2c = tokio::spawn(async move {
        let mut buf = [0u8; BUF_SIZE];
        let mut total: u64 = 0;
        while let Ok(Ok(n @ 1..)) = timeout(idle, ur.read(&mut buf)).await {
            dc_dec.apply(&mut buf[..n]);
            client_enc.apply(&mut buf[..n]);
            if cw.write_all(&buf[..n]).await.is_err() { break; }
            total += n as u64;
            trace!(bytes = n, total, "relay: DC -> client");
        }
        debug!(total_bytes = total, "relay: DC -> client done");
    });

    let _ = tokio::join!(c2s, s2c);
}
