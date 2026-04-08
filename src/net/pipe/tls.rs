use crate::crypto::stream::cipher::ObfuscatedCipher;
use crate::tls::record::writer::RecordWriteConfig;
use crate::tls::record::{read_record_into, write_record_with};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, trace};

const DC_BUF_SIZE: usize = 16384;

pub async fn relay(
    client: TcpStream,
    upstream: TcpStream,
    mut client_cipher: ObfuscatedCipher,
    mut dc_cipher: ObfuscatedCipher,
    initial_extra: Option<Vec<u8>>,
    write_cfg: RecordWriteConfig,
    idle: Duration,
) {
    let (mut cr, mut cw) = client.into_split();
    let (mut ur, mut uw) = upstream.into_split();

    if let Some(mut extra) = initial_extra {
        client_cipher.decrypt_in_place(&mut extra);
        dc_cipher.encrypt_in_place(&mut extra);
        if uw.write_all(&extra).await.is_err() { return; }
        trace!(bytes = extra.len(), "relay: forwarded init overflow");
    }

    let (mut client_dec, mut client_enc) = client_cipher.into_halves();
    let (mut dc_dec, mut dc_enc) = dc_cipher.into_halves();

    let c2s = tokio::spawn(async move {
        let mut total: u64 = 0;
        let mut buf: Vec<u8> = Vec::with_capacity(16 * 1024);
        loop {
            match timeout(idle, read_record_into(&mut cr, &mut buf)).await {
                Ok(Ok(())) if !buf.is_empty() => {
                    client_dec.apply(&mut buf);
                    dc_enc.apply(&mut buf);
                    if uw.write_all(&buf).await.is_err() { break; }
                    total += buf.len() as u64;
                    trace!(bytes = buf.len(), total, "relay: client[tls] -> DC");
                }
                _ => break,
            }
        }
        let _ = uw.shutdown().await;
        debug!(total_bytes = total, "relay: client[tls] -> DC done");
    });

    let s2c = tokio::spawn(async move {
        let mut buf = [0u8; DC_BUF_SIZE];
        let mut total: u64 = 0;
        while let Ok(Ok(n @ 1..)) = timeout(idle, ur.read(&mut buf)).await {
            dc_dec.apply(&mut buf[..n]);
            client_enc.apply(&mut buf[..n]);
            if write_record_with(&mut cw, &buf[..n], &write_cfg).await.is_err() { break; }
            total += n as u64;
            trace!(bytes = n, total, "relay: DC -> client[tls]");
        }
        let _ = cw.shutdown().await;
        debug!(total_bytes = total, "relay: DC -> client[tls] done");
    });

    let _ = tokio::join!(c2s, s2c);
}
