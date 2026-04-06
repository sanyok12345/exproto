use crate::crypto::stream::cipher::ObfuscatedCipher;
use crate::tls::record::{read_record, write_record};
use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::trace;

const DC_BUF_SIZE: usize = 16384;

pub async fn relay(
    client: &mut TcpStream,
    upstream: TcpStream,
    mut client_cipher: ObfuscatedCipher,
    mut dc_cipher: ObfuscatedCipher,
    initial_extra: Option<Vec<u8>>,
) {
    let (mut ur, mut uw) = upstream.into_split();

    if let Some(mut extra) = initial_extra {
        client_cipher.decrypt_in_place(&mut extra);
        dc_cipher.encrypt_in_place(&mut extra);
        if uw.write_all(&extra).await.is_err() { return; }
        trace!(bytes = extra.len(), "relay: forwarded init overflow");
    }

    let mut client_buf = BytesMut::with_capacity(DC_BUF_SIZE);

    loop {
        let mut dc_buf = [0u8; DC_BUF_SIZE];

        tokio::select! {
            result = read_record(client) => {
                match result {
                    Ok(data) if !data.is_empty() => {
                        client_buf.clear();
                        client_buf.extend_from_slice(&data);
                        client_cipher.decrypt_in_place(&mut client_buf);
                        dc_cipher.encrypt_in_place(&mut client_buf);
                        if uw.write_all(&client_buf).await.is_err() { break; }
                        trace!(bytes = client_buf.len(), "relay: client[tls] -> DC");
                    }
                    _ => break,
                }
            }
            result = ur.read(&mut dc_buf) => {
                match result {
                    Ok(n @ 1..) => {
                        dc_cipher.decrypt_in_place(&mut dc_buf[..n]);
                        client_cipher.encrypt_in_place(&mut dc_buf[..n]);
                        if write_record(client, &dc_buf[..n]).await.is_err() { break; }
                        trace!(bytes = n, "relay: DC -> client[tls]");
                    }
                    _ => break,
                }
            }
        }
    }
}
