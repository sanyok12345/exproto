use crate::tls::verify::hmac::verify_digest;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tracing::trace;

const DIGEST_POS: usize = 11;
const DIGEST_LEN: usize = 32;
const SESSION_ID_LEN_POS: usize = 43;
const SESSION_ID_POS: usize = 44;

pub struct ClientHelloResult {
    pub session_id: Vec<u8>,
    pub digest: Vec<u8>,
    pub timestamp: u32,
}

pub struct RawClientHello {
    pub handshake: Vec<u8>,
}

pub async fn read_client_hello(
    stream: &mut TcpStream,
    first_bytes: &[u8; 3],
) -> Result<RawClientHello, Box<dyn std::error::Error + Send + Sync>> {
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let tls_len = u16::from_be_bytes(len_buf) as usize;

    if tls_len < 512 {
        return Err(format!("ExProto: ClientHello too short ({tls_len} bytes)").into());
    }

    let mut body = vec![0u8; tls_len];
    stream.read_exact(&mut body).await?;

    let mut handshake = Vec::with_capacity(5 + tls_len);
    handshake.extend_from_slice(first_bytes);
    handshake.extend_from_slice(&len_buf);
    handshake.extend_from_slice(&body);

    trace!(len = handshake.len(), "ClientHello read");
    Ok(RawClientHello { handshake })
}

pub fn verify_for_secret(raw: &RawClientHello, secret: &[u8]) -> Option<ClientHelloResult> {
    let handshake = &raw.handshake;

    if handshake.len() < SESSION_ID_POS + 1 {
        return None;
    }

    let timestamp = verify_digest(handshake, secret)?;

    let digest = handshake[DIGEST_POS..DIGEST_POS + DIGEST_LEN].to_vec();
    let sess_id_len = handshake[SESSION_ID_LEN_POS] as usize;
    let session_id = handshake[SESSION_ID_POS..SESSION_ID_POS + sess_id_len].to_vec();

    Some(ClientHelloResult { session_id, digest, timestamp })
}
