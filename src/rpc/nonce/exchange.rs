use crate::rpc::frame::make_frame;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const RPC_NONCE: u32 = 0x7acb87aa;
const CRYPTO_AES: u32 = 1;

pub struct NonceResult {
    pub nonce_srv: [u8; 16],
    pub nonce_clt: [u8; 16],
    pub timestamp: u32,
}

pub async fn perform_nonce_exchange(
    stream: &mut TcpStream,
    proxy_secret: &[u8],
) -> Result<NonceResult, Box<dyn std::error::Error + Send + Sync>> {
    let nonce_clt: [u8; 16] = rand::random::<[u8; 16]>();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;

    let key_selector = &proxy_secret[0..4];

    let mut msg = Vec::with_capacity(32);
    msg.extend_from_slice(&RPC_NONCE.to_le_bytes());
    msg.extend_from_slice(key_selector);
    msg.extend_from_slice(&CRYPTO_AES.to_le_bytes());
    msg.extend_from_slice(&ts.to_le_bytes());
    msg.extend_from_slice(&nonce_clt);

    let frame = make_frame(-2, &msg);
    stream.write_all(&frame).await?;

    let mut len_buf = [0u8; 4];
    loop {
        stream.read_exact(&mut len_buf).await?;
        let msg_len = u32::from_le_bytes(len_buf) as usize;
        if msg_len == 4 { continue; }
        if msg_len < 12 { return Err("ExProto: bad nonce response".into()); }

        let mut rest = vec![0u8; msg_len - 4];
        stream.read_exact(&mut rest).await?;
        let data = &rest[4..rest.len() - 4];

        if data.len() < 32 { return Err("ExProto: nonce response truncated".into()); }
        let resp_type = u32::from_le_bytes(data[0..4].try_into().unwrap());
        if resp_type != RPC_NONCE { return Err("ExProto: unexpected nonce response type".into()); }

        let nonce_srv: [u8; 16] = data[16..32].try_into().unwrap();

        return Ok(NonceResult { nonce_srv, nonce_clt, timestamp: ts });
    }
}
