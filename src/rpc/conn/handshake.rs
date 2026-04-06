use crate::crypto::block::cbc::CbcCipher;
use crate::crypto::kdf::middle::derive_middle_key_iv;
use crate::net::socket::configure_socket;
use crate::rpc::frame::make_frame;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

const RPC_NONCE: u32 = 0x7acb87aa;
const RPC_HANDSHAKE: u32 = 0x7682eef5;
const CRYPTO_AES: u32 = 1;
const SENDER_PID: &[u8; 12] = b"IPIPPRPDTIME";

pub async fn handshake(
    addr: SocketAddr,
    proxy_secret: &[u8],
) -> Result<(TcpStream, CbcCipher), Box<dyn std::error::Error + Send + Sync>> {
    let mut stream = TcpStream::connect(addr).await?;
    configure_socket(&stream);

    let local_addr = stream.local_addr()?;
    let srv_ip4 = match addr {
        SocketAddr::V4(a) => *a.ip(),
        _ => return Err("ipv4 only".into()),
    };
    let clt_ip4 = match local_addr {
        SocketAddr::V4(a) => *a.ip(),
        _ => Ipv4Addr::new(127, 0, 0, 1),
    };

    let nonce_clt: [u8; 16] = rand::random::<[u8; 16]>();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;

    let mut nonce_msg = Vec::with_capacity(32);
    nonce_msg.extend_from_slice(&RPC_NONCE.to_le_bytes());
    nonce_msg.extend_from_slice(&proxy_secret[0..4]);
    nonce_msg.extend_from_slice(&CRYPTO_AES.to_le_bytes());
    nonce_msg.extend_from_slice(&ts.to_le_bytes());
    nonce_msg.extend_from_slice(&nonce_clt);

    let frame = make_frame(-2, &nonce_msg);
    stream.write_all(&frame).await?;

    let resp = read_frame_unencrypted(&mut stream).await?;
    if resp.len() != 32 { return Err("bad nonce response".into()); }
    if u32::from_le_bytes(resp[0..4].try_into().unwrap()) != RPC_NONCE {
        return Err("unexpected nonce response".into());
    }
    let nonce_srv: [u8; 16] = resp[16..32].try_into().unwrap();

    let srv_ip_rev = rev_ip(srv_ip4);
    let clt_ip_rev = rev_ip(clt_ip4);
    let ts_bytes = ts.to_le_bytes();

    let (enc_key, enc_iv) = derive_middle_key_iv(
        &nonce_srv, &nonce_clt, &ts_bytes,
        &srv_ip_rev, local_addr.port(), b"CLIENT", &clt_ip_rev, addr.port(),
        proxy_secret,
    );
    let (dec_key, dec_iv) = derive_middle_key_iv(
        &nonce_srv, &nonce_clt, &ts_bytes,
        &srv_ip_rev, local_addr.port(), b"SERVER", &clt_ip_rev, addr.port(),
        proxy_secret,
    );

    let mut cbc = CbcCipher::new(enc_key, enc_iv, dec_key, dec_iv);

    let mut hs_msg = Vec::with_capacity(32);
    hs_msg.extend_from_slice(&RPC_HANDSHAKE.to_le_bytes());
    hs_msg.extend_from_slice(&[0u8; 4]);
    hs_msg.extend_from_slice(SENDER_PID);
    hs_msg.extend_from_slice(SENDER_PID);

    let mut frame = make_frame(-1, &hs_msg);
    cbc.encrypt(&mut frame);
    stream.write_all(&frame).await?;

    let mut dec_buf = Vec::new();
    let resp = read_frame_cbc(&mut stream, &mut cbc, &mut dec_buf).await?;
    if resp.len() != 32 { return Err("bad handshake response".into()); }
    if u32::from_le_bytes(resp[0..4].try_into().unwrap()) != RPC_HANDSHAKE {
        return Err("unexpected handshake response".into());
    }

    debug!("middle-proxy handshake complete");
    Ok((stream, cbc))
}

async fn read_frame_unencrypted(stream: &mut TcpStream) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    loop {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let msg_len = u32::from_le_bytes(len_buf) as usize;
        if msg_len == 4 { continue; }
        if msg_len < 12 { return Err("bad frame".into()); }
        let mut rest = vec![0u8; msg_len - 4];
        stream.read_exact(&mut rest).await?;
        return Ok(rest[4..rest.len() - 4].to_vec());
    }
}

async fn read_frame_cbc(
    stream: &mut TcpStream,
    cbc: &mut CbcCipher,
    dec_buf: &mut Vec<u8>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    loop {
        while dec_buf.len() < 4 {
            let mut block = [0u8; 16];
            stream.read_exact(&mut block).await?;
            cbc.decrypt(&mut block);
            dec_buf.extend_from_slice(&block);
        }
        let len_bytes: [u8; 4] = dec_buf[..4].try_into().unwrap();
        let msg_len = u32::from_le_bytes(len_bytes) as usize;
        if msg_len == 4 { dec_buf.drain(..4); continue; }
        if !(12..=(1 << 24)).contains(&msg_len) || msg_len % 4 != 0 {
            return Err(format!("bad frame len: {msg_len}").into());
        }
        while dec_buf.len() < msg_len {
            let mut block = [0u8; 16];
            stream.read_exact(&mut block).await?;
            cbc.decrypt(&mut block);
            dec_buf.extend_from_slice(&block);
        }
        let data = dec_buf[4..msg_len].to_vec();
        dec_buf.drain(..msg_len);
        return Ok(data[4..data.len() - 4].to_vec());
    }
}

fn rev_ip(ip: Ipv4Addr) -> [u8; 4] {
    let o = ip.octets();
    [o[3], o[2], o[1], o[0]]
}
