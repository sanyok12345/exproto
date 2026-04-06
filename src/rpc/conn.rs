use crate::crypto::block::cbc::CbcCipher;
use crate::crypto::kdf::middle::derive_middle_key_iv;
use crate::rpc::frame::make_frame;
use crate::rpc::proxy::req::build_proxy_req;
use crate::rpc::proxy::ans::{parse_proxy_ans, ProxyResponse};
use std::net::{Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

const RPC_NONCE: u32 = 0x7acb87aa;
const RPC_HANDSHAKE: u32 = 0x7682eef5;
const CRYPTO_AES: u32 = 1;
const SENDER_PID: &[u8; 12] = b"IPIPPRPDTIME";

pub struct MiddleProxyConn {
    stream: TcpStream,
    cbc: CbcCipher,
    send_seq: i32,
    recv_seq: i32,
    dec_buf: Vec<u8>,
}

impl MiddleProxyConn {
    pub async fn connect(
        addr: SocketAddr,
        proxy_secret: &[u8],
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut stream = TcpStream::connect(addr).await?;
        let _ = stream.set_nodelay(true);

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

        let mut conn = Self {
            stream, cbc, send_seq: 0, recv_seq: -1, dec_buf: Vec::new(),
        };

        let resp = conn.read_frame_encrypted().await?;
        if resp.len() != 32 { return Err("bad handshake response".into()); }
        if u32::from_le_bytes(resp[0..4].try_into().unwrap()) != RPC_HANDSHAKE {
            return Err("unexpected handshake response".into());
        }

        conn.recv_seq = 0;
        debug!("middle-proxy handshake complete");
        Ok(conn)
    }

    async fn read_cbc(&mut self, n: usize) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        while self.dec_buf.len() < n {
            let mut block = [0u8; 16];
            self.stream.read_exact(&mut block).await?;
            self.cbc.decrypt(&mut block);
            self.dec_buf.extend_from_slice(&block);
        }
        let ret = self.dec_buf[..n].to_vec();
        self.dec_buf.drain(..n);
        Ok(ret)
    }

    async fn read_frame_encrypted(&mut self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        loop {
            let len_bytes = self.read_cbc(4).await?;
            let msg_len = u32::from_le_bytes(len_bytes[..4].try_into().unwrap()) as usize;
            if msg_len == 4 { continue; }
            if msg_len < 12 || msg_len > (1 << 24) || msg_len % 4 != 0 {
                return Err(format!("bad frame len: {msg_len}").into());
            }
            let rest = self.read_cbc(msg_len - 4).await?;
            self.recv_seq += 1;
            return Ok(rest[4..rest.len() - 4].to_vec());
        }
    }

    async fn send_encrypted(&mut self, data: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut frame = make_frame(self.send_seq, data);
        self.send_seq += 1;
        self.cbc.encrypt(&mut frame);
        self.stream.write_all(&frame).await?;
        Ok(())
    }

    pub async fn send_proxy_req(
        &mut self,
        conn_id: &[u8; 8],
        client_addr: SocketAddr,
        our_addr: SocketAddr,
        proto_tag: u32,
        ad_tag: Option<&[u8; 16]>,
        data: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let msg = build_proxy_req(conn_id, client_addr, our_addr, proto_tag, ad_tag, data);
        self.send_encrypted(&msg).await
    }

    pub async fn recv_proxy_ans(&mut self) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        let data = self.read_frame_encrypted().await?;
        match parse_proxy_ans(&data) {
            ProxyResponse::Data(payload) => Ok(Some(payload)),
            ProxyResponse::Closed => Err("middle-proxy closed".into()),
            ProxyResponse::Ack | ProxyResponse::Unknown => Ok(None),
        }
    }
}

fn rev_ip(ip: Ipv4Addr) -> [u8; 4] {
    let o = ip.octets();
    [o[3], o[2], o[1], o[0]]
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
