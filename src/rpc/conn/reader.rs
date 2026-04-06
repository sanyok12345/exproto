use crate::crypto::block::cbc::CbcDecryptHalf;
use crate::rpc::proxy::ans::{parse_proxy_ans, ProxyResponse};
use tokio::io::AsyncReadExt;
use tokio::net::tcp::OwnedReadHalf;

pub struct MiddleReader {
    stream: OwnedReadHalf,
    dec: CbcDecryptHalf,
    dec_buf: Vec<u8>,
}

impl MiddleReader {
    pub fn new(stream: OwnedReadHalf, dec: CbcDecryptHalf) -> Self {
        Self { stream, dec, dec_buf: Vec::new() }
    }

    async fn read_cbc(&mut self, n: usize) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        while self.dec_buf.len() < n {
            let mut block = [0u8; 16];
            self.stream.read_exact(&mut block).await?;
            self.dec.decrypt(&mut block);
            self.dec_buf.extend_from_slice(&block);
        }
        let ret = self.dec_buf[..n].to_vec();
        self.dec_buf.drain(..n);
        Ok(ret)
    }

    async fn read_frame(&mut self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        loop {
            let len_bytes = self.read_cbc(4).await?;
            let msg_len = u32::from_le_bytes(len_bytes[..4].try_into().unwrap()) as usize;
            if msg_len == 4 { continue; }
            if !(12..=(1 << 24)).contains(&msg_len) || msg_len % 4 != 0 {
                return Err(format!("bad frame len: {msg_len}").into());
            }
            let rest = self.read_cbc(msg_len - 4).await?;
            return Ok(rest[4..rest.len() - 4].to_vec());
        }
    }

    pub async fn recv_proxy_ans(&mut self) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        let data = self.read_frame().await?;
        match parse_proxy_ans(&data) {
            ProxyResponse::Data(payload) => Ok(Some(payload)),
            ProxyResponse::Closed => Err("middle-proxy closed".into()),
            ProxyResponse::Ack | ProxyResponse::Unknown => Ok(None),
        }
    }
}
