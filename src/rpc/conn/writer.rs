use crate::crypto::block::cbc::CbcEncryptHalf;
use crate::rpc::frame::make_frame;
use crate::rpc::proxy::req::build_proxy_req;
use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::OwnedWriteHalf;

pub struct MiddleWriter {
    stream: OwnedWriteHalf,
    enc: CbcEncryptHalf,
    send_seq: i32,
}

impl MiddleWriter {
    pub fn new(stream: OwnedWriteHalf, enc: CbcEncryptHalf) -> Self {
        Self { stream, enc, send_seq: 0 }
    }

    async fn send_encrypted(&mut self, data: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut frame = make_frame(self.send_seq, data);
        self.send_seq += 1;
        self.enc.encrypt(&mut frame);
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
}
