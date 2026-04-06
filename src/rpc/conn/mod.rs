mod handshake;
pub mod reader;
pub mod writer;

use crate::crypto::block::cbc::CbcCipher;
use std::net::SocketAddr;
use tokio::net::TcpStream;

pub use reader::MiddleReader;
pub use writer::MiddleWriter;

pub struct MiddleProxyConn {
    stream: TcpStream,
    cbc: CbcCipher,
}

impl MiddleProxyConn {
    pub async fn connect(
        addr: SocketAddr,
        proxy_secret: &[u8],
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (stream, cbc) = handshake::handshake(addr, proxy_secret).await?;
        Ok(Self { stream, cbc })
    }

    pub fn into_halves(self) -> (MiddleReader, MiddleWriter) {
        let (enc, dec) = self.cbc.into_halves();
        let (read_half, write_half) = self.stream.into_split();
        (
            MiddleReader::new(read_half, dec),
            MiddleWriter::new(write_half, enc),
        )
    }
}
