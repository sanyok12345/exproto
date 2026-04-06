use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

const MAX_PAYLOAD: usize = 16384 + 24;

pub async fn write_record(stream: &mut TcpStream, data: &[u8]) -> std::io::Result<()> {
    for chunk in data.chunks(MAX_PAYLOAD) {
        let len = chunk.len() as u16;
        stream.write_all(&[0x17, 0x03, 0x03]).await?;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(chunk).await?;
    }
    Ok(())
}
