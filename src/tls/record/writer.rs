use tokio::io::AsyncWriteExt;

const MAX_PAYLOAD: usize = 16384 + 24;
const TLS_HEADER: [u8; 3] = [0x17, 0x03, 0x03];

pub async fn write_record(stream: &mut (impl AsyncWriteExt + Unpin), data: &[u8]) -> std::io::Result<()> {
    for chunk in data.chunks(MAX_PAYLOAD) {
        let len = chunk.len() as u16;
        let len_bytes = len.to_be_bytes();
        let mut buf = Vec::with_capacity(5 + chunk.len());
        buf.extend_from_slice(&TLS_HEADER);
        buf.extend_from_slice(&len_bytes);
        buf.extend_from_slice(chunk);
        stream.write_all(&buf).await?;
    }
    Ok(())
}
