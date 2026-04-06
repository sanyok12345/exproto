use rand::Rng;
use tokio::io::AsyncWriteExt;

const DEFAULT_MAX_PAYLOAD: usize = 16640;
const TLS_HEADER: [u8; 3] = [0x17, 0x03, 0x03];

pub struct RecordWriteConfig {
    pub max_record_size: usize,
    pub record_jitter: f64,
}

impl Default for RecordWriteConfig {
    fn default() -> Self {
        Self { max_record_size: DEFAULT_MAX_PAYLOAD, record_jitter: 0.03 }
    }
}

impl RecordWriteConfig {
    fn effective_max(&self) -> usize {
        if self.record_jitter <= 0.0 {
            return self.max_record_size;
        }
        let min = ((self.max_record_size as f64) * (1.0 - self.record_jitter)) as usize;
        rand::rng().random_range(min..=self.max_record_size)
    }
}

pub async fn write_record(stream: &mut (impl AsyncWriteExt + Unpin), data: &[u8]) -> std::io::Result<()> {
    write_record_with(stream, data, &RecordWriteConfig::default()).await
}

pub async fn write_record_with(
    stream: &mut (impl AsyncWriteExt + Unpin),
    data: &[u8],
    cfg: &RecordWriteConfig,
) -> std::io::Result<()> {
    let mut offset = 0;
    while offset < data.len() {
        let chunk_size = cfg.effective_max().min(data.len() - offset);
        let chunk = &data[offset..offset + chunk_size];
        let len = chunk.len() as u16;
        let mut buf = Vec::with_capacity(5 + chunk.len());
        buf.extend_from_slice(&TLS_HEADER);
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(chunk);
        stream.write_all(&buf).await?;
        offset += chunk_size;
    }
    Ok(())
}
