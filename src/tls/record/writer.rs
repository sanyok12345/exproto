use rand::RngExt;
use std::io::IoSlice;
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
        let len = (chunk.len() as u16).to_be_bytes();
        let header = [TLS_HEADER[0], TLS_HEADER[1], TLS_HEADER[2], len[0], len[1]];
        write_all_vectored(stream, &header, chunk).await?;
        offset += chunk_size;
    }
    Ok(())
}

async fn write_all_vectored(
    stream: &mut (impl AsyncWriteExt + Unpin),
    header: &[u8],
    body: &[u8],
) -> std::io::Result<()> {
    let mut h_off = 0usize;
    let mut b_off = 0usize;
    loop {
        let slices = [
            IoSlice::new(&header[h_off..]),
            IoSlice::new(&body[b_off..]),
        ];
        let n = stream.write_vectored(&slices).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "write_vectored returned 0",
            ));
        }
        let h_rem = header.len() - h_off;
        if n >= h_rem {
            b_off += n - h_rem;
            h_off = header.len();
        } else {
            h_off += n;
        }
        if h_off == header.len() && b_off == body.len() {
            return Ok(());
        }
        if h_off == header.len() {
            stream.write_all(&body[b_off..]).await?;
            return Ok(());
        }
    }
}
