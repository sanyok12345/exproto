#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("unknown protocol tag: 0x{0:08x}")]
    UnknownProtoTag(u32),

    #[error("invalid datacenter index: {0}")]
    InvalidDc(i16),

    #[error("obfuscated2 init too short: {0} bytes (need 64)")]
    InitTooShort(usize),

    #[error("upstream DC connection failed: {0}")]
    UpstreamConnect(#[source] std::io::Error),

    #[error("protocol io: {0}")]
    Io(#[from] std::io::Error),
}
