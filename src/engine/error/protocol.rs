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

impl ProtocolError {
    pub fn is_probe_noise(&self) -> bool {
        matches!(self, Self::UnknownProtoTag(_) | Self::InvalidDc(_) | Self::InitTooShort(_))
    }
}
