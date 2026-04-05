#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("ClientHello HMAC verification failed — invalid secret or replay")]
    InvalidClientHello,

    #[error("ClientHello too short: {0} bytes (minimum 512)")]
    ClientHelloTooShort(usize),

    #[error("unexpected TLS record type: 0x{0:02x}")]
    UnexpectedRecordType(u8),

    #[error("TLS record exceeds maximum size: {0} bytes")]
    RecordTooLarge(usize),

    #[error("transport io: {0}")]
    Io(#[from] std::io::Error),
}
