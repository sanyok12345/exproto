#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("HMAC-SHA256 verification failed")]
    HmacMismatch,

    #[error("invalid key material length: {0} bytes")]
    InvalidKeyLength(usize),

    #[error("AES block size alignment violation: {0} bytes (must be multiple of 16)")]
    BlockAlignment(usize),
}
