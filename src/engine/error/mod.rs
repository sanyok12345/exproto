mod transport;
mod protocol;
mod crypto;

pub use transport::TransportError;
pub use protocol::ProtocolError;
pub use crypto::CryptoError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("transport: {0}")]
    Transport(#[from] TransportError),

    #[error("protocol: {0}")]
    Protocol(#[from] ProtocolError),

    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
