use crate::crypto::stream::cipher::ObfuscatedCipher;
use crate::crypto::stream::ctr::Aes256Ctr;
use crate::engine::error::ProtocolError;
use crate::mtproto::conn::state::ProtoTag;
use crate::mtproto::dc;
use crate::net::socket::configure_socket;
use super::pattern;
use ctr::cipher::{KeyIvInit, StreamCipher};
use rand::RngCore as _;
use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::debug;

fn generate_init(proto: ProtoTag) -> [u8; 64] {
    let mut rng = rand::rng();
    let tag = proto.to_raw().to_le_bytes();

    loop {
        let mut init = [0u8; 64];
        rng.fill_bytes(&mut init[..]);
        init[56..60].copy_from_slice(&tag);

        if !pattern::is_reserved(&init) {
            return init;
        }
    }
}

async fn tcp_connect_with_bind(
    addr: &str,
    bind_addr: Option<&str>,
) -> Result<TcpStream, ProtocolError> {
    match bind_addr {
        Some(bind_ip) => {
            let remote: SocketAddr = addr.parse().map_err(|_| ProtocolError::InvalidDc(0))?;
            let bind: SocketAddr = format!("{bind_ip}:0").parse().map_err(|_| ProtocolError::InvalidDc(0))?;

            let socket = match remote {
                SocketAddr::V4(_) => socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None),
                SocketAddr::V6(_) => socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::STREAM, None),
            }.map_err(ProtocolError::UpstreamConnect)?;

            socket.set_nonblocking(true).map_err(ProtocolError::UpstreamConnect)?;
            socket.bind(&bind.into()).map_err(ProtocolError::UpstreamConnect)?;
            let _ = socket.connect(&remote.into());

            let std_stream: std::net::TcpStream = socket.into();
            let stream = TcpStream::from_std(std_stream).map_err(ProtocolError::UpstreamConnect)?;

            stream.writable().await.map_err(ProtocolError::Io)?;
            if let Some(err) = stream.take_error().map_err(ProtocolError::Io)? {
                return Err(ProtocolError::UpstreamConnect(err));
            }

            Ok(stream)
        }
        None => {
            TcpStream::connect(addr).await.map_err(ProtocolError::UpstreamConnect)
        }
    }
}

pub async fn connect_to_dc(
    dc_id: i16,
    proto: ProtoTag,
    bind_addr: Option<&str>,
) -> Result<(TcpStream, ObfuscatedCipher), ProtocolError> {
    let addr = dc::resolve_dc(dc_id)?;
    let mut stream = tcp_connect_with_bind(addr, bind_addr).await?;
    configure_socket(&stream);

    let init = generate_init(proto);

    let dec_kiv: Vec<u8> = init[8..56].iter().rev().copied().collect();
    let enc_key: [u8; 32] = init[8..40].try_into().unwrap();
    let enc_iv: [u8; 16] = init[40..56].try_into().unwrap();
    let dec_key: [u8; 32] = dec_kiv[..32].try_into().unwrap();
    let dec_iv: [u8; 16] = dec_kiv[32..48].try_into().unwrap();

    let mut encryptor = Aes256Ctr::new(&enc_key.into(), &enc_iv.into());
    let mut init_wire = init;
    let mut tmp = init;
    encryptor.apply_keystream(&mut tmp);
    init_wire[56..].copy_from_slice(&tmp[56..]);

    let mut encryptor = Aes256Ctr::new(&enc_key.into(), &enc_iv.into());
    let mut skip = [0u8; 64];
    encryptor.apply_keystream(&mut skip);

    let decryptor = Aes256Ctr::new(&dec_key.into(), &dec_iv.into());

    stream.write_all(&init_wire).await.map_err(ProtocolError::Io)?;
    stream.flush().await.map_err(ProtocolError::Io)?;

    debug!(dc = dc_id, addr, "DC handshake complete");

    Ok((stream, ObfuscatedCipher { encrypt: encryptor, decrypt: decryptor }))
}
