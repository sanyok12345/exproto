use crate::tls::consts::*;
use hmac::{Hmac, Mac};
use rand::{Rng, RngCore, rng};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub struct ServerHelloFragments {
    pub handshake: Vec<u8>,
    pub change_cipher: Vec<u8>,
    pub app_data: Vec<u8>,
}

pub fn build_server_hello(secret: &[u8], client_digest: &[u8], session_id: &[u8]) -> ServerHelloFragments {
    let mut r = rng();
    let fake_pubkey: [u8; 32] = r.random();

    let mut ext = Vec::with_capacity(48);
    ext.extend_from_slice(&[0x00, 0x2e]);
    ext.extend_from_slice(&[0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);
    ext.extend_from_slice(&fake_pubkey);
    ext.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);

    let mut sh = Vec::new();
    sh.extend_from_slice(&TLS_VERS_12);
    sh.extend_from_slice(&[0u8; DIGEST_LEN]);
    sh.push(session_id.len() as u8);
    sh.extend_from_slice(session_id);
    sh.extend_from_slice(&[0x13, 0x01]);
    sh.push(0x00);
    sh.extend_from_slice(&ext);

    let sh_len = sh.len();
    let mut handshake = Vec::new();
    handshake.push(TLS_HANDSHAKE);
    handshake.extend_from_slice(&TLS_VERS_12);
    handshake.extend_from_slice(&((sh_len + 4) as u16).to_be_bytes());
    handshake.push(0x02);
    handshake.push(((sh_len >> 16) & 0xff) as u8);
    handshake.push(((sh_len >> 8) & 0xff) as u8);
    handshake.push((sh_len & 0xff) as u8);
    handshake.extend_from_slice(&sh);

    let change_cipher = vec![TLS_CHANGE_CIPHER, 0x03, 0x03, 0x00, 0x01, 0x01];

    let cert_len = r.random_range(1024..4096);
    let mut cert = vec![0u8; cert_len];
    r.fill_bytes(&mut cert[..]);
    let mut app_data = Vec::with_capacity(5 + cert_len);
    app_data.push(TLS_APP_DATA);
    app_data.extend_from_slice(&TLS_VERS_12);
    app_data.extend_from_slice(&(cert_len as u16).to_be_bytes());
    app_data.extend_from_slice(&cert);

    let mut full = Vec::with_capacity(handshake.len() + change_cipher.len() + app_data.len());
    full.extend_from_slice(&handshake);
    full.extend_from_slice(&change_cipher);
    full.extend_from_slice(&app_data);

    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(client_digest);
    mac.update(&full);
    let digest = mac.finalize().into_bytes();

    handshake[DIGEST_POS..DIGEST_POS + DIGEST_LEN].copy_from_slice(&digest);

    ServerHelloFragments { handshake, change_cipher, app_data }
}
