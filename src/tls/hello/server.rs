use hmac::{Hmac, Mac};
use rand::{Rng, RngCore, rng};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const TLS_HANDSHAKE: u8 = 0x16;
const TLS_CHANGE_CIPHER: u8 = 0x14;
const TLS_APP_DATA: u8 = 0x17;
const TLS_VERS_12: [u8; 2] = [0x03, 0x03];
const DIGEST_POS: usize = 11;
const DIGEST_LEN: usize = 32;

pub fn build_server_hello(secret: &[u8], client_digest: &[u8], session_id: &[u8]) -> Vec<u8> {
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
    let mut pkt = Vec::new();
    pkt.push(TLS_HANDSHAKE);
    pkt.extend_from_slice(&TLS_VERS_12);
    pkt.extend_from_slice(&((sh_len + 4) as u16).to_be_bytes());
    pkt.push(0x02);
    pkt.push(((sh_len >> 16) & 0xff) as u8);
    pkt.push(((sh_len >> 8) & 0xff) as u8);
    pkt.push((sh_len & 0xff) as u8);
    pkt.extend_from_slice(&sh);

    pkt.extend_from_slice(&[TLS_CHANGE_CIPHER, 0x03, 0x03, 0x00, 0x01, 0x01]);

    let cert_len = r.random_range(1024..4096);
    let mut cert = vec![0u8; cert_len];
    r.fill_bytes(&mut cert[..]);
    pkt.push(TLS_APP_DATA);
    pkt.extend_from_slice(&TLS_VERS_12);
    pkt.extend_from_slice(&(cert_len as u16).to_be_bytes());
    pkt.extend_from_slice(&cert);

    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(client_digest);
    mac.update(&pkt);
    let digest = mac.finalize().into_bytes();
    pkt[DIGEST_POS..DIGEST_POS + DIGEST_LEN].copy_from_slice(&digest);

    pkt
}
