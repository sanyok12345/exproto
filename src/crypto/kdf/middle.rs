use md5::Md5;
use sha1::Sha1;
use sha2::Digest;

#[allow(clippy::too_many_arguments)]
pub fn derive_middle_key_iv(
    nonce_srv: &[u8; 16],
    nonce_clt: &[u8; 16],
    clt_ts: &[u8; 4],
    srv_ip: &[u8; 4],
    clt_port: u16,
    purpose: &[u8],
    clt_ip: &[u8; 4],
    srv_port: u16,
    proxy_secret: &[u8],
) -> ([u8; 32], [u8; 16]) {
    let mut s = Vec::with_capacity(256);
    s.extend_from_slice(nonce_srv);
    s.extend_from_slice(nonce_clt);
    s.extend_from_slice(clt_ts);
    s.extend_from_slice(srv_ip);
    s.extend_from_slice(&clt_port.to_le_bytes());
    s.extend_from_slice(purpose);
    s.extend_from_slice(clt_ip);
    s.extend_from_slice(&srv_port.to_le_bytes());
    s.extend_from_slice(proxy_secret);
    s.extend_from_slice(nonce_srv);
    s.extend_from_slice(nonce_clt);

    let md5_partial: [u8; 16] = Md5::new_with_prefix(&s[1..]).finalize().into();
    let sha1_full: [u8; 20] = Sha1::new_with_prefix(&s).finalize().into();
    let iv: [u8; 16] = Md5::new_with_prefix(&s[2..]).finalize().into();

    let mut key = [0u8; 32];
    key[..12].copy_from_slice(&md5_partial[..12]);
    key[12..32].copy_from_slice(&sha1_full);

    (key, iv)
}
