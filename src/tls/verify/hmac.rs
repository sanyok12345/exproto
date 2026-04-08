use crate::tls::consts::{DIGEST_LEN, DIGEST_POS};
use hmac::{Hmac, Mac, KeyInit};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn verify_digest(handshake: &[u8], secret: &[u8]) -> Option<u32> {
    if handshake.len() < DIGEST_POS + DIGEST_LEN {
        return None;
    }

    let digest = &handshake[DIGEST_POS..DIGEST_POS + DIGEST_LEN];

    let mut msg = handshake.to_vec();
    msg[DIGEST_POS..DIGEST_POS + DIGEST_LEN].fill(0);

    let mut mac = HmacSha256::new_from_slice(secret).ok()?;
    mac.update(&msg);
    let computed = mac.finalize().into_bytes();

    let mut xored = [0u8; DIGEST_LEN];
    for i in 0..DIGEST_LEN {
        xored[i] = digest[i] ^ computed[i];
    }

    if xored[..28] != [0u8; 28] {
        return None;
    }

    Some(u32::from_le_bytes(xored[28..32].try_into().unwrap()))
}
