use sha2::{Digest, Sha256};

pub fn derive_obfs2_key(pre_key: &[u8], secret: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(pre_key);
    hasher.update(secret);
    hasher.finalize().into()
}
