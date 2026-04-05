use super::ctr::Aes256Ctr;
use ::ctr::cipher::{KeyIvInit, StreamCipher};

pub struct ObfuscatedCipher {
    pub decrypt: Aes256Ctr,
    pub encrypt: Aes256Ctr,
}

impl ObfuscatedCipher {
    pub fn new(
        dec_key: &[u8; 32], dec_iv: &[u8; 16],
        enc_key: &[u8; 32], enc_iv: &[u8; 16],
    ) -> Self {
        Self {
            decrypt: Aes256Ctr::new(dec_key.into(), dec_iv.into()),
            encrypt: Aes256Ctr::new(enc_key.into(), enc_iv.into()),
        }
    }

    pub fn into_halves(self) -> (CipherHalf, CipherHalf) {
        (CipherHalf(self.decrypt), CipherHalf(self.encrypt))
    }

    #[inline]
    pub fn decrypt_in_place(&mut self, buf: &mut [u8]) {
        self.decrypt.apply_keystream(buf);
    }

    #[inline]
    pub fn encrypt_in_place(&mut self, buf: &mut [u8]) {
        self.encrypt.apply_keystream(buf);
    }
}

pub struct CipherHalf(pub Aes256Ctr);

impl CipherHalf {
    #[inline]
    pub fn apply(&mut self, buf: &mut [u8]) {
        self.0.apply_keystream(buf);
    }
}
