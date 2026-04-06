use aes::Aes256;
use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};

pub struct CbcCipher {
    enc_cipher: Aes256,
    dec_cipher: Aes256,
    enc_iv: [u8; 16],
    dec_iv: [u8; 16],
}

impl CbcCipher {
    pub fn new(enc_key: [u8; 32], enc_iv: [u8; 16], dec_key: [u8; 32], dec_iv: [u8; 16]) -> Self {
        Self {
            enc_cipher: <Aes256 as KeyInit>::new(&enc_key.into()),
            dec_cipher: <Aes256 as KeyInit>::new(&dec_key.into()),
            enc_iv,
            dec_iv,
        }
    }

    pub fn encrypt(&mut self, data: &mut [u8]) {
        assert!(data.len() % 16 == 0);
        for chunk in data.chunks_mut(16) {
            for (c, iv) in chunk.iter_mut().zip(self.enc_iv.iter()) {
                *c ^= iv;
            }
            let block = GenericArray::from_mut_slice(chunk);
            self.enc_cipher.encrypt_block(block);
            self.enc_iv.copy_from_slice(chunk);
        }
    }

    pub fn decrypt(&mut self, data: &mut [u8]) {
        assert!(data.len() % 16 == 0);
        for chunk in data.chunks_mut(16) {
            let ct: [u8; 16] = chunk.try_into().unwrap();
            let block = GenericArray::from_mut_slice(chunk);
            self.dec_cipher.decrypt_block(block);
            for (c, iv) in chunk.iter_mut().zip(self.dec_iv.iter()) {
                *c ^= iv;
            }
            self.dec_iv = ct;
        }
    }
}
