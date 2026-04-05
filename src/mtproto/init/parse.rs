use crate::cli::Secret;
use crate::crypto::stream::cipher::ObfuscatedCipher;
use crate::crypto::kdf::obfs2::derive_obfs2_key;
use crate::engine::error::ProtocolError;
use crate::mtproto::conn::state::ProtoTag;
use ctr::cipher::StreamCipher;

pub struct ParsedInit {
    pub cipher: ObfuscatedCipher,
    pub proto: ProtoTag,
    pub dc_id: i16,
    pub secret_name: String,
}

fn try_parse(init: &[u8; 64], secret: &[u8]) -> Option<(ObfuscatedCipher, ProtoTag, i16)> {
    let dec_key = derive_obfs2_key(&init[8..40], secret);
    let dec_iv: [u8; 16] = init[40..56].try_into().unwrap();

    let mut reversed = *init;
    reversed.reverse();
    let enc_key = derive_obfs2_key(&reversed[8..40], secret);
    let enc_iv: [u8; 16] = reversed[40..56].try_into().unwrap();

    let mut cipher = ObfuscatedCipher::new(&dec_key, &dec_iv, &enc_key, &enc_iv);

    let mut decrypted = *init;
    cipher.decrypt.apply_keystream(&mut decrypted);

    let raw_tag = u32::from_le_bytes(decrypted[56..60].try_into().unwrap());
    let proto = ProtoTag::from_raw(raw_tag)?;
    let dc_id = i16::from_le_bytes(decrypted[60..62].try_into().unwrap());

    Some((cipher, proto, dc_id))
}

pub fn parse_init_multi(init: &[u8; 64], secrets: &[Secret]) -> Result<ParsedInit, ProtocolError> {
    for secret in secrets {
        if let Some((cipher, proto, dc_id)) = try_parse(init, &secret.key) {
            return Ok(ParsedInit {
                cipher,
                proto,
                dc_id,
                secret_name: secret.name.clone(),
            });
        }
    }
    Err(ProtocolError::UnknownProtoTag(0))
}

pub fn parse_init(init: &[u8; 64], secret: &[u8]) -> Result<ParsedInit, ProtocolError> {
    match try_parse(init, secret) {
        Some((cipher, proto, dc_id)) => Ok(ParsedInit {
            cipher,
            proto,
            dc_id,
            secret_name: "default".into(),
        }),
        None => {
            let mut decrypted = *init;
            let dec_key = derive_obfs2_key(&init[8..40], secret);
            let dec_iv: [u8; 16] = init[40..56].try_into().unwrap();
            let mut dec = <crate::crypto::Aes256Ctr as ctr::cipher::KeyIvInit>::new(
                &dec_key.into(), &dec_iv.into(),
            );
            dec.apply_keystream(&mut decrypted);
            let raw = u32::from_le_bytes(decrypted[56..60].try_into().unwrap());
            Err(ProtocolError::UnknownProtoTag(raw))
        }
    }
}
