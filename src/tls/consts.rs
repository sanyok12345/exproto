pub const TLS_HANDSHAKE: u8 = 0x16;
pub const TLS_CHANGE_CIPHER: u8 = 0x14;
pub const TLS_APP_DATA: u8 = 0x17;
pub const TLS_VERS_12: [u8; 2] = [0x03, 0x03];
pub const DIGEST_POS: usize = 11;
pub const DIGEST_LEN: usize = 32;
