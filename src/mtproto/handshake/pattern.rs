pub const RESERVED_FIRST_BYTES: &[u8] = &[0xef];

pub const RESERVED_PREFIXES: &[[u8; 4]] = &[
    [0x48, 0x45, 0x41, 0x44],
    [0x50, 0x4f, 0x53, 0x54],
    [0x47, 0x45, 0x54, 0x20],
    [0xee, 0xee, 0xee, 0xee],
    [0xdd, 0xdd, 0xdd, 0xdd],
    [0x16, 0x03, 0x01, 0x02],
];

pub fn is_reserved(init: &[u8; 64]) -> bool {
    if RESERVED_FIRST_BYTES.contains(&init[0]) {
        return true;
    }
    let first4: [u8; 4] = init[0..4].try_into().unwrap();
    if RESERVED_PREFIXES.contains(&first4) {
        return true;
    }
    if init[4..8] == [0; 4] {
        return true;
    }
    false
}
