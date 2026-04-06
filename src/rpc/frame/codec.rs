use super::crc::compute_crc32;

const PADDING_FILLER: [u8; 4] = [0x04, 0x00, 0x00, 0x00];

pub fn make_frame(seq: i32, data: &[u8]) -> Vec<u8> {
    let total_len = (data.len() + 12) as u32;
    let mut frame = Vec::with_capacity((total_len as usize + 15) & !15);

    frame.extend_from_slice(&total_len.to_le_bytes());
    frame.extend_from_slice(&seq.to_le_bytes());
    frame.extend_from_slice(data);

    let checksum = compute_crc32(&frame);
    frame.extend_from_slice(&checksum.to_le_bytes());

    while frame.len() % 16 != 0 {
        frame.extend_from_slice(&PADDING_FILLER);
    }

    frame
}
