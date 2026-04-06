use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

const TLS_CHANGE_CIPHER: u8 = 0x14;
const TLS_APP_DATA: u8 = 0x17;

pub async fn read_record(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    loop {
        let mut hdr = [0u8; 5];
        stream.read_exact(&mut hdr).await?;

        let rec_type = hdr[0];
        let length = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;

        if length > 1 << 16 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("ExProto: TLS record too large ({length} bytes)"),
            ));
        }

        let mut data = vec![0u8; length];
        stream.read_exact(&mut data).await?;

        match rec_type {
            TLS_CHANGE_CIPHER => continue,
            TLS_APP_DATA => return Ok(data),
            t => return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("ExProto: unexpected TLS record type 0x{t:02x}"),
            )),
        }
    }
}
