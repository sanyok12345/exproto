use std::net::SocketAddr;

const RPC_PROXY_REQ: u32 = 0x36cef1ee;
const PROXY_TAG: u32 = 0xdb1e26ae;
const EXTRA_SIZE: u32 = 0x18;

const FLAG_NOT_ENCRYPTED: u32 = 0x2;
const FLAG_HAS_AD_TAG: u32 = 0x8;
const FLAG_MAGIC: u32 = 0x1000;
const FLAG_EXTMODE2: u32 = 0x20000;
const FLAG_PAD: u32 = 0x8000000;
const FLAG_INTERMEDIATE: u32 = 0x20000000;
const FLAG_ABRIDGED: u32 = 0x40000000;

pub fn build_proxy_req(
    conn_id: &[u8; 8],
    client_addr: SocketAddr,
    our_addr: SocketAddr,
    proto_tag: u32,
    ad_tag: Option<&[u8; 16]>,
    data: &[u8],
) -> Vec<u8> {
    let mut flags: u32 = FLAG_MAGIC | FLAG_EXTMODE2;

    if ad_tag.is_some() {
        flags |= FLAG_HAS_AD_TAG;
    }

    match proto_tag {
        0xefefefef => flags |= FLAG_ABRIDGED,
        0xdddddddd => flags |= FLAG_INTERMEDIATE | FLAG_PAD,
        0xeeeeeeee => flags |= FLAG_INTERMEDIATE,
        _ => {}
    }
    if data.len() >= 8 && data[..8] == [0; 8] {
        flags |= FLAG_NOT_ENCRYPTED;
    }

    let mut msg = Vec::with_capacity(80 + data.len());
    msg.extend_from_slice(&RPC_PROXY_REQ.to_le_bytes());
    msg.extend_from_slice(&flags.to_le_bytes());
    msg.extend_from_slice(conn_id);
    msg.extend_from_slice(&ip_port_bytes(client_addr));
    msg.extend_from_slice(&ip_port_bytes(our_addr));

    if let Some(tag) = ad_tag {
        msg.extend_from_slice(&EXTRA_SIZE.to_le_bytes());
        msg.extend_from_slice(&PROXY_TAG.to_le_bytes());
        msg.push(16);
        msg.extend_from_slice(tag);
        msg.extend_from_slice(&[0u8; 3]);
    } else {
        msg.extend_from_slice(&0u32.to_le_bytes());
    }

    msg.extend_from_slice(data);
    msg
}

fn ip_port_bytes(addr: SocketAddr) -> [u8; 20] {
    let mut buf = [0u8; 20];
    match addr {
        SocketAddr::V4(v4) => {
            buf[10] = 0xff;
            buf[11] = 0xff;
            buf[12..16].copy_from_slice(&v4.ip().octets());
            buf[16..20].copy_from_slice(&(v4.port() as u32).to_le_bytes());
        }
        SocketAddr::V6(v6) => {
            buf[0..16].copy_from_slice(&v6.ip().octets());
            buf[16..20].copy_from_slice(&(v6.port() as u32).to_le_bytes());
        }
    }
    buf
}
