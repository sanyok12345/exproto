const RPC_PROXY_ANS: u32 = 0x4403da0d;
const RPC_CLOSE_EXT: u32 = 0x5eb634a2;
const RPC_SIMPLE_ACK: u32 = 0x3bac409b;

pub enum ProxyResponse {
    Data(Vec<u8>),
    Closed,
    Ack,
    Unknown,
}

pub fn parse_proxy_ans(data: &[u8]) -> ProxyResponse {
    if data.len() < 4 {
        return ProxyResponse::Unknown;
    }

    let msg_type = u32::from_le_bytes(data[0..4].try_into().unwrap());
    match msg_type {
        RPC_PROXY_ANS => {
            if data.len() < 16 { return ProxyResponse::Unknown; }
            ProxyResponse::Data(data[16..].to_vec())
        }
        RPC_CLOSE_EXT => ProxyResponse::Closed,
        RPC_SIMPLE_ACK => ProxyResponse::Ack,
        _ => ProxyResponse::Unknown,
    }
}
