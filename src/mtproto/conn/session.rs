use std::net::SocketAddr;
use super::state::{TransportMode, ProtoTag};

#[derive(Debug)]
pub struct Session {
    pub peer: SocketAddr,
    pub mode: TransportMode,
    pub proto: ProtoTag,
    pub dc_id: i16,
}

impl std::fmt::Display for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "dc={} proto={} mode={} peer={}", self.dc_id, self.proto, self.mode, self.peer)
    }
}
