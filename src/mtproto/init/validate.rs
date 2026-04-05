use crate::mtproto::conn::state::ProtoTag;

pub fn validate_dc_index(dc_id: i16) -> bool {
    let abs = dc_id.unsigned_abs();
    (1..=5).contains(&abs)
}

pub fn validate_proto_tag(raw: u32) -> bool {
    ProtoTag::from_raw(raw).is_some()
}
