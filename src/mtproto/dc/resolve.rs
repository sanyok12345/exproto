use super::addr::TELEGRAM_DC_ADDRS;
use crate::engine::error::ProtocolError;

pub fn resolve_dc(dc_id: i16) -> Result<&'static str, ProtocolError> {
    let idx = dc_id.unsigned_abs() as usize;
    if idx == 0 || idx >= TELEGRAM_DC_ADDRS.len() {
        return Err(ProtocolError::InvalidDc(dc_id));
    }
    Ok(TELEGRAM_DC_ADDRS[idx])
}
