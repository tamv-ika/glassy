//! Minimal STUN parsing for the gateway slow path: read the server ufrag from a binding request.

const HEADER_LEN: usize = 20;
const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
const BINDING_REQUEST: u16 = 0x0001;
const ATTR_USERNAME: u16 = 0x0006;

#[derive(Debug, PartialEq, Eq)]
pub enum StunError {
    NotStun,
    NotBindingRequest,
    NoUsername,
    Malformed,
}

fn check_header(pkt: &[u8]) -> Result<usize, StunError> {
    // RFC 8489 §5: the two most significant bits are zero and the magic cookie is fixed.
    if pkt.len() < HEADER_LEN || pkt[0] & 0xc0 != 0 || pkt[4..8] != MAGIC_COOKIE {
        return Err(StunError::NotStun);
    }
    if u16::from_be_bytes([pkt[0], pkt[1]]) != BINDING_REQUEST {
        return Err(StunError::NotBindingRequest);
    }
    let body_len = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
    if HEADER_LEN + body_len > pkt.len() {
        return Err(StunError::Malformed);
    }
    Ok(HEADER_LEN + body_len)
}

pub fn is_binding_request(pkt: &[u8]) -> bool {
    check_header(pkt).is_ok()
}

/// Returns the server's ufrag: the part of USERNAME before ':' (RFC 8445 §7.2.2).
pub fn server_ufrag(pkt: &[u8]) -> Result<&str, StunError> {
    let end = check_header(pkt)?;
    let mut off = HEADER_LEN;
    while off + 4 <= end {
        let attr_type = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
        let attr_len = usize::from(u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]));
        let value_end = off + 4 + attr_len;
        if value_end > end {
            return Err(StunError::Malformed);
        }
        if attr_type == ATTR_USERNAME {
            let username =
                std::str::from_utf8(&pkt[off + 4..value_end]).map_err(|_| StunError::Malformed)?;
            return username
                .split_once(':')
                .map(|(server, _)| server)
                .ok_or(StunError::Malformed);
        }
        // Attribute values are padded to a multiple of 4 bytes.
        off = value_end + (4 - attr_len % 4) % 4;
    }
    Err(StunError::NoUsername)
}

/// Builds a binding request carrying only USERNAME; used by tests.
pub fn build_binding_request(username: &str, txid: [u8; 12]) -> Vec<u8> {
    let name = username.as_bytes();
    let padded = name.len().div_ceil(4) * 4;
    let body_len = u16::try_from(4 + padded).expect("test usernames are short");
    let mut pkt = Vec::with_capacity(HEADER_LEN + usize::from(body_len));
    pkt.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    pkt.extend_from_slice(&body_len.to_be_bytes());
    pkt.extend_from_slice(&MAGIC_COOKIE);
    pkt.extend_from_slice(&txid);
    pkt.extend_from_slice(&ATTR_USERNAME.to_be_bytes());
    pkt.extend_from_slice(
        &u16::try_from(name.len())
            .expect("short username")
            .to_be_bytes(),
    );
    pkt.extend_from_slice(name);
    pkt.resize(HEADER_LEN + usize::from(body_len), 0);
    pkt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc5769_username() {
        // RFC 5769 §2.1 sample request (bytes cross-checked against the coturn and pion copies).
        let p = hex::decode(
            include_str!("../tests/fixtures/rfc5769_request.hex")
                .split_whitespace()
                .collect::<String>(),
        )
        .unwrap();
        assert!(is_binding_request(&p));
        assert_eq!(server_ufrag(&p), Ok("evtj"));
    }

    #[test]
    fn built_request_roundtrip() {
        let p = build_binding_request("abcd:wxyz", [9; 12]);
        assert_eq!(server_ufrag(&p), Ok("abcd"));
    }

    #[test]
    fn not_stun() {
        assert_eq!(server_ufrag(&[0x16, 0xfe, 0xfd]), Err(StunError::NotStun));
    }

    #[test]
    fn truncated_is_malformed() {
        let p = build_binding_request("abcd:wxyz", [9; 12]);
        assert_eq!(server_ufrag(&p[..p.len() - 3]), Err(StunError::Malformed));
    }
}
