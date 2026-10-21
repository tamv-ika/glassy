//! Routing tickets minted by the broker and opened by the gateway (spec §3.2).
//!
//! Wire layout (60 bytes):
//! `ver(1) | key_id(1) | nonce(12) | AES-128-GCM(body)(30) | tag(16)`, with AAD = `ver | key_id`.
//! `body = server_id(16) | session_id(8) | expiry(u32 BE) | transports(1) | flags(1)`.

use std::collections::HashMap;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, KeyInit};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use data_encoding::BASE32_NOPAD;

pub const TICKET_LEN: usize = 60;

const VERSION: u8 = 1;
const NONCE_RANGE: std::ops::Range<usize> = 2..14;
const BODY_LEN: usize = 30;
/// Base64 length of a ticket without padding: ceil(60 * 4 / 3).
const UFRAG_LEN: usize = 80;
/// Length of each SNI label; two labels keep every label under the 63-byte DNS limit.
const SNI_LABEL_LEN: usize = 48;

/// Bitmask values for [`RoutingTicket::transports`].
pub mod transports {
    pub const NATIVE: u8 = 1;
    pub const WEBRTC: u8 = 2;
    pub const WEBTRANSPORT: u8 = 4;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutingTicket {
    pub server_id: [u8; 16],
    pub session_id: [u8; 8],
    /// Unix seconds after which the gateway rejects the ticket.
    pub expiry: u32,
    pub transports: u8,
    pub flags: u8,
}

/// Gateway-side ticket keys indexed by `key_id`, so rotated keys keep working.
pub struct KeyRing {
    keys: HashMap<u8, [u8; 16]>,
    current: u8,
}

impl KeyRing {
    pub fn new(current_id: u8, key: [u8; 16]) -> Self {
        Self {
            keys: HashMap::from([(current_id, key)]),
            current: current_id,
        }
    }

    pub fn insert(&mut self, id: u8, key: [u8; 16]) {
        self.keys.insert(id, key);
    }

    pub fn current_id(&self) -> u8 {
        self.current
    }

    fn cipher(&self, id: u8) -> Option<Aes128Gcm> {
        self.keys.get(&id).map(|k| Aes128Gcm::new(&(*k).into()))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum TicketError {
    Length,
    Encoding,
    Version,
    UnknownKey,
    Auth,
    Expired,
}

/// Seals `t` with the ring's current key. The caller supplies a unique nonce per ticket.
pub fn seal(t: &RoutingTicket, ring: &KeyRing, nonce: [u8; 12]) -> [u8; TICKET_LEN] {
    let mut body = [0u8; BODY_LEN];
    body[..16].copy_from_slice(&t.server_id);
    body[16..24].copy_from_slice(&t.session_id);
    body[24..28].copy_from_slice(&t.expiry.to_be_bytes());
    body[28] = t.transports;
    body[29] = t.flags;

    let id = ring.current_id();
    let header = [VERSION, id];
    let cipher = ring
        .cipher(id)
        .expect("current key is always present in the ring");
    let sealed = cipher
        .encrypt(
            &nonce.into(),
            Payload {
                msg: &body,
                aad: &header,
            },
        )
        .expect("a 30-byte body never exceeds AES-GCM limits");

    let mut out = [0u8; TICKET_LEN];
    out[..2].copy_from_slice(&header);
    out[NONCE_RANGE].copy_from_slice(&nonce);
    out[14..].copy_from_slice(&sealed);
    out
}

/// Opens and validates a ticket; `now` is Unix seconds.
pub fn open(b: &[u8], ring: &KeyRing, now: u32) -> Result<RoutingTicket, TicketError> {
    if b.len() != TICKET_LEN {
        return Err(TicketError::Length);
    }
    if b[0] != VERSION {
        return Err(TicketError::Version);
    }
    let cipher = ring.cipher(b[1]).ok_or(TicketError::UnknownKey)?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&b[NONCE_RANGE]);
    let body = cipher
        .decrypt(
            &nonce.into(),
            Payload {
                msg: &b[14..],
                aad: &b[..2],
            },
        )
        .map_err(|_| TicketError::Auth)?;

    let mut t = RoutingTicket {
        server_id: [0; 16],
        session_id: [0; 8],
        expiry: u32::from_be_bytes([body[24], body[25], body[26], body[27]]),
        transports: body[28],
        flags: body[29],
    };
    t.server_id.copy_from_slice(&body[..16]);
    t.session_id.copy_from_slice(&body[16..24]);
    if t.expiry < now {
        return Err(TicketError::Expired);
    }
    Ok(t)
}

/// Encodes a ticket as an ICE ufrag (standard base64 without padding, 80 chars).
pub fn to_ufrag(b: &[u8; TICKET_LEN]) -> String {
    STANDARD_NO_PAD.encode(b)
}

pub fn from_ufrag(s: &str) -> Result<[u8; TICKET_LEN], TicketError> {
    // A sealed ticket always encodes to exactly 80 chars; reject other sizes before decoding.
    if s.len() != UFRAG_LEN {
        return Err(TicketError::Length);
    }
    let raw = STANDARD_NO_PAD
        .decode(s)
        .map_err(|_| TicketError::Encoding)?;
    raw.try_into().map_err(|_| TicketError::Length)
}

/// Encodes a ticket as two lowercase base32 DNS labels, `"<48>.<48>"`.
pub fn to_sni_labels(b: &[u8; TICKET_LEN]) -> String {
    let s = BASE32_NOPAD.encode(b).to_ascii_lowercase();
    format!("{}.{}", &s[..SNI_LABEL_LEN], &s[SNI_LABEL_LEN..])
}

/// Extracts the ticket from `host`, which must end with `.{suffix}` (compared case-insensitively).
pub fn from_sni(host: &str, suffix: &str) -> Result<[u8; TICKET_LEN], TicketError> {
    let host = host.to_ascii_lowercase();
    let suffix = format!(".{}", suffix.to_ascii_lowercase());
    let labels = host.strip_suffix(&suffix).ok_or(TicketError::Encoding)?;
    let joined: String = labels
        .chars()
        .filter(|&c| c != '.')
        .collect::<String>()
        .to_ascii_uppercase();
    let raw = BASE32_NOPAD
        .decode(joined.as_bytes())
        .map_err(|_| TicketError::Encoding)?;
    raw.try_into().map_err(|_| TicketError::Length)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring() -> KeyRing {
        KeyRing::new(1, [0x11; 16])
    }

    fn sample() -> RoutingTicket {
        RoutingTicket {
            server_id: [0xab; 16],
            session_id: [1, 2, 3, 4, 5, 6, 7, 8],
            expiry: 2_000_000_000,
            transports: transports::WEBRTC | transports::WEBTRANSPORT,
            flags: 0,
        }
    }

    #[test]
    fn seal_open_roundtrip() {
        let b = seal(&sample(), &ring(), [7; 12]);
        assert_eq!((b.len(), b[0], b[1]), (60, 1, 1));
        assert_eq!(open(&b, &ring(), 1_900_000_000).unwrap(), sample());
    }

    #[test]
    fn tamper_is_auth_error() {
        let mut b = seal(&sample(), &ring(), [7; 12]);
        b[20] ^= 1;
        assert_eq!(open(&b, &ring(), 0), Err(TicketError::Auth));
    }

    #[test]
    fn unknown_key_id() {
        let mut b = seal(&sample(), &ring(), [7; 12]);
        b[1] = 2;
        assert_eq!(open(&b, &ring(), 0), Err(TicketError::UnknownKey));
    }

    #[test]
    fn expired() {
        let b = seal(&sample(), &ring(), [7; 12]);
        assert_eq!(open(&b, &ring(), 2_000_000_001), Err(TicketError::Expired));
    }

    #[test]
    fn bad_version_and_length() {
        let mut b = seal(&sample(), &ring(), [7; 12]);
        assert_eq!(open(&b[..59], &ring(), 0), Err(TicketError::Length));
        b[0] = 2;
        assert_eq!(open(&b, &ring(), 0), Err(TicketError::Version));
    }

    #[test]
    fn ufrag_roundtrip() {
        let b = seal(&sample(), &ring(), [7; 12]);
        let s = to_ufrag(&b);
        assert_eq!(s.len(), 80);
        // ICE ufrag only allows ice-char: ALPHA / DIGIT / "+" / "/" (RFC 8839).
        assert!(
            s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
        );
        assert_eq!(from_ufrag(&s).unwrap(), b);
        assert_eq!(from_ufrag("ab"), Err(TicketError::Length));
    }

    #[test]
    fn sni_roundtrip_case_insensitive() {
        let b = seal(&sample(), &ring(), [7; 12]);
        let l = to_sni_labels(&b);
        let parts: Vec<&str> = l.split('.').collect();
        assert_eq!((parts.len(), parts[0].len(), parts[1].len()), (2, 48, 48));
        assert!(
            l.chars()
                .all(|c| c == '.' || c.is_ascii_lowercase() || ('2'..='7').contains(&c))
        );
        let host = format!("{l}.wt.test");
        assert_eq!(from_sni(&host, "wt.test").unwrap(), b);
        // Hostnames are case-insensitive, so an upper-cased SNI must still decode.
        assert_eq!(from_sni(&host.to_uppercase(), "wt.test").unwrap(), b);
        assert_eq!(
            from_sni("abc.other.test", "wt.test"),
            Err(TicketError::Encoding)
        );
    }
}
