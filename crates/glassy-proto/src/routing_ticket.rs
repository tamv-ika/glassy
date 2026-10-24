//! Routing ticket minted by the broker and opened by the gateway (spec §3.1).
//!
//! Wire layout (60 bytes):
//! `ver(1) | key_id(1) | nonce(12) | AES-128-GCM(body)(30) | tag(16)`, AAD = `ver | key_id`.
//! `body = server_id(16) | session_id(8) | expiry(u32 BE) | transports(1) | flags(1)`.

use aes_gcm::aead::AeadInOut;
use aes_gcm::{Aes128Gcm, KeyInit};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use data_encoding::BASE32_NOPAD;

use crate::{Error, transport};

pub const ROUTING_TICKET_LEN: usize = 60;

const VERSION: u8 = 1;
const BODY_LEN: usize = 30;
const TAG_LEN: usize = 16;
const BODY_START: usize = 14;
const TAG_START: usize = BODY_START + BODY_LEN;
/// Base64 length of a ticket without padding: 60 * 8 / 6.
const UFRAG_LEN: usize = 80;
/// Length of each SNI label; two labels keep every label under the 63-byte DNS limit.
const SNI_LABEL_LEN: usize = 48;
const SNI_LABELS: usize = 2;
const ALLOWED_TRANSPORTS: u8 = transport::NATIVE | transport::WEBRTC | transport::WEBTRANSPORT;
/// Cap on distinct keys so a misconfigured rotation cannot grow the ring unbounded.
const MAX_KEYS: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutingTicket {
    pub server_id: [u8; 16],
    pub session_id: [u8; 8],
    /// Unix seconds; the ticket is valid while `expiry >= now`.
    pub expiry: u32,
    /// Bitmask of [`transport`] values the ticket allows.
    pub transports: u8,
}

/// Gateway-side ticket keys indexed by `key_id`, so rotated keys keep working.
pub struct RoutingKeyRing {
    keys: Vec<(u8, [u8; 16])>,
    current: u8,
}

impl RoutingKeyRing {
    pub fn new(current_id: u8, key: [u8; 16]) -> Self {
        Self {
            keys: vec![(current_id, key)],
            current: current_id,
        }
    }

    /// Adds a key, or replaces the key stored under the same id.
    pub fn insert(&mut self, id: u8, key: [u8; 16]) -> Result<(), Error> {
        if let Some(slot) = self.keys.iter_mut().find(|(i, _)| *i == id) {
            slot.1 = key;
            return Ok(());
        }
        if self.keys.len() >= MAX_KEYS {
            return Err(Error::TooLarge);
        }
        self.keys.push((id, key));
        Ok(())
    }

    pub fn current_id(&self) -> u8 {
        self.current
    }

    fn cipher(&self, id: u8) -> Option<Aes128Gcm> {
        self.keys
            .iter()
            .find(|(i, _)| *i == id)
            .map(|(_, k)| Aes128Gcm::new(&(*k).into()))
    }
}

/// Seals `t` with the ring's current key; `flags` is always written as 0.
/// The caller supplies a fresh random nonce per ticket.
pub fn seal_routing(t: &RoutingTicket, ring: &RoutingKeyRing, nonce: [u8; 12]) -> [u8; 60] {
    let mut body = [0u8; BODY_LEN];
    body[..16].copy_from_slice(&t.server_id);
    body[16..24].copy_from_slice(&t.session_id);
    body[24..28].copy_from_slice(&t.expiry.to_be_bytes());
    body[28] = t.transports;

    let id = ring.current_id();
    let header = [VERSION, id];
    // `new` guarantees the current key is present; without it there is nothing to seal with.
    let cipher = ring
        .cipher(id)
        .expect("the current key is always present in the ring");
    let tag = cipher
        .encrypt_inout_detached(&nonce.into(), &header, (&mut body[..]).into())
        // Fails only above the AES-GCM length limit, which a 30-byte body never reaches.
        .expect("a 30-byte body never exceeds AES-GCM limits");

    let mut out = [0u8; ROUTING_TICKET_LEN];
    out[..2].copy_from_slice(&header);
    out[2..BODY_START].copy_from_slice(&nonce);
    out[BODY_START..TAG_START].copy_from_slice(&body);
    out[TAG_START..].copy_from_slice(&tag);
    out
}

/// Opens and validates a ticket (spec §3.1 receiver obligations, in this fixed order).
/// `via` is the single transport bit the packet arrived on; `connect_session_id` is the
/// `CONNECT` header's session id for native packets. Allocation-free.
pub fn open_routing(
    b: &[u8],
    ring: &RoutingKeyRing,
    now: u32,
    via: u8,
    connect_session_id: Option<&[u8; 8]>,
) -> Result<RoutingTicket, Error> {
    if b.len() != ROUTING_TICKET_LEN {
        return Err(Error::BadLength);
    }
    if b[0] != VERSION {
        return Err(Error::BadVersion);
    }
    let cipher = ring.cipher(b[1]).ok_or(Error::UnknownKey)?;

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&b[2..BODY_START]);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&b[TAG_START..]);
    let mut body = [0u8; BODY_LEN];
    body.copy_from_slice(&b[BODY_START..TAG_START]);
    cipher
        .decrypt_inout_detached(&nonce.into(), &b[..2], (&mut body[..]).into(), &tag.into())
        .map_err(|_| Error::AuthFailed)?;

    let flags = body[29];
    let transports = body[28];
    if flags != 0 || transports & !ALLOWED_TRANSPORTS != 0 {
        return Err(Error::ReservedNonzero);
    }
    let mut t = RoutingTicket {
        server_id: [0; 16],
        session_id: [0; 8],
        expiry: u32::from_be_bytes([body[24], body[25], body[26], body[27]]),
        transports,
    };
    t.server_id.copy_from_slice(&body[..16]);
    t.session_id.copy_from_slice(&body[16..24]);
    if t.expiry < now {
        return Err(Error::Expired);
    }
    if t.transports & via == 0 {
        return Err(Error::BadTransport);
    }
    if connect_session_id.is_some_and(|s| *s != t.session_id) {
        return Err(Error::SessionMismatch);
    }
    Ok(t)
}

/// Encodes a ticket as an ICE ufrag (standard base64 without padding, 80 chars).
pub fn to_ufrag(b: &[u8; 60]) -> String {
    STANDARD_NO_PAD.encode(b)
}

pub fn from_ufrag(s: &str) -> Result<[u8; 60], Error> {
    // A ticket always encodes to exactly 80 chars; check before decoding.
    if s.len() != UFRAG_LEN {
        return Err(Error::BadLength);
    }
    let raw = STANDARD_NO_PAD.decode(s).map_err(|_| Error::BadEncoding)?;
    raw.try_into().map_err(|_| Error::BadLength)
}

/// Encodes a ticket as two lowercase base32 DNS labels, `"<48>.<48>"`.
pub fn to_sni_labels(b: &[u8; 60]) -> String {
    let s = BASE32_NOPAD.encode(b).to_ascii_lowercase();
    format!("{}.{}", &s[..SNI_LABEL_LEN], &s[SNI_LABEL_LEN..])
}

/// Extracts the ticket from `host`, which must end with `.{suffix}` (case-insensitive).
pub fn from_sni(host: &str, suffix: &str) -> Result<[u8; 60], Error> {
    let host = host.to_ascii_uppercase();
    let suffix = format!(".{}", suffix.to_ascii_uppercase());
    let labels = host.strip_suffix(&suffix).ok_or(Error::BadEncoding)?;
    let mut joined = String::with_capacity(SNI_LABELS * SNI_LABEL_LEN);
    let mut count = 0;
    for label in labels.split('.') {
        count += 1;
        if label.len() != SNI_LABEL_LEN {
            return Err(Error::BadLength);
        }
        joined.push_str(label);
    }
    if count != SNI_LABELS {
        return Err(Error::BadLength);
    }
    let raw = BASE32_NOPAD
        .decode(joined.as_bytes())
        .map_err(|_| Error::BadEncoding)?;
    raw.try_into().map_err(|_| Error::BadLength)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u32 = 1_900_000_000;

    fn ring() -> RoutingKeyRing {
        RoutingKeyRing::new(1, [0x11; 16])
    }

    fn sample() -> RoutingTicket {
        RoutingTicket {
            server_id: [0xab; 16],
            session_id: [1, 2, 3, 4, 5, 6, 7, 8],
            expiry: 2_000_000_000,
            transports: transport::WEBRTC | transport::WEBTRANSPORT,
        }
    }

    fn sealed() -> [u8; 60] {
        seal_routing(&sample(), &ring(), [0x88; 12])
    }

    /// Re-seals a hand-built body so tests can violate exactly one rule.
    fn seal_body(mut body: [u8; BODY_LEN]) -> [u8; 60] {
        let header = [VERSION, 1];
        let nonce = [0x88u8; 12];
        let tag = ring()
            .cipher(1)
            .unwrap()
            .encrypt_inout_detached(&nonce.into(), &header, (&mut body[..]).into())
            .unwrap();
        let mut out = [0u8; 60];
        out[..2].copy_from_slice(&header);
        out[2..BODY_START].copy_from_slice(&nonce);
        out[BODY_START..TAG_START].copy_from_slice(&body);
        out[TAG_START..].copy_from_slice(&tag);
        out
    }

    fn body_of(t: &RoutingTicket, flags: u8) -> [u8; BODY_LEN] {
        let mut b = [0u8; BODY_LEN];
        b[..16].copy_from_slice(&t.server_id);
        b[16..24].copy_from_slice(&t.session_id);
        b[24..28].copy_from_slice(&t.expiry.to_be_bytes());
        b[28] = t.transports;
        b[29] = flags;
        b
    }

    #[test]
    fn seal_open_roundtrip() {
        let b = sealed();
        assert_eq!((b.len(), b[0], b[1]), (60, 1, 1));
        let got = open_routing(&b, &ring(), NOW, transport::WEBRTC, None).unwrap();
        assert_eq!(got, sample());
        let sid = sample().session_id;
        assert!(open_routing(&b, &ring(), NOW, transport::WEBRTC, Some(&sid)).is_ok());
    }

    #[test]
    fn check_1_bad_length() {
        let b = sealed();
        assert_eq!(
            open_routing(&b[..59], &ring(), NOW, transport::WEBRTC, None),
            Err(Error::BadLength)
        );
    }

    #[test]
    fn check_2_bad_version() {
        let mut b = sealed();
        b[0] = 2;
        assert_eq!(
            open_routing(&b, &ring(), NOW, transport::WEBRTC, None),
            Err(Error::BadVersion)
        );
    }

    #[test]
    fn check_3_unknown_key() {
        let mut b = sealed();
        b[1] = 2;
        assert_eq!(
            open_routing(&b, &ring(), NOW, transport::WEBRTC, None),
            Err(Error::UnknownKey)
        );
    }

    #[test]
    fn check_4_auth_failed() {
        let mut b = sealed();
        b[59] ^= 1;
        assert_eq!(
            open_routing(&b, &ring(), NOW, transport::WEBRTC, None),
            Err(Error::AuthFailed)
        );
    }

    #[test]
    fn check_5_flags_nonzero() {
        let b = seal_body(body_of(&sample(), 1));
        assert_eq!(
            open_routing(&b, &ring(), NOW, transport::WEBRTC, None),
            Err(Error::ReservedNonzero)
        );
    }

    #[test]
    fn check_5_reserved_transport_bit() {
        let mut t = sample();
        t.transports |= 0x08;
        let b = seal_body(body_of(&t, 0));
        assert_eq!(
            open_routing(&b, &ring(), NOW, transport::WEBRTC, None),
            Err(Error::ReservedNonzero)
        );
    }

    #[test]
    fn check_6_expiry_boundary() {
        let b = sealed();
        let exp = sample().expiry;
        assert!(open_routing(&b, &ring(), exp, transport::WEBRTC, None).is_ok());
        assert_eq!(
            open_routing(&b, &ring(), exp + 1, transport::WEBRTC, None),
            Err(Error::Expired)
        );
    }

    #[test]
    fn check_7_transport_not_allowed() {
        let b = sealed();
        assert_eq!(
            open_routing(&b, &ring(), NOW, transport::NATIVE, None),
            Err(Error::BadTransport)
        );
    }

    #[test]
    fn check_8_session_mismatch() {
        let b = sealed();
        assert_eq!(
            open_routing(&b, &ring(), NOW, transport::WEBRTC, Some(&[9; 8])),
            Err(Error::SessionMismatch)
        );
    }

    #[test]
    fn key_ring_is_capped_at_16() {
        let mut r = ring();
        for id in 2..=16 {
            r.insert(id, [id; 16]).unwrap();
        }
        assert_eq!(r.insert(17, [17; 16]), Err(Error::TooLarge));
        // Replacing an existing id is not growth.
        assert!(r.insert(3, [0; 16]).is_ok());
    }

    #[test]
    fn ufrag_is_ice_char_only() {
        let s = to_ufrag(&sealed());
        assert_eq!(s.len(), 80);
        // ICE ufrag only allows ice-char: ALPHA / DIGIT / "+" / "/" (RFC 8839).
        assert!(
            s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
        );
        assert_eq!(from_ufrag(&s).unwrap(), sealed());
        assert_eq!(from_ufrag("ab"), Err(Error::BadLength));
        assert_eq!(from_ufrag(&"!".repeat(80)), Err(Error::BadEncoding));
    }

    #[test]
    fn sni_case_insensitive() {
        let b = sealed();
        let l = to_sni_labels(&b);
        let parts: Vec<&str> = l.split('.').collect();
        assert_eq!((parts.len(), parts[0].len(), parts[1].len()), (2, 48, 48));
        let host = format!("{l}.wt.test");
        assert_eq!(from_sni(&host, "wt.test").unwrap(), b);
        assert_eq!(from_sni(&host.to_uppercase(), "WT.test").unwrap(), b);
        assert_eq!(
            from_sni("abc.other.test", "wt.test"),
            Err(Error::BadEncoding)
        );
        assert_eq!(from_sni("abc.wt.test", "wt.test"), Err(Error::BadLength));
        let bad = format!("{}.{}.wt.test", "1".repeat(48), "a".repeat(48));
        assert_eq!(from_sni(&bad, "wt.test"), Err(Error::BadEncoding));
    }
}
