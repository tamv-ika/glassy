//! Server ticket minted by the broker and opened by the game server (spec §3.2).
//!
//! Wire layout: `ver(1) | key_id(1) | nonce(24) | XChaCha20-Poly1305(body) | tag(16)`,
//! AAD = `ver | key_id`, key = `K_ticket` derived from `K_gs`.
//! `body = user_id_len(1) | user_id | server_id(16) | session_id(8) | expiry(u32 BE)
//! | transport(1) | [key_c2s(32) | key_s2c(32)] | metadata_len(u16 BE) | metadata`.
//! The native key pair is present if and only if `transport` is native.

use crate::crypto::{k_ticket, xchacha_open, xchacha_seal};
use crate::{Error, transport};

/// Smallest sealed server ticket (spec §3.2).
pub const SERVER_TICKET_MIN: usize = 75;
/// Largest sealed server ticket (spec §3.2).
pub const SERVER_TICKET_MAX: usize = 458;
/// Smallest sealed native server ticket, which carries both keys (spec §3.2).
pub const SERVER_TICKET_NATIVE_MIN: usize = 139;
/// WebRTC/WebTransport tickets carry no native keys (spec §3.2), hence the smaller maximum.
pub const SERVER_TICKET_BROWSER_MAX: usize = 394;

const VERSION: u8 = 1;
/// `ver | key_id`, also the AAD.
const HEADER_LEN: usize = 2;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const BODY_START: usize = HEADER_LEN + NONCE_LEN;
const USER_ID_MAX: usize = 64;
const METADATA_MAX: usize = 256;
/// Cap on distinct keys so a misconfigured rotation cannot grow the ring unbounded.
const MAX_KEYS: usize = 16;

/// Per-direction packet keys; carried only by native tickets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeKeys {
    /// Client-to-server packet key.
    pub c2s: [u8; 32],
    /// Server-to-client packet key.
    pub s2c: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Plaintext server ticket (spec §3.2).
pub struct ServerTicket {
    /// Authenticated user id, 1 to `USER_ID_MAX` bytes of UTF-8.
    pub user_id: String,
    /// UID of the one game server this ticket is valid on (spec §3.2, change 4).
    pub server_id: [u8; 16],
    /// Session the ticket was issued for.
    pub session_id: [u8; 8],
    /// Unix seconds; the ticket is valid while `expiry >= now`.
    pub expiry: u32,
    /// Exactly one [`transport`] bit.
    pub transport: u8,
    /// Present if and only if `transport` is native.
    pub native_keys: Option<NativeKeys>,
    /// Opaque backend metadata, bounded by `METADATA_MAX`.
    pub metadata: Vec<u8>,
}

/// Game-server ticket keys indexed by `key_id`. Stores the derived `K_ticket`, never `K_gs`.
pub struct ServerKeyRing {
    keys: Vec<(u8, [u8; 32])>,
    current: u8,
}

impl ServerKeyRing {
    /// Creates a ring holding `k_gs` as the current key `current_id`.
    pub fn new(current_id: u8, k_gs: [u8; 32]) -> Self {
        Self {
            keys: vec![(current_id, k_ticket(&k_gs))],
            current: current_id,
        }
    }

    /// Adds a key, or replaces the key stored under the same id.
    pub fn insert(&mut self, id: u8, k_gs: [u8; 32]) -> Result<(), Error> {
        let derived = k_ticket(&k_gs);
        if let Some(slot) = self.keys.iter_mut().find(|(i, _)| *i == id) {
            slot.1 = derived;
            return Ok(());
        }
        if self.keys.len() >= MAX_KEYS {
            return Err(Error::TooLarge);
        }
        self.keys.push((id, derived));
        Ok(())
    }

    /// Id of the key used by [`seal_server`].
    pub fn current_id(&self) -> u8 {
        self.current
    }

    fn key(&self, id: u8) -> Option<&[u8; 32]> {
        self.keys.iter().find(|(i, _)| *i == id).map(|(_, k)| k)
    }
}

fn is_defined_transport(t: u8) -> bool {
    matches!(
        t,
        transport::NATIVE | transport::WEBRTC | transport::WEBTRANSPORT
    )
}

/// Seals `t` with the ring's current key. The caller supplies a fresh random nonce per ticket.
pub fn seal_server(
    t: &ServerTicket,
    ring: &ServerKeyRing,
    nonce: [u8; 24],
) -> Result<Vec<u8>, Error> {
    let uid = t.user_id.as_bytes();
    if uid.is_empty() || uid.len() > USER_ID_MAX {
        return Err(Error::BadUserId);
    }
    if t.metadata.len() > METADATA_MAX {
        return Err(Error::BadMetadata);
    }
    if !is_defined_transport(t.transport)
        || t.native_keys.is_some() != (t.transport == transport::NATIVE)
    {
        return Err(Error::BadTransport);
    }
    let id = ring.current_id();
    // `new` guarantees the current key is present; without it nothing can be sealed.
    let key = ring.key(id).ok_or(Error::UnknownKey)?;

    let mut body = Vec::with_capacity(1 + uid.len() + 29 + 64 + 2 + t.metadata.len());
    body.push(uid.len() as u8);
    body.extend_from_slice(uid);
    body.extend_from_slice(&t.server_id);
    body.extend_from_slice(&t.session_id);
    body.extend_from_slice(&t.expiry.to_be_bytes());
    body.push(t.transport);
    if let Some(k) = &t.native_keys {
        body.extend_from_slice(&k.c2s);
        body.extend_from_slice(&k.s2c);
    }
    body.extend_from_slice(&(t.metadata.len() as u16).to_be_bytes());
    body.extend_from_slice(&t.metadata);

    let header = [VERSION, id];
    let sealed = xchacha_seal(key, &nonce, &header, &body);
    let mut out = Vec::with_capacity(BODY_START + sealed.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Sequential body reader; running out of bytes is always `BadLength`.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.0.len() < n {
            return Err(Error::BadLength);
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }
}

/// Opens and validates a ticket (spec §3.2 receiver obligations, in this fixed order).
/// `via` is the single transport bit the ticket arrived on.
pub fn open_server(
    b: &[u8],
    ring: &ServerKeyRing,
    now: u32,
    self_server_id: &[u8; 16],
    via: u8,
) -> Result<ServerTicket, Error> {
    if !(SERVER_TICKET_MIN..=SERVER_TICKET_MAX).contains(&b.len()) {
        return Err(Error::BadLength);
    }
    if b[0] != VERSION {
        return Err(Error::BadVersion);
    }
    let key = ring.key(b[1]).ok_or(Error::UnknownKey)?;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&b[HEADER_LEN..BODY_START]);
    let body = xchacha_open(key, &nonce, &b[..HEADER_LEN], &b[BODY_START..])?;
    debug_assert!(b.len() >= BODY_START + TAG_LEN);

    let mut r = Reader(&body);
    let user_id_len = usize::from(r.array::<1>()?[0]);
    if !(1..=USER_ID_MAX).contains(&user_id_len) {
        return Err(Error::BadUserId);
    }
    let user_id = r.take(user_id_len)?;
    let server_id = r.array::<16>()?;
    let session_id = r.array::<8>()?;
    let expiry = u32::from_be_bytes(r.array::<4>()?);
    let tr = r.array::<1>()?[0];
    if !is_defined_transport(tr) {
        return Err(Error::BadTransport);
    }
    let native_keys = if tr == transport::NATIVE {
        Some(NativeKeys {
            c2s: r.array::<32>()?,
            s2c: r.array::<32>()?,
        })
    } else {
        None
    };
    let metadata_len = usize::from(u16::from_be_bytes(r.array::<2>()?));
    if metadata_len > METADATA_MAX {
        return Err(Error::BadMetadata);
    }
    // Neither missing nor trailing bytes are tolerated.
    if r.0.len() != metadata_len {
        return Err(Error::BadLength);
    }
    let metadata = r.0.to_vec();

    let user_id = std::str::from_utf8(user_id)
        .map_err(|_| Error::BadUserId)?
        .to_owned();
    if &server_id != self_server_id {
        return Err(Error::WrongServer);
    }
    if expiry < now {
        return Err(Error::Expired);
    }
    if tr != via {
        return Err(Error::BadTransport);
    }
    Ok(ServerTicket {
        user_id,
        server_id,
        session_id,
        expiry,
        transport: tr,
        native_keys,
        metadata,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u32 = 1_900_000_000;
    const EXPIRY: u32 = 2_000_000_000;
    const SID: [u8; 16] = [0xab; 16];
    const NONCE: [u8; 24] = [0x99; 24];

    fn ring() -> ServerKeyRing {
        ServerKeyRing::new(1, [0x22; 32])
    }

    fn ticket(tr: u8) -> ServerTicket {
        ServerTicket {
            user_id: "user-1".into(),
            server_id: SID,
            session_id: [1, 2, 3, 4, 5, 6, 7, 8],
            expiry: EXPIRY,
            transport: tr,
            native_keys: (tr == transport::NATIVE).then_some(NativeKeys {
                c2s: [0x44; 32],
                s2c: [0x55; 32],
            }),
            metadata: b"meta".to_vec(),
        }
    }

    fn sealed(tr: u8) -> Vec<u8> {
        seal_server(&ticket(tr), &ring(), NONCE).unwrap()
    }

    /// Seals an arbitrary (possibly malformed) body under the test key.
    fn seal_body(body: &[u8]) -> Vec<u8> {
        let mut out = vec![1u8, 1];
        out.extend_from_slice(&NONCE);
        out.extend(xchacha_seal(&k_ticket(&[0x22; 32]), &NONCE, &[1, 1], body));
        out
    }

    /// A well-formed WebRTC body split at the point a test wants to corrupt.
    fn tail(tr: u8, metadata_len: u16, metadata: &[u8]) -> Vec<u8> {
        let mut v = SID.to_vec();
        v.extend_from_slice(&[0; 8]);
        v.extend_from_slice(&EXPIRY.to_be_bytes());
        v.push(tr);
        v.extend_from_slice(&metadata_len.to_be_bytes());
        v.extend_from_slice(metadata);
        v
    }

    fn open(b: &[u8], via: u8) -> Result<ServerTicket, Error> {
        open_server(b, &ring(), NOW, &SID, via)
    }

    #[test]
    fn seal_open_roundtrip_native() {
        let t = ticket(transport::NATIVE);
        let b = sealed(transport::NATIVE);
        assert_eq!(open(&b, transport::NATIVE), Ok(t));
    }

    #[test]
    fn seal_open_roundtrip_webrtc() {
        let t = ticket(transport::WEBRTC);
        let b = sealed(transport::WEBRTC);
        assert_eq!(open(&b, transport::WEBRTC), Ok(t));
    }

    #[test]
    fn sizes_match_spec() {
        let mut t = ticket(transport::WEBRTC);
        t.user_id = "u".into();
        t.metadata.clear();
        assert_eq!(
            seal_server(&t, &ring(), NONCE).unwrap().len(),
            SERVER_TICKET_MIN
        );
        let mut t = ticket(transport::NATIVE);
        t.user_id = "u".into();
        t.metadata.clear();
        assert_eq!(
            seal_server(&t, &ring(), NONCE).unwrap().len(),
            SERVER_TICKET_NATIVE_MIN
        );
        t.user_id = "u".repeat(64);
        t.metadata = vec![7; 256];
        let b = seal_server(&t, &ring(), NONCE).unwrap();
        assert_eq!(b.len(), SERVER_TICKET_MAX);
        assert_eq!(open(&b, transport::NATIVE), Ok(t));
    }

    #[test]
    fn encoder_rejects_invalid_tickets() {
        let mut t = ticket(transport::WEBRTC);
        t.user_id = String::new();
        assert_eq!(seal_server(&t, &ring(), NONCE), Err(Error::BadUserId));
        t.user_id = "u".repeat(65);
        assert_eq!(seal_server(&t, &ring(), NONCE), Err(Error::BadUserId));
        let mut t = ticket(transport::WEBRTC);
        t.metadata = vec![0; 257];
        assert_eq!(seal_server(&t, &ring(), NONCE), Err(Error::BadMetadata));
        let mut t = ticket(transport::WEBRTC);
        t.native_keys = ticket(transport::NATIVE).native_keys;
        assert_eq!(seal_server(&t, &ring(), NONCE), Err(Error::BadTransport));
        let mut t = ticket(transport::NATIVE);
        t.native_keys = None;
        assert_eq!(seal_server(&t, &ring(), NONCE), Err(Error::BadTransport));
        let mut t = ticket(transport::WEBRTC);
        t.transport = 3;
        assert_eq!(seal_server(&t, &ring(), NONCE), Err(Error::BadTransport));
    }

    #[test]
    fn check_1_length_bounds() {
        let b = sealed(transport::WEBRTC);
        assert_eq!(open(&b[..74], transport::WEBRTC), Err(Error::BadLength));
        assert_eq!(open(&[0; 459], transport::WEBRTC), Err(Error::BadLength));
    }

    #[test]
    fn check_2_bad_version() {
        let mut b = sealed(transport::WEBRTC);
        b[0] = 2;
        assert_eq!(open(&b, transport::WEBRTC), Err(Error::BadVersion));
    }

    #[test]
    fn check_3_unknown_key() {
        let mut b = sealed(transport::WEBRTC);
        b[1] = 2;
        assert_eq!(open(&b, transport::WEBRTC), Err(Error::UnknownKey));
    }

    #[test]
    fn check_4_auth_failed() {
        let mut b = sealed(transport::WEBRTC);
        let last = b.len() - 1;
        b[last] ^= 1;
        assert_eq!(open(&b, transport::WEBRTC), Err(Error::AuthFailed));
    }

    #[test]
    fn check_5_user_id_len_out_of_range() {
        // Padded so the ticket clears the 75-byte minimum and reaches the body checks.
        let mut body = vec![0u8];
        body.extend(tail(2, 0, &[0; 4]));
        assert_eq!(open(&seal_body(&body), 2), Err(Error::BadUserId));
        let mut body = vec![65u8];
        body.extend(vec![b'a'; 65]);
        body.extend(tail(2, 0, &[]));
        assert_eq!(open(&seal_body(&body), 2), Err(Error::BadUserId));
    }

    #[test]
    fn check_5_missing_bytes_are_bad_length() {
        // user_id_len says 40 but the body ends first.
        let mut body = vec![40u8];
        body.extend(vec![b'a'; 40]);
        body.extend_from_slice(&[0; 3]);
        assert_eq!(open(&seal_body(&body), 2), Err(Error::BadLength));
        // Native transport, body ends before the 64 key bytes.
        let mut body = vec![1u8, b'a'];
        body.extend(tail(1, 0, &[]));
        assert_eq!(open(&seal_body(&body), 1), Err(Error::BadLength));
    }

    #[test]
    fn check_5_transport_must_be_a_defined_bit() {
        for tr in [0u8, 3, 8] {
            let mut body = vec![1u8, b'a'];
            body.extend(tail(tr, 0, &[]));
            assert_eq!(open(&seal_body(&body), 2), Err(Error::BadTransport), "{tr}");
        }
    }

    #[test]
    fn check_5_metadata_length_rules() {
        let mut body = vec![1u8, b'a'];
        body.extend(tail(2, 257, &[0; 257]));
        assert_eq!(open(&seal_body(&body), 2), Err(Error::BadMetadata));
        let mut body = vec![1u8, b'a'];
        body.extend(tail(2, 4, &[0; 3]));
        assert_eq!(open(&seal_body(&body), 2), Err(Error::BadLength));
        let mut body = vec![1u8, b'a'];
        body.extend(tail(2, 0, &[0]));
        assert_eq!(open(&seal_body(&body), 2), Err(Error::BadLength));
    }

    #[test]
    fn check_6_user_id_not_utf8() {
        let mut body = vec![2u8, 0xff, 0xfe];
        body.extend(tail(2, 0, &[]));
        assert_eq!(open(&seal_body(&body), 2), Err(Error::BadUserId));
    }

    #[test]
    fn check_7_wrong_server() {
        let b = sealed(transport::WEBRTC);
        assert_eq!(
            open_server(&b, &ring(), NOW, &[0xcd; 16], transport::WEBRTC),
            Err(Error::WrongServer)
        );
    }

    #[test]
    fn check_8_expired() {
        let b = sealed(transport::WEBRTC);
        assert_eq!(
            open_server(&b, &ring(), EXPIRY, &SID, transport::WEBRTC).map(|_| ()),
            Ok(())
        );
        assert_eq!(
            open_server(&b, &ring(), EXPIRY + 1, &SID, transport::WEBRTC),
            Err(Error::Expired)
        );
    }

    #[test]
    fn check_9_via_mismatch() {
        let b = sealed(transport::WEBRTC);
        assert_eq!(open(&b, transport::NATIVE), Err(Error::BadTransport));
    }

    #[test]
    fn precedence_server_before_expiry_before_via() {
        let b = sealed(transport::WEBRTC);
        assert_eq!(
            open_server(&b, &ring(), EXPIRY + 1, &[0xcd; 16], transport::NATIVE),
            Err(Error::WrongServer)
        );
        assert_eq!(
            open_server(&b, &ring(), EXPIRY + 1, &SID, transport::NATIVE),
            Err(Error::Expired)
        );
    }

    #[test]
    fn key_ring_is_capped_at_16() {
        let mut r = ring();
        for id in 2..=16 {
            r.insert(id, [id; 32]).unwrap();
        }
        assert_eq!(r.insert(17, [17; 32]), Err(Error::TooLarge));
        // Replacing an existing id is not growth.
        assert!(r.insert(3, [0; 32]).is_ok());
    }
}
