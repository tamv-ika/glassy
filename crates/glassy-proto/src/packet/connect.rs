//! Native `CONNECT` packet (spec §4.2).
//!
//! `0x80 | ver(1)=1 | session_id(8) | conn_id(16) | connect_seq(u64 BE) | routing_ticket(60)
//! | server_ticket_len(u16 BE) | server_ticket | proof_tag(16) | padding(0x00…)`.

use super::{CONNECT_MIN, MAX_PACKET, packet_type};
use crate::crypto::{xchacha_open, xchacha_seal};
use crate::server_ticket::{
    SERVER_TICKET_MAX, SERVER_TICKET_NATIVE_MIN, ServerKeyRing, ServerTicket, open_server,
};
use crate::{Error, transport};

const VERSION: u8 = 1;
/// `type | ver | session_id | conn_id | connect_seq | routing_ticket | server_ticket_len`.
const HEADER_LEN: usize = 96;
const ROUTING_LEN: usize = 60;
const PROOF_LEN: usize = 16;

/// Proof nonce: `conn_id | 0⁸` (spec §4.2). `conn_id` must be fresh per `CONNECT`.
fn proof_nonce(conn_id: &[u8; 16]) -> [u8; 24] {
    let mut n = [0u8; 24];
    n[..16].copy_from_slice(conn_id);
    n
}

/// Copies a slice already length-checked by the caller; a mismatch is `BadLength`.
fn arr<const N: usize>(s: &[u8]) -> Result<[u8; N], Error> {
    s.try_into().map_err(|_| Error::BadLength)
}

fn arr_ref<const N: usize>(s: &[u8]) -> Result<&[u8; N], Error> {
    s.try_into().map_err(|_| Error::BadLength)
}

#[derive(Debug)]
/// Zero-copy view of a structurally valid `CONNECT` (spec §4.2); nothing is authenticated yet.
pub struct ConnectView<'a> {
    /// Session the client claims.
    pub session_id: [u8; 8],
    /// Client-chosen connection id, bound into the proof and reply AAD.
    pub conn_id: [u8; 16],
    /// Monotonic connect sequence number.
    pub connect_seq: u64,
    /// Sealed routing ticket the gateway used for routing (spec §3.1).
    pub routing_ticket: &'a [u8; 60],
    /// Sealed server ticket (spec §3.2).
    pub server_ticket: &'a [u8],
    /// Proof-of-key tag over the signed prefix, keyed with `key_c2s`.
    pub proof_tag: &'a [u8; 16],
    /// Trailing padding bytes; must be all zero.
    pub padding: &'a [u8],
    signed: &'a [u8],
}

/// Zero-allocation parse used by the gateway; checks structure only, not the proof.
pub fn parse_connect(b: &[u8]) -> Result<ConnectView<'_>, Error> {
    if !(CONNECT_MIN..=MAX_PACKET).contains(&b.len()) {
        return Err(Error::BadLength);
    }
    if b[0] != packet_type::CONNECT {
        return Err(Error::BadType);
    }
    if b[1] != VERSION {
        return Err(Error::BadVersion);
    }
    let ticket_len = usize::from(u16::from_be_bytes(arr(&b[94..96])?));
    if !(SERVER_TICKET_NATIVE_MIN..=SERVER_TICKET_MAX).contains(&ticket_len)
        || HEADER_LEN + ticket_len + PROOF_LEN > b.len()
    {
        return Err(Error::BadLength);
    }
    let signed_end = HEADER_LEN + ticket_len;
    let proof_end = signed_end + PROOF_LEN;
    Ok(ConnectView {
        session_id: arr(&b[2..10])?,
        conn_id: arr(&b[10..26])?,
        connect_seq: u64::from_be_bytes(arr(&b[26..34])?),
        routing_ticket: arr_ref(&b[34..34 + ROUTING_LEN])?,
        server_ticket: &b[HEADER_LEN..signed_end],
        proof_tag: arr_ref(&b[signed_end..proof_end])?,
        padding: &b[proof_end..],
        signed: &b[..signed_end],
    })
}

/// Builds a `CONNECT` (spec §4.2), zero-padded to `pad_to` bytes (at most `MAX_PACKET`).
pub fn build_connect(
    session_id: &[u8; 8],
    conn_id: &[u8; 16],
    connect_seq: u64,
    routing_ticket: &[u8; 60],
    server_ticket: &[u8],
    key_c2s: &[u8; 32],
    pad_to: usize,
) -> Result<Vec<u8>, Error> {
    if pad_to > MAX_PACKET {
        return Err(Error::TooLarge);
    }
    if !(SERVER_TICKET_NATIVE_MIN..=SERVER_TICKET_MAX).contains(&server_ticket.len()) {
        return Err(Error::BadLength);
    }
    let natural = HEADER_LEN + server_ticket.len() + PROOF_LEN;
    let mut out = Vec::with_capacity(natural.max(pad_to));
    out.push(packet_type::CONNECT);
    out.push(VERSION);
    out.extend_from_slice(session_id);
    out.extend_from_slice(conn_id);
    out.extend_from_slice(&connect_seq.to_be_bytes());
    out.extend_from_slice(routing_ticket);
    // Length fits u16: bounded to 458 above.
    out.extend_from_slice(&(server_ticket.len() as u16).to_be_bytes());
    out.extend_from_slice(server_ticket);
    // Empty plaintext: the sealed output is exactly the 16-byte tag.
    let proof = xchacha_seal(key_c2s, &proof_nonce(conn_id), &out, &[]);
    out.extend_from_slice(&proof);
    if pad_to > out.len() {
        out.resize(pad_to, 0);
    }
    Ok(out)
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// A `CONNECT` whose padding, ticket and proof have all been verified.
pub struct VerifiedConnect {
    /// Session id, equal to the ticket's.
    pub session_id: [u8; 8],
    /// Connection id from the packet.
    pub conn_id: [u8; 16],
    /// Connect sequence number from the packet.
    pub connect_seq: u64,
    /// The opened server ticket.
    pub ticket: ServerTicket,
}

/// Verifies a `CONNECT` in the fixed order of spec §4.2: padding, ticket, session, proof.
pub fn verify_connect(
    b: &[u8],
    ring: &ServerKeyRing,
    now: u32,
    self_server_id: &[u8; 16],
) -> Result<VerifiedConnect, Error> {
    let v = parse_connect(b)?;
    // Padding first: it is cheap and rejects a trailer that was never split off.
    if v.padding.iter().any(|&x| x != 0) {
        return Err(Error::BadPadding);
    }
    let ticket = open_server(
        v.server_ticket,
        ring,
        now,
        self_server_id,
        transport::NATIVE,
    )?;
    if ticket.session_id != v.session_id {
        return Err(Error::SessionMismatch);
    }
    // `open_server` guarantees keys for a native ticket; absence cannot be proven.
    let keys = ticket.native_keys.as_ref().ok_or(Error::BadTransport)?;
    xchacha_open(&keys.c2s, &proof_nonce(&v.conn_id), v.signed, v.proof_tag)?;
    Ok(VerifiedConnect {
        session_id: v.session_id,
        conn_id: v.conn_id,
        connect_seq: v.connect_seq,
        ticket,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing_ticket::{RoutingKeyRing, RoutingTicket, seal_routing};
    use crate::server_ticket::{NativeKeys, seal_server};
    use crate::transport;

    const NOW: u32 = 1_900_000_000;
    const EXPIRY: u32 = 2_000_000_000;
    const SID: [u8; 16] = [0xab; 16];
    const SESSION: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    const CONN: [u8; 16] = [0x66; 16];
    const KEY_C2S: [u8; 32] = [0x44; 32];
    const SEQ: u64 = 1_700_000_000_000;

    fn ring() -> ServerKeyRing {
        ServerKeyRing::new(1, [0x22; 32])
    }

    fn routing() -> [u8; 60] {
        let t = RoutingTicket {
            server_id: SID,
            session_id: SESSION,
            expiry: EXPIRY,
            transports: transport::NATIVE,
        };
        seal_routing(&t, &RoutingKeyRing::new(1, [0x11; 16]), [0x88; 12])
    }

    fn ticket(tr: u8, session: [u8; 8], metadata: Vec<u8>) -> Vec<u8> {
        let t = ServerTicket {
            user_id: "u".into(),
            server_id: SID,
            session_id: session,
            expiry: EXPIRY,
            transport: tr,
            native_keys: (tr == transport::NATIVE).then_some(NativeKeys {
                c2s: KEY_C2S,
                s2c: [0x55; 32],
            }),
            metadata,
        };
        seal_server(&t, &ring(), [0x99; 24]).unwrap()
    }

    fn native_ticket() -> Vec<u8> {
        ticket(transport::NATIVE, SESSION, Vec::new())
    }

    fn build(st: &[u8], pad_to: usize) -> Vec<u8> {
        build_connect(&SESSION, &CONN, SEQ, &routing(), st, &KEY_C2S, pad_to).unwrap()
    }

    fn verify(b: &[u8]) -> Result<VerifiedConnect, Error> {
        verify_connect(b, &ring(), NOW, &SID)
    }

    #[test]
    fn build_then_verify() {
        let b = build(&native_ticket(), 0);
        assert_eq!(b.len(), CONNECT_MIN);
        let v = verify(&b).unwrap();
        assert_eq!(v.session_id, SESSION);
        assert_eq!(v.conn_id, CONN);
        assert_eq!(v.connect_seq, SEQ);
        assert_eq!(v.ticket.user_id, "u");
        assert_eq!(v.ticket.native_keys.map(|k| k.c2s), Some(KEY_C2S));
    }

    #[test]
    fn parse_exposes_fields_without_copying() {
        let st = native_ticket();
        let b = build(&st, 300);
        let v = parse_connect(&b).unwrap();
        assert_eq!(v.session_id, SESSION);
        assert_eq!(v.conn_id, CONN);
        assert_eq!(v.connect_seq, SEQ);
        assert_eq!(v.routing_ticket[..], routing()[..]);
        assert_eq!(v.server_ticket, &st[..]);
        assert_eq!(v.padding.len(), 300 - CONNECT_MIN);
        assert!(v.padding.iter().all(|&x| x == 0));
    }

    #[test]
    fn build_padded_to_1200() {
        let b = build(&native_ticket(), 1200);
        assert_eq!(b.len(), 1200);
        assert!(verify(&b).is_ok());
    }

    #[test]
    fn pad_to_1201_rejected() {
        let r = build_connect(
            &SESSION,
            &CONN,
            SEQ,
            &routing(),
            &native_ticket(),
            &KEY_C2S,
            1201,
        );
        assert_eq!(r, Err(Error::TooLarge));
    }

    #[test]
    fn pad_to_below_natural_length_is_ignored() {
        assert_eq!(build(&native_ticket(), 100).len(), CONNECT_MIN);
    }

    #[test]
    fn build_rejects_out_of_range_ticket() {
        for len in [138usize, 459] {
            let r = build_connect(&SESSION, &CONN, SEQ, &routing(), &vec![0; len], &KEY_C2S, 0);
            assert_eq!(r, Err(Error::BadLength), "{len}");
        }
    }

    #[test]
    fn check_1_length_bounds() {
        let b = build(&native_ticket(), 1200);
        assert_eq!(parse_connect(&b[..250]).err(), Some(Error::BadLength));
        let mut long = b.clone();
        long.push(0);
        assert_eq!(parse_connect(&long).err(), Some(Error::BadLength));
        assert_eq!(parse_connect(&[]).err(), Some(Error::BadLength));
    }

    #[test]
    fn check_2_bad_type() {
        let mut b = build(&native_ticket(), 0);
        b[0] = 0x81;
        assert_eq!(parse_connect(&b).err(), Some(Error::BadType));
    }

    #[test]
    fn check_3_bad_version() {
        let mut b = build(&native_ticket(), 0);
        b[1] = 2;
        assert_eq!(parse_connect(&b).err(), Some(Error::BadVersion));
    }

    #[test]
    fn check_4_ticket_len_bounds() {
        let mut b = build(&native_ticket(), 1200);
        b[94..96].copy_from_slice(&138u16.to_be_bytes());
        assert_eq!(parse_connect(&b).err(), Some(Error::BadLength));
        b[94..96].copy_from_slice(&459u16.to_be_bytes());
        assert_eq!(parse_connect(&b).err(), Some(Error::BadLength));
    }

    #[test]
    fn check_4_ticket_len_overflowing_packet() {
        let mut b = build(&native_ticket(), 0);
        // 96 + 140 + 16 = 252 > 251.
        b[94..96].copy_from_slice(&140u16.to_be_bytes());
        assert_eq!(parse_connect(&b).err(), Some(Error::BadLength));
    }

    #[test]
    fn verify_1_nonzero_padding() {
        let mut b = build(&native_ticket(), 400);
        b[399] = 1;
        assert_eq!(verify(&b).err(), Some(Error::BadPadding));
    }

    #[test]
    fn verify_2_ticket_errors_pass_through() {
        let mut b = build(&native_ticket(), 0);
        b[96] ^= 0xff; // ticket version byte
        assert_eq!(verify(&b).err(), Some(Error::BadVersion));
        let wrong = verify_connect(&build(&native_ticket(), 0), &ring(), NOW, &[0xcd; 16]);
        assert_eq!(wrong.err(), Some(Error::WrongServer));
    }

    #[test]
    fn verify_2_webrtc_ticket_is_bad_transport() {
        let st = ticket(transport::WEBRTC, SESSION, vec![0; 100]);
        assert!(st.len() >= 139);
        let b = build(&st, 0);
        assert_eq!(verify(&b).err(), Some(Error::BadTransport));
    }

    #[test]
    fn verify_3_session_mismatch() {
        let st = ticket(transport::NATIVE, [9; 8], Vec::new());
        let b = build(&st, 0);
        assert_eq!(verify(&b).err(), Some(Error::SessionMismatch));
    }

    #[test]
    fn verify_4_bad_proof() {
        let mut b = build(&native_ticket(), 0);
        let last = b.len() - 1;
        b[last] ^= 1;
        assert_eq!(verify(&b).err(), Some(Error::AuthFailed));
        // A signed field changed after proofing also fails.
        let mut b = build(&native_ticket(), 0);
        b[40] ^= 1; // routing_ticket byte
        assert_eq!(verify(&b).err(), Some(Error::AuthFailed));
        let mut b = build(&native_ticket(), 0);
        b[30] ^= 1; // connect_seq
        assert_eq!(verify(&b).err(), Some(Error::AuthFailed));
    }

    #[test]
    fn padding_checked_before_proof() {
        let mut b = build(&native_ticket(), 400);
        b[399] = 1;
        b[250] ^= 1;
        assert_eq!(verify(&b).err(), Some(Error::BadPadding));
    }

    #[test]
    fn trailer_is_nonzero_padding_without_split() {
        use crate::packet::trailer::{ClientAddrV4, append_trailer};
        let mut b = build(&native_ticket(), 0);
        append_trailer(
            &mut b,
            ClientAddrV4 {
                ip: [203, 0, 113, 7],
                port: 4433,
            },
        );
        assert_eq!(verify(&b).err(), Some(Error::BadPadding));
    }
}
