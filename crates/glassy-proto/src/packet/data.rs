//! Native `DATA` and `DISCONNECT` packets (spec §4.4, §4.5).
//!
//! `type | session_id(8) | pn_low(u32 BE) | AEAD(body) | tag(16)`. The AAD is the 13 header
//! bytes and the nonce is `packet_nonce(server_nonce, pn)` with the full reconstructed `pn`.

use super::{MAX_PACKET, packet_type};
use crate::Error;
use crate::crypto::{packet_nonce, xchacha_open, xchacha_seal};

const HEADER_LEN: usize = 13;
const TAG_LEN: usize = 16;
/// Smallest `DATA`: a keep-alive with no frames.
pub const DATA_MIN: usize = HEADER_LEN + TAG_LEN;
/// Largest frame payload that still fits a 1200-byte datagram.
pub const MAX_FRAMES: usize = MAX_PACKET - DATA_MIN;
/// Wire length of `DISCONNECT`: header, one reason byte and the tag (spec §4.5).
pub const DISCONNECT_LEN: usize = HEADER_LEN + 1 + TAG_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Parsed 13-byte header shared by `DATA` and `DISCONNECT` (spec §4.1).
pub struct Header {
    /// Packet type byte, see [`packet_type`](super::packet_type).
    pub ty: u8,
    /// Session the packet belongs to.
    pub session_id: [u8; 8],
    /// Low 32 bits of the packet number; see [`decode_pn`](super::pn::decode_pn).
    pub pn_low: u32,
}

/// Parses the header of a `DATA` or `DISCONNECT`; the caller reconstructs `pn` from `pn_low`.
pub fn parse_header(b: &[u8]) -> Result<Header, Error> {
    if !(DATA_MIN..=MAX_PACKET).contains(&b.len()) {
        return Err(Error::BadLength);
    }
    let ty = b[0];
    if ty != packet_type::DATA && ty != packet_type::DISCONNECT {
        return Err(Error::BadType);
    }
    Ok(Header {
        ty,
        session_id: b[1..9].try_into().map_err(|_| Error::BadLength)?,
        pn_low: u32::from_be_bytes(b[9..13].try_into().map_err(|_| Error::BadLength)?),
    })
}

fn seal(
    ty: u8,
    key: &[u8; 32],
    server_nonce: &[u8; 16],
    session_id: &[u8; 8],
    pn: u64,
    body: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + body.len() + TAG_LEN);
    out.push(ty);
    out.extend_from_slice(session_id);
    // Only the low 32 bits travel; the receiver reconstructs the rest (RFC 9000 A.3).
    out.extend_from_slice(&(pn as u32).to_be_bytes());
    let sealed = xchacha_seal(key, &packet_nonce(server_nonce, pn), &out, body);
    out.extend_from_slice(&sealed);
    out
}

fn open(
    b: &[u8],
    ty: u8,
    key: &[u8; 32],
    server_nonce: &[u8; 16],
    pn: u64,
) -> Result<Vec<u8>, Error> {
    let h = parse_header(b)?;
    if h.ty != ty {
        return Err(Error::BadType);
    }
    let (aad, sealed) = b.split_at(HEADER_LEN);
    xchacha_open(key, &packet_nonce(server_nonce, pn), aad, sealed)
}

/// `pn` 0 is reserved for `ACCEPT`/`REJECT`, so it is never a valid `DATA` number.
pub fn seal_data(
    key: &[u8; 32],
    server_nonce: &[u8; 16],
    session_id: &[u8; 8],
    pn: u64,
    frames: &[u8],
) -> Result<Vec<u8>, Error> {
    if frames.len() > MAX_FRAMES {
        return Err(Error::TooLarge);
    }
    if pn == 0 {
        return Err(Error::Replayed);
    }
    Ok(seal(
        packet_type::DATA,
        key,
        server_nonce,
        session_id,
        pn,
        frames,
    ))
}

/// Opens a `DATA` packet with the packet number recovered by the caller; returns the frames.
pub fn open_data(
    key: &[u8; 32],
    server_nonce: &[u8; 16],
    b: &[u8],
    pn: u64,
) -> Result<Vec<u8>, Error> {
    open(b, packet_type::DATA, key, server_nonce, pn)
}

/// Seals a `DISCONNECT` carrying `reason`. `pn` 0 is refused (nonce reuse with `ACCEPT`).
pub fn seal_disconnect(
    key: &[u8; 32],
    server_nonce: &[u8; 16],
    session_id: &[u8; 8],
    pn: u64,
    reason: u8,
) -> Result<[u8; DISCONNECT_LEN], Error> {
    // pn 0 with key_s2c would reuse the ACCEPT/REJECT nonce (server_nonce | 0⁸), spec §0.3.
    if pn == 0 {
        return Err(Error::Replayed);
    }
    let v = seal(
        packet_type::DISCONNECT,
        key,
        server_nonce,
        session_id,
        pn,
        &[reason],
    );
    let mut out = [0u8; DISCONNECT_LEN];
    out.copy_from_slice(&v);
    Ok(out)
}

/// Returns the reason byte as received; unknown values are not an error.
pub fn open_disconnect(
    key: &[u8; 32],
    server_nonce: &[u8; 16],
    b: &[u8],
    pn: u64,
) -> Result<u8, Error> {
    if b.len() != DISCONNECT_LEN {
        return Err(Error::BadLength);
    }
    let p = open(b, packet_type::DISCONNECT, key, server_nonce, pn)?;
    p.first().copied().ok_or(Error::BadLength)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const KEY: [u8; 32] = [0x55; 32];
    const NONCE: [u8; 16] = [0x77; 16];
    const SESSION: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    #[test]
    fn data_keepalive_empty() {
        let b = seal_data(&KEY, &NONCE, &SESSION, 1, &[]).unwrap();
        assert_eq!(b.len(), 29);
        assert_eq!(open_data(&KEY, &NONCE, &b, 1), Ok(Vec::new()));
    }

    #[test]
    fn data_max_1200() {
        let frames = vec![0xaa; 1171];
        let b = seal_data(&KEY, &NONCE, &SESSION, 7, &frames).unwrap();
        assert_eq!(b.len(), 1200);
        assert_eq!(open_data(&KEY, &NONCE, &b, 7), Ok(frames));
    }

    #[test]
    fn data_1172_rejected() {
        let r = seal_data(&KEY, &NONCE, &SESSION, 7, &vec![0; 1172]);
        assert_eq!(r, Err(Error::TooLarge));
    }

    #[test]
    fn data_pn_zero_rejected() {
        assert_eq!(
            seal_data(&KEY, &NONCE, &SESSION, 0, &[1]),
            Err(Error::Replayed)
        );
    }

    #[test]
    fn data_wrong_direction_key() {
        let b = seal_data(&KEY, &NONCE, &SESSION, 1, &[1, 2]).unwrap();
        assert_eq!(
            open_data(&[0x44; 32], &NONCE, &b, 1),
            Err(Error::AuthFailed)
        );
    }

    #[test]
    fn data_wrong_pn() {
        let b = seal_data(&KEY, &NONCE, &SESSION, 1, &[1, 2]).unwrap();
        assert_eq!(open_data(&KEY, &NONCE, &b, 2), Err(Error::AuthFailed));
    }

    #[test]
    fn data_header_is_authenticated() {
        let mut b = seal_data(&KEY, &NONCE, &SESSION, 1, &[1, 2]).unwrap();
        b[1] ^= 1; // session_id
        assert_eq!(open_data(&KEY, &NONCE, &b, 1), Err(Error::AuthFailed));
    }

    #[test]
    fn data_pn_low_wraps_with_full_pn_in_nonce() {
        let pn = 0x1_0000_0005;
        let b = seal_data(&KEY, &NONCE, &SESSION, pn, &[9]).unwrap();
        assert_eq!(parse_header(&b).map(|h| h.pn_low), Ok(5));
        assert_eq!(open_data(&KEY, &NONCE, &b, pn), Ok(vec![9]));
        assert_eq!(open_data(&KEY, &NONCE, &b, 5), Err(Error::AuthFailed));
    }

    #[test]
    fn data_open_rejects_disconnect_type() {
        let d = seal_disconnect(&KEY, &NONCE, &SESSION, 1, 0).unwrap();
        assert_eq!(open_data(&KEY, &NONCE, &d, 1), Err(Error::BadType));
    }

    #[test]
    fn parse_header_checks() {
        let b = seal_data(&KEY, &NONCE, &SESSION, 3, &[]).unwrap();
        assert_eq!(
            parse_header(&b),
            Ok(Header {
                ty: 0x82,
                session_id: SESSION,
                pn_low: 3
            })
        );
        assert_eq!(parse_header(&b[..28]), Err(Error::BadLength));
        assert_eq!(parse_header(&vec![0x82; 1201]), Err(Error::BadLength));
        let mut t = b;
        t[0] = 0x85;
        assert_eq!(parse_header(&t), Err(Error::BadType));
        t[0] = 0x80;
        assert_eq!(parse_header(&t), Err(Error::BadType));
    }

    #[test]
    fn disconnect_pn_zero_rejected() {
        assert_eq!(
            seal_disconnect(&KEY, &NONCE, &SESSION, 0, 0),
            Err(Error::Replayed)
        );
    }

    #[test]
    fn disconnect_is_30_bytes() {
        let b = seal_disconnect(&KEY, &NONCE, &SESSION, 4, 2).unwrap();
        assert_eq!(b.len(), 30);
        assert_eq!(b[0], 0x83);
        assert_eq!(open_disconnect(&KEY, &NONCE, &b, 4), Ok(2));
    }

    #[test]
    fn disconnect_unknown_reason_preserved() {
        let b = seal_disconnect(&KEY, &NONCE, &SESSION, 4, 0xfe).unwrap();
        assert_eq!(open_disconnect(&KEY, &NONCE, &b, 4), Ok(0xfe));
    }

    #[test]
    fn disconnect_length_and_type() {
        let b = seal_disconnect(&KEY, &NONCE, &SESSION, 4, 0).unwrap();
        assert_eq!(
            open_disconnect(&KEY, &NONCE, &b[..29], 4),
            Err(Error::BadLength)
        );
        let data = seal_data(&KEY, &NONCE, &SESSION, 4, &[0]).unwrap();
        assert_eq!(data.len(), 30);
        assert_eq!(open_disconnect(&KEY, &NONCE, &data, 4), Err(Error::BadType));
    }

    proptest! {
        #[test]
        fn data_roundtrip(
            key in any::<[u8; 32]>(),
            nonce in any::<[u8; 16]>(),
            session in any::<[u8; 8]>(),
            pn in 1u64..(1 << 62),
            frames in proptest::collection::vec(any::<u8>(), 0..=1171),
            reason in any::<u8>(),
        ) {
            let b = seal_data(&key, &nonce, &session, pn, &frames).unwrap();
            let h = parse_header(&b).unwrap();
            prop_assert_eq!((h.session_id, h.pn_low), (session, pn as u32));
            prop_assert_eq!(open_data(&key, &nonce, &b, pn), Ok(frames));
            let d = seal_disconnect(&key, &nonce, &session, pn, reason).unwrap();
            prop_assert_eq!(open_disconnect(&key, &nonce, &d, pn), Ok(reason));
        }
    }
}
