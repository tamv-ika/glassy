//! Native `ACCEPT` and `REJECT` packets (spec §4.3, §4.4).
//!
//! `type | session_id(8) | connect_seq(u64 BE) | server_nonce(16) | AEAD_s2c(body) | tag(16)`.
//! The AEAD nonce is `server_nonce | 0⁸` and the AAD is the 33 header bytes followed by the
//! `conn_id` of the `CONNECT` being answered, which is not on the wire.

use super::packet_type;
use crate::Error;
use crate::crypto::{packet_nonce, xchacha_open, xchacha_seal};

/// `type | session_id | connect_seq | server_nonce`.
const HEAD_LEN: usize = 33;
pub const ACCEPT_LEN: usize = 59;
pub const REJECT_LEN: usize = 58;

pub mod reject_reason {
    pub const STALE_CONNECT_SEQ: u8 = 1;
    pub const KICKED: u8 = 2;
    pub const SESSION_CLOSED: u8 = 3;
    pub const SERVER_FULL: u8 = 4;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accept {
    pub session_id: [u8; 8],
    pub connect_seq: u64,
    pub server_nonce: [u8; 16],
    pub resumed: bool,
    pub server_time_ms: u64,
}

/// `reason` keeps unknown byte values as received; mapping to SDK errors is SP2's job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reject {
    pub session_id: [u8; 8],
    pub connect_seq: u64,
    pub server_nonce: [u8; 16],
    pub reason: u8,
    pub last_connect_seq: u64,
}

fn seal_reply(
    ty: u8,
    session_id: &[u8; 8],
    connect_seq: u64,
    server_nonce: &[u8; 16],
    body: &[u8],
    conn_id: &[u8; 16],
    key_s2c: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEAD_LEN + body.len() + 16);
    out.push(ty);
    out.extend_from_slice(session_id);
    out.extend_from_slice(&connect_seq.to_be_bytes());
    out.extend_from_slice(server_nonce);
    let mut aad = [0u8; HEAD_LEN + 16];
    aad[..HEAD_LEN].copy_from_slice(&out);
    aad[HEAD_LEN..].copy_from_slice(conn_id);
    let sealed = xchacha_seal(key_s2c, &packet_nonce(server_nonce, 0), &aad, body);
    out.extend_from_slice(&sealed);
    out
}

/// Head fields plus the decrypted body of an authenticated reply.
struct Opened {
    session_id: [u8; 8],
    connect_seq: u64,
    server_nonce: [u8; 16],
    body: Vec<u8>,
}

/// Checks length and type, then opens the body.
fn open_reply(
    b: &[u8],
    ty: u8,
    len: usize,
    conn_id: &[u8; 16],
    key_s2c: &[u8; 32],
) -> Result<Opened, Error> {
    if b.len() != len {
        return Err(Error::BadLength);
    }
    let (head, sealed) = b.split_at(HEAD_LEN);
    if head[0] != ty {
        return Err(Error::BadType);
    }
    let session_id: [u8; 8] = head[1..9].try_into().map_err(|_| Error::BadLength)?;
    let connect_seq = u64::from_be_bytes(head[9..17].try_into().map_err(|_| Error::BadLength)?);
    let server_nonce: [u8; 16] = head[17..33].try_into().map_err(|_| Error::BadLength)?;
    let mut aad = [0u8; HEAD_LEN + 16];
    aad[..HEAD_LEN].copy_from_slice(head);
    aad[HEAD_LEN..].copy_from_slice(conn_id);
    let plain = xchacha_open(key_s2c, &packet_nonce(&server_nonce, 0), &aad, sealed)?;
    Ok(Opened {
        session_id,
        connect_seq,
        server_nonce,
        body: plain,
    })
}

pub fn build_accept(a: &Accept, conn_id: &[u8; 16], key_s2c: &[u8; 32]) -> [u8; ACCEPT_LEN] {
    let mut body = [0u8; 10];
    body[0] = u8::from(a.resumed);
    body[2..].copy_from_slice(&a.server_time_ms.to_be_bytes());
    let v = seal_reply(
        packet_type::ACCEPT,
        &a.session_id,
        a.connect_seq,
        &a.server_nonce,
        &body,
        conn_id,
        key_s2c,
    );
    let mut out = [0u8; ACCEPT_LEN];
    // Length is fixed by the constant sizes above.
    out.copy_from_slice(&v);
    out
}

/// Reads the unauthenticated head of an `ACCEPT`/`REJECT` so a client can find the pending
/// `conn_id` it needs for [`open_accept`]/[`open_reject`]. Returns `(type, session_id, connect_seq)`.
///
/// The length decides first: anything but 59 or 58 bytes is `BadLength`. The type must then
/// match the length (59 with `0x81`, 58 with `0x84`), otherwise `BadType`.
pub fn peek_reply(b: &[u8]) -> Result<(u8, [u8; 8], u64), Error> {
    let want = match b.len() {
        ACCEPT_LEN => packet_type::ACCEPT,
        REJECT_LEN => packet_type::REJECT,
        _ => return Err(Error::BadLength),
    };
    let ty = b[0];
    if ty != want {
        return Err(Error::BadType);
    }
    let session_id = b[1..9].try_into().map_err(|_| Error::BadLength)?;
    let seq = u64::from_be_bytes(b[9..17].try_into().map_err(|_| Error::BadLength)?);
    Ok((ty, session_id, seq))
}

pub fn open_accept(b: &[u8], conn_id: &[u8; 16], key_s2c: &[u8; 32]) -> Result<Accept, Error> {
    let o = open_reply(b, packet_type::ACCEPT, ACCEPT_LEN, conn_id, key_s2c)?;
    let p = o.body;
    if p.len() != 10 {
        return Err(Error::BadLength);
    }
    if p[0] & !1 != 0 || p[1] != 0 {
        return Err(Error::ReservedNonzero);
    }
    Ok(Accept {
        session_id: o.session_id,
        connect_seq: o.connect_seq,
        server_nonce: o.server_nonce,
        resumed: p[0] & 1 == 1,
        server_time_ms: u64::from_be_bytes(p[2..10].try_into().map_err(|_| Error::BadLength)?),
    })
}

pub fn build_reject(r: &Reject, conn_id: &[u8; 16], key_s2c: &[u8; 32]) -> [u8; REJECT_LEN] {
    let mut body = [0u8; 9];
    body[0] = r.reason;
    body[1..].copy_from_slice(&r.last_connect_seq.to_be_bytes());
    let v = seal_reply(
        packet_type::REJECT,
        &r.session_id,
        r.connect_seq,
        &r.server_nonce,
        &body,
        conn_id,
        key_s2c,
    );
    let mut out = [0u8; REJECT_LEN];
    out.copy_from_slice(&v);
    out
}

pub fn open_reject(b: &[u8], conn_id: &[u8; 16], key_s2c: &[u8; 32]) -> Result<Reject, Error> {
    let o = open_reply(b, packet_type::REJECT, REJECT_LEN, conn_id, key_s2c)?;
    let p = o.body;
    if p.len() != 9 {
        return Err(Error::BadLength);
    }
    Ok(Reject {
        session_id: o.session_id,
        connect_seq: o.connect_seq,
        server_nonce: o.server_nonce,
        reason: p[0],
        last_connect_seq: u64::from_be_bytes(p[1..9].try_into().map_err(|_| Error::BadLength)?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const CONN: [u8; 16] = [0x66; 16];
    const KEY: [u8; 32] = [0x55; 32];

    fn accept() -> Accept {
        Accept {
            session_id: [1, 2, 3, 4, 5, 6, 7, 8],
            connect_seq: 1_700_000_000_000,
            server_nonce: [0x77; 16],
            resumed: false,
            server_time_ms: 1_900_000_000_123,
        }
    }

    fn reject() -> Reject {
        Reject {
            session_id: [1, 2, 3, 4, 5, 6, 7, 8],
            connect_seq: 5,
            server_nonce: [0x77; 16],
            reason: reject_reason::STALE_CONNECT_SEQ,
            last_connect_seq: 9,
        }
    }

    /// Seals an arbitrary `ACCEPT` body so reserved-bit handling can be tested past the AEAD.
    fn forged_accept(body: [u8; 10]) -> Vec<u8> {
        let a = accept();
        seal_reply(
            packet_type::ACCEPT,
            &a.session_id,
            a.connect_seq,
            &a.server_nonce,
            &body,
            &CONN,
            &KEY,
        )
    }

    #[test]
    fn accept_is_59_bytes() {
        let b = build_accept(&accept(), &CONN, &KEY);
        assert_eq!(b.len(), 59);
        assert_eq!(b[0], 0x81);
        assert_eq!(open_accept(&b, &CONN, &KEY), Ok(accept()));
    }

    #[test]
    fn reject_is_58_bytes() {
        let b = build_reject(&reject(), &CONN, &KEY);
        assert_eq!(b.len(), 58);
        assert_eq!(b[0], 0x84);
        assert_eq!(open_reject(&b, &CONN, &KEY), Ok(reject()));
    }

    #[test]
    fn accept_resumed_flag_roundtrips() {
        let a = Accept {
            resumed: true,
            ..accept()
        };
        let b = build_accept(&a, &CONN, &KEY);
        assert_eq!(open_accept(&b, &CONN, &KEY), Ok(a));
    }

    #[test]
    fn accept_bound_to_conn_id() {
        let b = build_accept(&accept(), &CONN, &KEY);
        assert_eq!(open_accept(&b, &[0x67; 16], &KEY), Err(Error::AuthFailed));
        let r = build_reject(&reject(), &CONN, &KEY);
        assert_eq!(open_reject(&r, &[0x67; 16], &KEY), Err(Error::AuthFailed));
    }

    #[test]
    fn accept_wrong_key_or_tamper_is_auth_failed() {
        let mut b = build_accept(&accept(), &CONN, &KEY);
        assert_eq!(open_accept(&b, &CONN, &[0x44; 32]), Err(Error::AuthFailed));
        b[20] ^= 1; // server_nonce, both nonce and AAD
        assert_eq!(open_accept(&b, &CONN, &KEY), Err(Error::AuthFailed));
    }

    #[test]
    fn accept_length_and_type_checks() {
        let b = build_accept(&accept(), &CONN, &KEY);
        assert_eq!(open_accept(&b[..58], &CONN, &KEY), Err(Error::BadLength));
        let mut long = b.to_vec();
        long.push(0);
        assert_eq!(open_accept(&long, &CONN, &KEY), Err(Error::BadLength));
        let mut t = b;
        t[0] = 0x84;
        assert_eq!(open_accept(&t, &CONN, &KEY), Err(Error::BadType));
        let r = build_reject(&reject(), &CONN, &KEY);
        assert_eq!(open_reject(&r[..57], &CONN, &KEY), Err(Error::BadLength));
        let mut t = r;
        t[0] = 0x81;
        assert_eq!(open_reject(&t, &CONN, &KEY), Err(Error::BadType));
    }

    #[test]
    fn accept_reserved_bits_rejected_after_aead() {
        let mut body = [0u8; 10];
        body[2..].copy_from_slice(&5u64.to_be_bytes());
        for (i, v) in [(0usize, 2u8), (0, 0x80), (1, 1)] {
            let mut bd = body;
            bd[i] = v;
            let b = forged_accept(bd);
            assert_eq!(
                open_accept(&b, &CONN, &KEY),
                Err(Error::ReservedNonzero),
                "{i} {v}"
            );
        }
        assert!(open_accept(&forged_accept(body), &CONN, &KEY).is_ok());
    }

    #[test]
    fn reject_unknown_reason_preserved() {
        let r = Reject {
            reason: 9,
            ..reject()
        };
        let b = build_reject(&r, &CONN, &KEY);
        assert_eq!(open_reject(&b, &CONN, &KEY).map(|x| x.reason), Ok(9));
    }

    #[test]
    fn peek_reply_reads_head_without_key() {
        let b = build_accept(&accept(), &CONN, &KEY);
        assert_eq!(
            peek_reply(&b),
            Ok((0x81, accept().session_id, accept().connect_seq))
        );
        let r = build_reject(&reject(), &CONN, &KEY);
        assert_eq!(peek_reply(&r), Ok((0x84, reject().session_id, 5)));
        assert_eq!(peek_reply(&r[..57]), Err(Error::BadLength));
        assert_eq!(peek_reply(&b[..58]), Err(Error::BadType));
        assert_eq!(peek_reply(&[]), Err(Error::BadLength));
        let mut bad = b;
        bad[0] = 0x82;
        assert_eq!(peek_reply(&bad), Err(Error::BadType));
    }

    proptest! {
        #[test]
        fn accept_reject_roundtrip(
            session_id in any::<[u8; 8]>(),
            connect_seq in any::<u64>(),
            server_nonce in any::<[u8; 16]>(),
            conn_id in any::<[u8; 16]>(),
            key in any::<[u8; 32]>(),
            resumed in any::<bool>(),
            time in any::<u64>(),
            reason in any::<u8>(),
            last in any::<u64>(),
        ) {
            let a = Accept { session_id, connect_seq, server_nonce, resumed, server_time_ms: time };
            let b = build_accept(&a, &conn_id, &key);
            prop_assert_eq!(open_accept(&b, &conn_id, &key), Ok(a));
            let r = Reject { session_id, connect_seq, server_nonce, reason, last_connect_seq: last };
            let b = build_reject(&r, &conn_id, &key);
            prop_assert_eq!(open_reject(&b, &conn_id, &key), Ok(r));
        }
    }
}
