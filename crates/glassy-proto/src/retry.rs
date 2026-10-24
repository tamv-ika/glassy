//! Stateless Retry offload in no-shared-state mode (draft-ietf-quic-retry-offload; spec §3.6).
//!
//! Token = `byte0 (0 | ODCIL) | ODCID | expiry (u64 BE) | tag16`, where tag16 is the first 16 bytes
//! of HMAC-SHA256(key, byte0 | ODCID | expiry | ip16 | port (u16 BE) | RSCIL | RSCID). Only the
//! gateway holds the key; game servers read the ODCID in clear and trust gateway-sourced tokens.

use std::net::{IpAddr, SocketAddr};

use crate::Error;
use crate::crypto::hmac_sha256;

const MIN_ODCIL: usize = 8;
const MAX_ODCIL: usize = 20;
const MAX_CID: usize = 20;
const EXPIRY_LEN: usize = 8;
const TAG_LEN: usize = 16;

/// IPv4 addresses occupy the first 4 bytes followed by 12 zero bytes, as in the draft.
fn ip16(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => {
            let mut out = [0u8; 16];
            out[..4].copy_from_slice(&v4.octets());
            out
        }
        IpAddr::V6(v6) => v6.octets(),
    }
}

fn token_tag(
    key: &[u8; 32],
    byte0: u8,
    odcid: &[u8],
    expiry: &[u8],
    client: SocketAddr,
    rscid: &[u8],
) -> [u8; 32] {
    // RSCID length is at most 20 (checked by every caller), so the cast is lossless.
    let rscil = [rscid.len() as u8];
    hmac_sha256(
        key,
        &[
            &[byte0],
            odcid,
            expiry,
            &ip16(client.ip()),
            &client.port().to_be_bytes(),
            &rscil,
            rscid,
        ],
    )
}

/// Mints a token bound to the client address and to the Retry's Source Connection ID.
pub fn mint_retry_token(
    key: &[u8; 32],
    odcid: &[u8],
    client: SocketAddr,
    rscid: &[u8],
    expiry: u64,
) -> Result<Vec<u8>, Error> {
    if !(MIN_ODCIL..=MAX_ODCIL).contains(&odcid.len()) {
        return Err(Error::BadOdcil);
    }
    if rscid.len() > MAX_CID {
        return Err(Error::BadLength);
    }
    // ODCIL <= 20 was checked above, so it fits in the low bits with bit 7 clear.
    let byte0 = odcid.len() as u8;
    let expiry = expiry.to_be_bytes();
    let tag = token_tag(key, byte0, odcid, &expiry, client, rscid);
    let mut t = Vec::with_capacity(1 + odcid.len() + EXPIRY_LEN + TAG_LEN);
    t.push(byte0);
    t.extend_from_slice(odcid);
    t.extend_from_slice(&expiry);
    t.extend_from_slice(&tag[..TAG_LEN]);
    Ok(t)
}

/// `(byte0, odcid, expiry, tag)` slices of a structurally valid token.
type Parts<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);

/// Structure checks 1-4; returns `(byte0, odcid, expiry, tag)` borrowed from `token`.
fn split(token: &[u8]) -> Result<Parts<'_>, Error> {
    let (&byte0, rest) = token.split_first().ok_or(Error::BadLength)?;
    if byte0 & 0x80 != 0 {
        return Err(Error::BadTokenType);
    }
    let odcil = usize::from(byte0);
    if !(MIN_ODCIL..=MAX_ODCIL).contains(&odcil) {
        return Err(Error::BadOdcil);
    }
    if rest.len() != odcil + EXPIRY_LEN + TAG_LEN {
        return Err(Error::BadLength);
    }
    let (odcid, rest) = rest.split_at(odcil);
    let (expiry, tag) = rest.split_at(EXPIRY_LEN);
    Ok((byte0, odcid, expiry, tag))
}

/// Reads the ODCID without checking the tag; for game servers that trust gateway-sourced tokens.
pub fn retry_token_odcid(token: &[u8]) -> Result<&[u8], Error> {
    split(token).map(|(_, odcid, _, _)| odcid)
}

/// Validates a token carried by an Initial whose DCID is `packet_dcid`; returns the ODCID.
///
/// The tag is checked before the expiry so an attacker cannot probe expiry without a valid tag.
pub fn validate_retry_token<'a>(
    key: &[u8; 32],
    token: &'a [u8],
    client: SocketAddr,
    packet_dcid: &[u8],
    now: u64,
) -> Result<&'a [u8], Error> {
    let (byte0, odcid, expiry, tag) = split(token)?;
    // No token can bind a DCID longer than 20 bytes (RFC 9000 §17.2), so it can never verify.
    if packet_dcid.len() > MAX_CID {
        return Err(Error::AuthFailed);
    }
    let want = token_tag(key, byte0, odcid, expiry, client, packet_dcid);
    // Constant-time compare of the truncated tag.
    let diff = want[..TAG_LEN]
        .iter()
        .zip(tag)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if diff != 0 {
        return Err(Error::AuthFailed);
    }
    let mut buf = [0u8; EXPIRY_LEN];
    buf.copy_from_slice(expiry);
    if now > u64::from_be_bytes(buf) {
        return Err(Error::Expired);
    }
    Ok(odcid)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ODCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
    const RSCID: [u8; 8] = [0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5];
    const KEY: [u8; 32] = [0x33; 32];
    const EXPIRY: u64 = 2_000_000_000;

    fn client() -> SocketAddr {
        "192.0.2.10:51000".parse().unwrap()
    }

    fn token() -> Vec<u8> {
        mint_retry_token(&KEY, &ODCID, client(), &RSCID, EXPIRY).unwrap()
    }

    fn validate(t: &[u8], now: u64) -> Result<Vec<u8>, Error> {
        validate_retry_token(&KEY, t, client(), &RSCID, now).map(<[u8]>::to_vec)
    }

    #[test]
    fn token_known_answer() {
        // Same bytes as the spike, computed independently with Python's hmac/hashlib.
        let hexed: String = token().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hexed,
            "088394c8f03e51570800000000773594008fc3943538d3f2736f399447bed2acdd"
        );
    }

    #[test]
    fn validate_ok_returns_odcid() {
        assert_eq!(validate(&token(), 1_999_999_999).unwrap(), ODCID.to_vec());
        assert_eq!(validate(&token(), EXPIRY).unwrap(), ODCID.to_vec());
    }

    #[test]
    fn empty_token_is_bad_length() {
        assert_eq!(validate(&[], 0), Err(Error::BadLength));
        assert_eq!(retry_token_odcid(&[]), Err(Error::BadLength));
    }

    #[test]
    fn type_bit_set_is_bad_token_type() {
        let mut t = token();
        t[0] |= 0x80;
        assert_eq!(validate(&t, 0), Err(Error::BadTokenType));
        assert_eq!(retry_token_odcid(&t), Err(Error::BadTokenType));
    }

    #[test]
    fn odcil_out_of_range_is_bad_odcil() {
        let mut t = token();
        t[0] = 7;
        assert_eq!(validate(&t, 0), Err(Error::BadOdcil));
        t[0] = 21;
        assert_eq!(validate(&t, 0), Err(Error::BadOdcil));
        assert_eq!(retry_token_odcid(&t), Err(Error::BadOdcil));
    }

    #[test]
    fn length_mismatch_is_bad_length() {
        let t = token();
        assert_eq!(validate(&t[..t.len() - 1], 0), Err(Error::BadLength));
        let mut long = t.clone();
        long.push(0);
        assert_eq!(validate(&long, 0), Err(Error::BadLength));
        assert_eq!(validate(&t[..1], 0), Err(Error::BadLength));
    }

    #[test]
    fn wrong_client_or_dcid_is_auth_failed() {
        let t = token();
        let other_ip: SocketAddr = "192.0.2.11:51000".parse().unwrap();
        let other_port: SocketAddr = "192.0.2.10:51001".parse().unwrap();
        for c in [other_ip, other_port] {
            assert_eq!(
                validate_retry_token(&KEY, &t, c, &RSCID, 0),
                Err(Error::AuthFailed)
            );
        }
        assert_eq!(
            validate_retry_token(&KEY, &t, client(), &ODCID, 0),
            Err(Error::AuthFailed)
        );
        assert_eq!(
            validate_retry_token(&[0x34; 32], &t, client(), &RSCID, 0),
            Err(Error::AuthFailed)
        );
    }

    #[test]
    fn expired_by_one_is_expired() {
        assert_eq!(validate(&token(), EXPIRY + 1), Err(Error::Expired));
    }

    #[test]
    fn bad_tag_is_checked_before_expiry() {
        let mut t = token();
        let last = t.len() - 1;
        t[last] ^= 1;
        assert_eq!(validate(&t, EXPIRY + 1), Err(Error::AuthFailed));
    }

    #[test]
    fn parse_ignores_tag() {
        let mut t = token();
        let last = t.len() - 1;
        t[last] ^= 1;
        assert_eq!(retry_token_odcid(&t).unwrap(), &ODCID);
    }

    #[test]
    fn mint_rejects_bad_odcid_and_rscid_lengths() {
        for n in [0usize, 7, 21] {
            assert_eq!(
                mint_retry_token(&KEY, &vec![1; n], client(), &RSCID, EXPIRY),
                Err(Error::BadOdcil)
            );
        }
        assert_eq!(
            mint_retry_token(&KEY, &ODCID, client(), &[0; 21], EXPIRY),
            Err(Error::BadLength)
        );
        assert!(mint_retry_token(&KEY, &[1; 20], client(), &[0; 20], EXPIRY).is_ok());
        assert!(mint_retry_token(&KEY, &ODCID, client(), &[], EXPIRY).is_ok());
    }

    #[test]
    fn ipv6_client_round_trips() {
        let c: SocketAddr = "[2001:db8::7]:4433".parse().unwrap();
        let t = mint_retry_token(&KEY, &ODCID, c, &RSCID, EXPIRY).unwrap();
        assert_eq!(
            validate_retry_token(&KEY, &t, c, &RSCID, 0).unwrap(),
            &ODCID
        );
    }
}
