//! Stateless Retry offload in no-shared-state mode (draft-ietf-quic-retry-offload; spec §3.6).
//!
//! Token = `byte0 (0 | ODCIL) | ODCID | expiry (u64 BE) | tag16`, where tag16 is the first 16 bytes
//! of HMAC-SHA256(key, byte0 | ODCID | expiry | ip16 | port (u16 BE) | RSCIL | RSCID). Only the
//! gateway holds the key; game servers read the ODCID in clear and trust gateway-sourced tokens.

use std::net::{IpAddr, SocketAddr};

use aes_gcm::Aes128Gcm;
use aes_gcm::aead::{Aead, Payload};
use hmac::{Hmac, KeyInit as _, Mac};
use sha2::Sha256;

const MIN_ODCIL: usize = 8;
const MAX_ODCIL: usize = 20;
const EXPIRY_LEN: usize = 8;
const TAG_LEN: usize = 16;
/// RFC 9001 §5.8 Retry integrity key and nonce for QUIC v1.
const RETRY_INTEGRITY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const RETRY_INTEGRITY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

#[derive(Debug, PartialEq, Eq)]
pub enum RetryError {
    /// First bit set: a NEW_TOKEN token, which this offload never issues.
    Type,
    Odcil,
    Length,
    Auth,
    Expired,
}

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

fn token_mac(
    key: &[u8; 32],
    byte0: u8,
    odcid: &[u8],
    expiry: &[u8],
    client: SocketAddr,
    rscid: &[u8],
) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&[byte0]);
    mac.update(odcid);
    mac.update(expiry);
    mac.update(&ip16(client.ip()));
    mac.update(&client.port().to_be_bytes());
    mac.update(&[u8::try_from(rscid.len()).expect("cid <= 20")]);
    mac.update(rscid);
    mac
}

/// Mints a token bound to the client address and to the Retry's Source Connection ID.
pub fn mint_token(
    key: &[u8; 32],
    odcid: &[u8],
    client: SocketAddr,
    rscid: &[u8],
    expiry: u64,
) -> Vec<u8> {
    let byte0 = u8::try_from(odcid.len()).expect("odcid <= 20");
    let expiry = expiry.to_be_bytes();
    let tag = token_mac(key, byte0, odcid, &expiry, client, rscid)
        .finalize()
        .into_bytes();
    let mut t = Vec::with_capacity(1 + odcid.len() + EXPIRY_LEN + TAG_LEN);
    t.push(byte0);
    t.extend_from_slice(odcid);
    t.extend_from_slice(&expiry);
    t.extend_from_slice(&tag[..TAG_LEN]);
    t
}

/// Validates a token carried by an Initial whose DCID is `packet_dcid`; returns the ODCID.
pub fn validate_token(
    key: &[u8; 32],
    token: &[u8],
    client: SocketAddr,
    packet_dcid: &[u8],
    now: u64,
) -> Result<Vec<u8>, RetryError> {
    let byte0 = *token.first().ok_or(RetryError::Length)?;
    if byte0 & 0x80 != 0 {
        return Err(RetryError::Type);
    }
    let odcil = usize::from(byte0);
    if !(MIN_ODCIL..=MAX_ODCIL).contains(&odcil) {
        return Err(RetryError::Odcil);
    }
    if token.len() != 1 + odcil + EXPIRY_LEN + TAG_LEN {
        return Err(RetryError::Length);
    }
    let odcid = &token[1..1 + odcil];
    let expiry = &token[1 + odcil..1 + odcil + EXPIRY_LEN];
    let tag = &token[1 + odcil + EXPIRY_LEN..];
    token_mac(key, byte0, odcid, expiry, client, packet_dcid)
        .verify_truncated_left(tag)
        .map_err(|_| RetryError::Auth)?;
    let expiry = u64::from_be_bytes(expiry.try_into().expect("8 bytes"));
    if now > expiry {
        return Err(RetryError::Expired);
    }
    Ok(odcid.to_vec())
}

/// Builds a QUIC v1 Retry packet with its integrity tag (RFC 9000 §17.2.5, RFC 9001 §5.8).
pub fn build_retry(client_scid: &[u8], rscid: &[u8], odcid: &[u8], token: &[u8]) -> Vec<u8> {
    // The four low bits are unused; 0xff matches the RFC 9001 A.4 test vector.
    let mut pkt = vec![0xff, 0x00, 0x00, 0x00, 0x01];
    pkt.push(u8::try_from(client_scid.len()).expect("cid <= 20"));
    pkt.extend_from_slice(client_scid);
    pkt.push(u8::try_from(rscid.len()).expect("cid <= 20"));
    pkt.extend_from_slice(rscid);
    pkt.extend_from_slice(token);

    let mut pseudo = Vec::with_capacity(1 + odcid.len() + pkt.len());
    pseudo.push(u8::try_from(odcid.len()).expect("cid <= 20"));
    pseudo.extend_from_slice(odcid);
    pseudo.extend_from_slice(&pkt);
    let tag = Aes128Gcm::new(&RETRY_INTEGRITY_KEY_V1.into())
        .encrypt(
            &RETRY_INTEGRITY_NONCE_V1.into(),
            Payload {
                msg: &[],
                aad: &pseudo,
            },
        )
        .expect("empty plaintext is within AES-GCM limits");
    pkt.extend_from_slice(&tag);
    pkt
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    const ODCID: [u8; 8] = hex!("8394c8f03e515708");
    const RSCID: [u8; 8] = hex!("f067a5502a4262b5");
    const KEY: [u8; 32] = [0x33; 32];

    fn client() -> SocketAddr {
        "192.0.2.10:51000".parse().unwrap()
    }

    fn token() -> Vec<u8> {
        mint_token(&KEY, &ODCID, client(), &RSCID, 2_000_000_000)
    }

    #[test]
    fn rfc9001_a4_retry_packet() {
        let path = format!(
            "{}/tests/fixtures/rfc9001_a4_retry.hex",
            env!("CARGO_MANIFEST_DIR")
        );
        let want = hex::decode(
            std::fs::read_to_string(path)
                .unwrap()
                .split_whitespace()
                .collect::<String>(),
        )
        .unwrap();
        assert_eq!(build_retry(&[], &RSCID, &ODCID, b"token"), want);
    }

    #[test]
    fn token_known_answer() {
        // Expected bytes were computed independently with Python's hmac/hashlib.
        assert_eq!(
            hex::encode(token()),
            "088394c8f03e51570800000000773594008fc3943538d3f2736f399447bed2acdd"
        );
    }

    #[test]
    fn validate_ok() {
        assert_eq!(
            validate_token(&KEY, &token(), client(), &RSCID, 1_999_999_999).unwrap(),
            ODCID.to_vec()
        );
    }

    #[test]
    fn wrong_ip_port_or_dcid_is_auth() {
        let t = token();
        let other_ip: SocketAddr = "192.0.2.11:51000".parse().unwrap();
        let other_port: SocketAddr = "192.0.2.10:51001".parse().unwrap();
        assert_eq!(
            validate_token(&KEY, &t, other_ip, &RSCID, 0),
            Err(RetryError::Auth)
        );
        assert_eq!(
            validate_token(&KEY, &t, other_port, &RSCID, 0),
            Err(RetryError::Auth)
        );
        assert_eq!(
            validate_token(&KEY, &t, client(), &ODCID, 0),
            Err(RetryError::Auth)
        );
    }

    #[test]
    fn expired_and_malformed() {
        let t = token();
        assert_eq!(
            validate_token(&KEY, &t, client(), &RSCID, 2_000_000_001),
            Err(RetryError::Expired)
        );
        let mut new_token_type = t.clone();
        new_token_type[0] |= 0x80;
        assert_eq!(
            validate_token(&KEY, &new_token_type, client(), &RSCID, 0),
            Err(RetryError::Type)
        );
        let mut short_odcid = t.clone();
        short_odcid[0] = 7;
        assert_eq!(
            validate_token(&KEY, &short_odcid, client(), &RSCID, 0),
            Err(RetryError::Odcil)
        );
        assert_eq!(
            validate_token(&KEY, &t[..5], client(), &RSCID, 0),
            Err(RetryError::Length)
        );
    }

    /// Writes the cross-language vector consumed by the C++ server tests.
    #[test]
    #[ignore]
    fn write_retry_vector() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/retry_token.json");
        let json = format!(
            "{{\"token_hex\": \"{}\", \"odcid_hex\": \"{}\"}}\n",
            hex::encode(token()),
            hex::encode(ODCID)
        );
        std::fs::write(path, json).unwrap();
    }
}
