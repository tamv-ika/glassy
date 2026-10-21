//! QUIC v1 Initial packet protection (RFC 9001 §5.2–§5.4).
//!
//! Initial keys derive from the client's Destination Connection ID and a public salt, so any
//! on-path observer — here the gateway — can read the ClientHello without the TLS keys.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::aes::Aes128;
use aes_gcm::aes::cipher::BlockCipherEncrypt;
use aes_gcm::{Aes128Gcm, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;

pub use super::QuicError;
use super::read_varint;

const QUIC_V1: u32 = 1;
/// RFC 9001 §5.2 initial salt for QUIC v1.
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const TAG_LEN: usize = 16;
const SAMPLE_LEN: usize = 16;
/// Clients must pad datagrams carrying Initial packets to at least 1200 bytes (RFC 9000 §14.1).
const MIN_INITIAL_DATAGRAM: usize = 1200;

#[derive(Debug)]
pub struct InitialHeader<'a> {
    pub version: u32,
    pub dcid: &'a [u8],
    pub scid: &'a [u8],
    pub token: &'a [u8],
    /// Offset of the (still protected) packet number.
    pub pn_offset: usize,
    /// Length of this packet within the datagram, which may hold coalesced packets.
    pub packet_len: usize,
}

pub struct InitialKeys {
    pub key: [u8; 16],
    pub iv: [u8; 12],
    pub hp: [u8; 16],
}

pub struct DecryptedInitial {
    pub packet_number: u64,
    pub payload: Vec<u8>,
    pub consumed: usize,
}

fn take<'a>(d: &'a [u8], at: &mut usize, n: usize) -> Result<&'a [u8], QuicError> {
    let s = d.get(*at..*at + n).ok_or(QuicError::Short)?;
    *at += n;
    Ok(s)
}

fn take_varint(d: &[u8], at: &mut usize) -> Result<u64, QuicError> {
    let (v, n) = read_varint(d.get(*at..).ok_or(QuicError::Short)?)?;
    *at += n;
    Ok(v)
}

/// Parses the long header of a v1 Initial packet without removing header protection.
pub fn parse_initial_header(d: &[u8]) -> Result<InitialHeader<'_>, QuicError> {
    let first = *d.first().ok_or(QuicError::Short)?;
    if first & 0x80 == 0 {
        return Err(QuicError::NotLong);
    }
    let mut at = 1;
    let version = u32::from_be_bytes(
        take(d, &mut at, 4)?
            .try_into()
            .map_err(|_| QuicError::Short)?,
    );
    if version != QUIC_V1 {
        return Err(QuicError::UnsupportedVersion);
    }
    // Long header packet type 0b00 is Initial in QUIC v1 (RFC 9000 §17.2.2).
    if first & 0x30 != 0 {
        return Err(QuicError::NotInitial);
    }
    let dcid_len = usize::from(take(d, &mut at, 1)?[0]);
    let dcid = take(d, &mut at, dcid_len)?;
    let scid_len = usize::from(take(d, &mut at, 1)?[0]);
    let scid = take(d, &mut at, scid_len)?;
    let token_len = usize::try_from(take_varint(d, &mut at)?).map_err(|_| QuicError::Malformed)?;
    let token = take(d, &mut at, token_len)?;
    let length = usize::try_from(take_varint(d, &mut at)?).map_err(|_| QuicError::Malformed)?;
    let packet_len = at.checked_add(length).ok_or(QuicError::Malformed)?;
    if packet_len > d.len() {
        return Err(QuicError::Short);
    }
    Ok(InitialHeader {
        version,
        dcid,
        scid,
        token,
        pn_offset: at,
        packet_len,
    })
}

fn expand_label(secret: &[u8], label: &str, out: &mut [u8]) {
    // HkdfLabel (RFC 8446 §7.1): length | "tls13 " + label | empty context.
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(4 + full.len());
    info.extend_from_slice(
        &u16::try_from(out.len())
            .expect("short output")
            .to_be_bytes(),
    );
    info.push(u8::try_from(full.len()).expect("short label"));
    info.extend_from_slice(full.as_bytes());
    info.push(0);
    Hkdf::<Sha256>::from_prk(secret)
        .expect("secret is a full SHA-256 PRK")
        .expand(&info, out)
        .expect("output length is within HKDF limits");
}

/// Derives the client Initial keys from the client-chosen Destination Connection ID.
pub fn client_initial_keys(dcid: &[u8]) -> InitialKeys {
    let (initial_secret, _) = Hkdf::<Sha256>::extract(Some(&INITIAL_SALT_V1), dcid);
    let mut client_secret = [0u8; 32];
    expand_label(&initial_secret, "client in", &mut client_secret);
    let mut keys = InitialKeys {
        key: [0; 16],
        iv: [0; 12],
        hp: [0; 16],
    };
    expand_label(&client_secret, "quic key", &mut keys.key);
    expand_label(&client_secret, "quic iv", &mut keys.iv);
    expand_label(&client_secret, "quic hp", &mut keys.hp);
    keys
}

fn header_mask(hp: &[u8; 16], sample: &[u8]) -> [u8; 16] {
    let mut block: [u8; 16] = sample.try_into().expect("sample is 16 bytes");
    let mut b = block.into();
    Aes128::new(&(*hp).into()).encrypt_block(&mut b);
    block.copy_from_slice(&b);
    block
}

fn nonce(iv: &[u8; 12], pn: u64) -> [u8; 12] {
    let mut n = *iv;
    for (i, b) in pn.to_be_bytes().iter().enumerate() {
        n[4 + i] ^= b;
    }
    n
}

/// Removes header protection and decrypts the first Initial packet in the datagram.
pub fn decrypt_initial(d: &[u8], keys: &InitialKeys) -> Result<DecryptedInitial, QuicError> {
    let h = parse_initial_header(d)?;
    let sample = d
        .get(h.pn_offset + 4..h.pn_offset + 4 + SAMPLE_LEN)
        .ok_or(QuicError::Short)?;
    let mask = header_mask(&keys.hp, sample);
    let first = d[0] ^ (mask[0] & 0x0f);
    let pn_len = usize::from(first & 0x03) + 1;
    let pn_end = h.pn_offset + pn_len;
    if pn_end + TAG_LEN > h.packet_len {
        return Err(QuicError::Malformed);
    }

    let mut header = d[..pn_end].to_vec();
    header[0] = first;
    let mut pn = 0u64;
    for i in 0..pn_len {
        header[h.pn_offset + i] ^= mask[1 + i];
        pn = (pn << 8) | u64::from(header[h.pn_offset + i]);
    }

    let payload = Aes128Gcm::new(&keys.key.into())
        .decrypt(
            &nonce(&keys.iv, pn).into(),
            Payload {
                msg: &d[pn_end..h.packet_len],
                aad: &header,
            },
        )
        .map_err(|_| QuicError::Decrypt)?;
    // The first Initial a client sends has no prior packet to expand a truncated number against.
    Ok(DecryptedInitial {
        packet_number: pn,
        payload,
        consumed: h.packet_len,
    })
}

fn push_varint(out: &mut Vec<u8>, v: u64) {
    match v {
        0..=0x3f => out.push(u8::try_from(v).expect("fits")),
        0x40..=0x3fff => {
            out.extend_from_slice(&(u16::try_from(v).expect("fits") | 0x4000).to_be_bytes())
        }
        _ => out.extend_from_slice(
            &(u32::try_from(v).expect("test packets are small") | 0x8000_0000).to_be_bytes(),
        ),
    }
}

/// Builds a protected client Initial padded to a 1200-byte datagram; used by tests.
pub fn protect_client_initial(
    dcid: &[u8],
    scid: &[u8],
    token: &[u8],
    pn: u32,
    payload: &[u8],
) -> Vec<u8> {
    const PN_LEN: usize = 4;
    let keys = client_initial_keys(dcid);
    let mut header = vec![0xc0 | u8::try_from(PN_LEN - 1).expect("fits")];
    header.extend_from_slice(&QUIC_V1.to_be_bytes());
    header.push(u8::try_from(dcid.len()).expect("cid <= 20"));
    header.extend_from_slice(dcid);
    header.push(u8::try_from(scid.len()).expect("cid <= 20"));
    header.extend_from_slice(scid);
    push_varint(&mut header, u64::try_from(token.len()).expect("fits"));
    header.extend_from_slice(token);

    // The Length field uses the 2-byte varint form; PADDING frames (0x00) fill the datagram.
    let fixed = header.len() + 2 + PN_LEN + TAG_LEN;
    let mut plain = payload.to_vec();
    plain.resize(
        plain.len().max(MIN_INITIAL_DATAGRAM.saturating_sub(fixed)),
        0,
    );
    let length = u16::try_from(PN_LEN + plain.len() + TAG_LEN).expect("fits a 2-byte varint");
    header.extend_from_slice(&(length | 0x4000).to_be_bytes());
    let pn_offset = header.len();
    header.extend_from_slice(&pn.to_be_bytes());

    let sealed = Aes128Gcm::new(&keys.key.into())
        .encrypt(
            &nonce(&keys.iv, u64::from(pn)).into(),
            Payload {
                msg: &plain,
                aad: &header,
            },
        )
        .expect("Initial payloads are within AES-GCM limits");
    let mut pkt = header;
    pkt.extend_from_slice(&sealed);

    let mask = header_mask(&keys.hp, &pkt[pn_offset + 4..pn_offset + 4 + SAMPLE_LEN]);
    pkt[0] ^= mask[0] & 0x0f;
    for i in 0..PN_LEN {
        pkt[pn_offset + i] ^= mask[1 + i];
    }
    pkt
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    fn fixture(name: &str) -> Vec<u8> {
        let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
        let text = std::fs::read_to_string(path).unwrap();
        hex::decode(text.split_whitespace().collect::<String>()).unwrap()
    }

    #[test]
    fn rfc9001_a1_client_keys() {
        let k = client_initial_keys(&hex!("8394c8f03e515708"));
        assert_eq!(k.key, hex!("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(k.iv, hex!("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(k.hp, hex!("9f50449e04a0e810283a1e9933adedd2"));
    }

    #[test]
    fn rfc9001_a2_decrypt() {
        // RFC 9001 Appendix A.2 protected client Initial (1200 bytes).
        let d = fixture("rfc9001_a2_client_initial.hex");
        let h = parse_initial_header(&d).unwrap();
        assert_eq!(h.dcid, &hex!("8394c8f03e515708")[..]);
        let p = decrypt_initial(&d, &client_initial_keys(h.dcid)).unwrap();
        assert_eq!(p.packet_number, 2);
        // CRYPTO frame at offset 0, length 0xf1, carrying a ClientHello (type 1).
        assert_eq!(&p.payload[..5], &[0x06, 0x00, 0x40, 0xf1, 0x01]);
    }

    #[test]
    fn coalesced_datagram_consumed_len() {
        let d = fixture("rfc9001_a2_client_initial.hex");
        let mut c = d.clone();
        c.extend_from_slice(&[0xe0; 50]);
        let keys = client_initial_keys(&hex!("8394c8f03e515708"));
        assert_eq!(decrypt_initial(&c, &keys).unwrap().consumed, d.len());
    }

    #[test]
    fn protect_then_decrypt_roundtrip() {
        let pkt = protect_client_initial(&[1; 8], &[2; 8], b"tok", 0, &[0x06, 0, 3, 1, 2, 3]);
        assert_eq!(pkt.len(), 1200);
        let p = decrypt_initial(&pkt, &client_initial_keys(&[1; 8])).unwrap();
        assert_eq!(&p.payload[..6], &[0x06, 0, 3, 1, 2, 3]);
        assert_eq!(parse_initial_header(&pkt).unwrap().token, b"tok");
    }

    #[test]
    fn handshake_packet_rejected() {
        let mut d = fixture("rfc9001_a2_client_initial.hex");
        // The long-header type bits (0x30) are not covered by header protection.
        d[0] = (d[0] & 0xcf) | 0x20;
        assert_eq!(parse_initial_header(&d).err(), Some(QuicError::NotInitial));
    }
}
