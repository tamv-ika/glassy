//! AEAD and key-derivation helpers (XChaCha20-Poly1305, HKDF-SHA256, HMAC-SHA256).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::Error;

const TAG_LEN: usize = 16;

/// Seals `plaintext`; returns `ciphertext | tag16`.
pub fn xchacha_seal(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        // Encryption only fails when the message exceeds the AEAD length limit
        // (~256 GiB), which a bounded datagram or message can never reach.
        .expect("XChaCha20-Poly1305 encrypt cannot fail for bounded input")
}

/// Opens `ciphertext | tag16`. Shorter than a tag is `Truncated`; a bad tag is `AuthFailed`.
pub fn xchacha_open(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>, Error> {
    if sealed.len() < TAG_LEN {
        return Err(Error::Truncated);
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(&XNonce::from(*nonce), Payload { msg: sealed, aad })
        .map_err(|_| Error::AuthFailed)
}

/// Packet nonce: `server_nonce (16) | pn (u64 big-endian)`.
pub fn packet_nonce(server_nonce: &[u8; 16], pn: u64) -> [u8; 24] {
    let mut out = [0u8; 24];
    out[..16].copy_from_slice(server_nonce);
    out[16..].copy_from_slice(&pn.to_be_bytes());
    out
}

fn derive(k_gs: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, k_gs);
    let mut out = [0u8; 32];
    // expand fails only when the output exceeds 255 * HashLen; 32 bytes is fine.
    hk.expand(info, &mut out)
        .expect("32-byte HKDF-SHA256 output is within the length limit");
    out
}

/// Server-ticket key: HKDF-SHA256(salt empty, ikm `K_gs`, info `"glassy-server-ticket"`).
pub fn k_ticket(k_gs: &[u8; 32]) -> [u8; 32] {
    derive(k_gs, b"glassy-server-ticket")
}

/// ICE key: HKDF-SHA256(salt empty, ikm `K_gs`, info `"glassy-ice"`).
pub fn k_ice(k_gs: &[u8; 32]) -> [u8; 32] {
    derive(k_gs, b"glassy-ice")
}

/// HMAC-SHA256 over the concatenation of `msg` parts.
pub fn hmac_sha256(key: &[u8], msg: &[&[u8]]) -> [u8; 32] {
    // HMAC accepts keys of any length.
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    for part in msg {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}
