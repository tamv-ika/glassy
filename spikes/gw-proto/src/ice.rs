//! ICE password derivation shared by the broker and the game server (spec §3.5).
//!
//! `pwd = base64_std_nopad(HMAC-SHA256(HKDF-SHA256(ikm = K_gs, salt = none, info = "glassy-ice"), ufrag))`
//! lets the game server answer STUN checks for a ufrag it has never seen before.

use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

const ICE_INFO: &[u8] = b"glassy-ice";

/// Derives the server-side ICE password for `ufrag` from the fleet key `k_gs`.
pub fn ice_pwd(k_gs: &[u8; 32], ufrag: &str) -> String {
    let mut ice_key = [0u8; 32];
    Hkdf::<Sha256>::new(None, k_gs)
        .expand(ICE_INFO, &mut ice_key)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    let mut mac = Hmac::<Sha256>::new_from_slice(&ice_key).expect("HMAC accepts any key length");
    mac.update(ufrag.as_bytes());
    STANDARD_NO_PAD.encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ice_pwd_known_answer() {
        // Expected values were computed independently with Python's hmac/hashlib.
        assert_eq!(
            ice_pwd(&[0x22; 32], "evtj"),
            "80zK66GjJqCxXOeI6qiO7Tyrn/sory+Ra/31l+h0e60"
        );
        assert_eq!(
            ice_pwd(&[0x22; 32], "evtk"),
            "A1/6J7XGHgokNUcZqm7BhqrgquS1iyt13K4ph1Ian4o"
        );
    }

    /// Writes the cross-language vector consumed by the C++ server tests.
    #[test]
    #[ignore]
    fn write_ice_vector() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/ice_pwd.json");
        let ufrag = "evtj";
        let json = format!(
            "{{\"k_gs_hex\": \"{}\", \"ufrag\": \"{ufrag}\", \"pwd\": \"{}\"}}\n",
            "22".repeat(32),
            ice_pwd(&[0x22; 32], ufrag)
        );
        std::fs::create_dir_all(std::path::Path::new(path).parent().unwrap()).unwrap();
        std::fs::write(path, json).unwrap();
    }
}
