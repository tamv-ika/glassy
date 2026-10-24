//! ICE password derivation shared by the broker and the game server (spec §3.5).
//!
//! `pwd = base64_std_nopad(HMAC-SHA256(K_ice, ufrag))` with `K_ice = HKDF-SHA256(K_gs, "glassy-ice")`
//! lets the game server answer STUN checks for a ufrag it has never seen before.

use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;

use crate::crypto::{hmac_sha256, k_ice};

/// Derives the server-side ICE password (43 characters) for `ufrag` from the fleet key `k_gs`.
pub fn ice_pwd(k_gs: &[u8; 32], ufrag: &str) -> String {
    STANDARD_NO_PAD.encode(hmac_sha256(&k_ice(k_gs), &[ufrag.as_bytes()]))
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
        assert_eq!(ice_pwd(&[0x22; 32], "evtj").len(), 43);
    }
}
