//! QUIC Retry token (spec §3.6): the gateway's full validation and the game server's
//! parse-only read must agree on the ODCID. Input: one raw token.
#![no_main]

use std::net::SocketAddr;

use glassy_proto::{retry_token_odcid, validate_retry_token};
use libfuzzer_sys::fuzz_target;

/// Key, client and clock of the vectors, so seeds built from them get past the tag check.
const K_RETRY_GW: [u8; 32] = [0x33; 32];
const DCID: [u8; 8] = [0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5];
const NOW: u64 = 1_900_000_000;

fuzz_target!(|data: &[u8]| {
    let parsed = retry_token_odcid(data);
    if let Ok(odcid) = parsed {
        // byte0 | ODCID | expiry (8) | tag (16), ODCIL 8..=20 (RFC 9000 §7.2).
        assert!((8..=20).contains(&odcid.len()));
        assert_eq!(1 + odcid.len() + 8 + 16, data.len());
    }
    for client in ["203.0.113.7:4433", "[2001:db8::7]:4433"] {
        let client: SocketAddr = client.parse().expect("constant address");
        if let Ok(odcid) = validate_retry_token(&K_RETRY_GW, data, client, &DCID, NOW) {
            assert_eq!(Ok(odcid), parsed);
        }
    }
});
