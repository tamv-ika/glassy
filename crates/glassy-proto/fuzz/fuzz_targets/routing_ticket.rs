//! Routing ticket (spec §3.1) in its three gateway encodings: raw bytes in CONNECT, the ICE
//! ufrag and the WebTransport SNI labels. Input: raw bytes, also read as text.
#![no_main]

use glassy_proto::{
    RoutingKeyRing, from_sni, from_ufrag, open_routing, to_sni_labels, to_ufrag, transport,
};
use libfuzzer_sys::fuzz_target;

/// Key, clock and SNI suffix of the vectors, so seeds built from them get past the AEAD check.
const K_GW: [u8; 16] = [0x11; 16];
const NOW: u32 = 1_900_000_000;
const SESSION_ID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const SNI_SUFFIX: &str = "wt.example.test";

fn open_all(ticket: &[u8], ring: &RoutingKeyRing) {
    for via in [
        transport::NATIVE,
        transport::WEBRTC,
        transport::WEBTRANSPORT,
    ] {
        for session in [None, Some(&SESSION_ID)] {
            if let Ok(t) = open_routing(ticket, ring, NOW, via, session) {
                assert!(t.expiry >= NOW);
                assert_ne!(t.transports & via, 0);
                if let Some(s) = session {
                    assert_eq!(&t.session_id, s);
                }
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let ring = RoutingKeyRing::new(1, K_GW);
    open_all(data, &ring);
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // Both text forms are canonical: decoding then encoding gives the input back.
    if let Ok(t) = from_ufrag(text) {
        assert_eq!(to_ufrag(&t), text);
        open_all(&t, &ring);
    }
    if let Ok(t) = from_sni(text, SNI_SUFFIX) {
        let host = format!("{}.{SNI_SUFFIX}", to_sni_labels(&t));
        assert!(host.eq_ignore_ascii_case(text));
        open_all(&t, &ring);
    }
});
