//! CONNECT as the gateway and the game server see it (spec §4.2), with and without the
//! gateway's client_addr trailer. Input: one raw datagram.
#![no_main]

use glassy_proto::{
    CONNECT_MIN, MAX_PACKET, ServerKeyRing, parse_connect, split_trailer, verify_connect,
};
use libfuzzer_sys::fuzz_target;

/// Key and identity of the vectors, so seeds built from them get past the AEAD checks.
const K_GS: [u8; 32] = [0x22; 32];
const SERVER_ID: [u8; 16] = [0xab; 16];
const NOW: u32 = 1_900_000_000;

fn check(packet: &[u8], ring: &ServerKeyRing) {
    if let Ok(v) = parse_connect(packet) {
        assert!((CONNECT_MIN..=MAX_PACKET).contains(&packet.len()));
        // 96-byte header | server ticket | 16-byte proof | padding covers the whole packet.
        assert_eq!(
            96 + v.server_ticket.len() + 16 + v.padding.len(),
            packet.len()
        );
        assert_eq!(&packet[2..10], v.session_id);
    }
    if let Ok(vc) = verify_connect(packet, ring, &SERVER_ID, NOW) {
        let v = parse_connect(packet).expect("verified CONNECT must parse");
        assert_eq!(vc.session_id, v.session_id);
        assert_eq!(vc.ticket.session_id, v.session_id);
        assert!(v.padding.iter().all(|&b| b == 0));
    }
}

fuzz_target!(|data: &[u8]| {
    let ring = ServerKeyRing::new(1, K_GS);
    check(data, &ring);
    if let Ok((body, _addr)) = split_trailer(data) {
        assert_eq!(body.len() + 8, data.len());
        check(body, &ring);
    }
});
