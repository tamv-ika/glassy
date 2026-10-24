//! Byte-level wire format for glassy (SP1). Mirrored byte for byte by the C++ lib.
//!
//! Spec: `docs/superpowers/specs/2026-10-23-sp1-glassy-proto-design.md`.
//!
//! # Example
//!
//! A native handshake and one datagram, end to end (spec §3, §4, §5):
//!
//! ```
//! use glassy_proto::{
//!     Accept, Frame, RoutingKeyRing, RoutingTicket, ServerKeyRing, ServerTicket, NativeKeys,
//!     build_accept, build_connect, decode_frames, encode_frame, open_accept, open_data,
//!     seal_data, seal_routing, seal_server, transport, verify_connect,
//! };
//!
//! let (key_c2s, key_s2c) = ([1u8; 32], [2u8; 32]);
//! let (session_id, conn_id, server_id) = ([3u8; 8], [4u8; 16], [5u8; 16]);
//! let now = 1_000;
//!
//! // Backend side: mint the tickets the client carries in CONNECT.
//! let routing_ring = RoutingKeyRing::new(1, [6u8; 16]);
//! let routing = seal_routing(
//!     &RoutingTicket { server_id, session_id, expiry: now + 60, transports: transport::NATIVE },
//!     &routing_ring,
//!     [7u8; 12],
//! );
//! let server_ring = ServerKeyRing::new(1, [8u8; 32]);
//! let ticket = seal_server(
//!     &ServerTicket {
//!         user_id: "alice".into(),
//!         server_id,
//!         session_id,
//!         expiry: now + 60,
//!         transport: transport::NATIVE,
//!         native_keys: Some(NativeKeys { c2s: key_c2s, s2c: key_s2c }),
//!         metadata: vec![],
//!     },
//!     &server_ring,
//!     [9u8; 24],
//! )
//! .unwrap();
//!
//! // Client -> server: CONNECT, padded to 1200 bytes.
//! let connect =
//!     build_connect(&session_id, &conn_id, 1, &routing, &ticket, &key_c2s, 1200).unwrap();
//! let verified = verify_connect(&connect, &server_ring, now, &server_id).unwrap();
//! assert_eq!(verified.session_id, session_id);
//!
//! // Server -> client: ACCEPT.
//! let accept = Accept {
//!     session_id,
//!     connect_seq: verified.connect_seq,
//!     server_nonce: [10u8; 16],
//!     resumed: false,
//!     server_time_ms: 42,
//! };
//! let bytes = build_accept(&accept, &conn_id, &key_s2c);
//! let accepted = open_accept(&bytes, &conn_id, &key_s2c).unwrap();
//! assert_eq!(accepted, accept);
//!
//! // Server -> client: DATA carrying one DATAGRAM frame.
//! let mut frames = Vec::new();
//! encode_frame(&Frame::Datagram(b"hello"), &mut frames).unwrap();
//! let packet = seal_data(&key_s2c, &accepted.server_nonce, &session_id, 1, &frames).unwrap();
//! let plain = open_data(&key_s2c, &accepted.server_nonce, &packet, 1).unwrap();
//! assert_eq!(decode_frames(&plain).unwrap(), vec![Frame::Datagram(b"hello")]);
//! ```

#![deny(missing_docs)]

pub mod connect_info;
pub mod consts;
pub mod crypto;
pub mod error;
pub mod frame;
pub mod ice;
pub mod message;
pub mod packet;
pub mod retry;
pub mod routing_ticket;
pub mod server_ticket;
pub mod varint;
pub mod wt;

// Flat re-exports: every item is also reachable at the crate root. `varint::{encode, decode,
// encoded_len, MAX}` are deliberately not flattened: their names are too generic and would
// read ambiguously next to the packet and frame encoders; use `glassy_proto::varint::...`.
pub use connect_info::{
    ConnectInfo, NativeInfo, WebRtcInfo, WtInfo, decode_connect_info, encode_connect_info,
};
pub use consts::*;
pub use crypto::{hmac_sha256, k_ice, k_ticket, packet_nonce, xchacha_open, xchacha_seal};
pub use error::Error;
pub use frame::{ACK_DELAY_UNKNOWN, AckFrame, Frame, ack_bit, decode_frames, encode_frame};
pub use ice::ice_pwd;
pub use message::{MessageHeader, decode_message_header, encode_message_header};
pub use packet::accept::reject_reason;
pub use packet::pn::{ReplayWindow, decode_pn};
pub use packet::{
    ACCEPT_LEN, Accept, CONNECT_MIN, ClientAddrV4, ConnectView, DATA_MIN, DISCONNECT_LEN, Header,
    MAX_FRAMES, MAX_PACKET, REJECT_LEN, Reject, TRAILER_V4_LEN, VerifiedConnect, append_trailer,
    build_accept, build_connect, build_reject, open_accept, open_data, open_disconnect,
    open_reject, packet_type, parse_connect, parse_header, peek_reply, seal_data, seal_disconnect,
    split_trailer, verify_connect,
};
pub use retry::{mint_retry_token, retry_token_odcid, validate_retry_token};
pub use routing_ticket::{
    ROUTING_TICKET_LEN, RoutingKeyRing, RoutingTicket, from_sni, from_ufrag, open_routing,
    seal_routing, to_sni_labels, to_ufrag,
};
pub use server_ticket::{
    NativeKeys, SERVER_TICKET_BROWSER_MAX, SERVER_TICKET_MAX, SERVER_TICKET_MIN,
    SERVER_TICKET_NATIVE_MIN, ServerKeyRing, ServerTicket, open_server, seal_server,
};
pub use wt::{WT_PATH_MAX, WT_PATH_PREFIX, WT_TICKET_B64_MAX, parse_wt_path, wt_path};

/// Transport bitmask shared by routing tickets (spec §3.1) and server tickets (§3.2).
pub mod transport {
    /// Native UDP transport (spec §4).
    pub const NATIVE: u8 = 1;
    /// WebRTC data-channel transport (spec §6.1).
    pub const WEBRTC: u8 = 2;
    /// WebTransport transport (spec §6.2).
    pub const WEBTRANSPORT: u8 = 4;
}
