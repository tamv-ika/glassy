//! Native packet layer (spec §4). Packet number handling lives in [`pn`].

pub mod accept;
pub mod connect;
pub mod data;
pub mod pn;
pub mod trailer;

pub use accept::{
    ACCEPT_LEN, Accept, REJECT_LEN, Reject, build_accept, build_reject, open_accept, open_reject,
    peek_reply, reject_reason,
};
pub use connect::{ConnectView, VerifiedConnect, build_connect, parse_connect, verify_connect};
pub use data::{
    DATA_MIN, DISCONNECT_LEN, Header, MAX_FRAMES, open_data, open_disconnect, parse_header,
    seal_data, seal_disconnect,
};
pub use trailer::{ClientAddrV4, append_trailer, split_trailer};

/// First byte of every native packet (spec §4.1).
pub mod packet_type {
    pub const CONNECT: u8 = 0x80;
    pub const ACCEPT: u8 = 0x81;
    pub const DATA: u8 = 0x82;
    pub const DISCONNECT: u8 = 0x83;
    pub const REJECT: u8 = 0x84;
}

/// Smallest valid `CONNECT`: 96-byte header + 139-byte native ticket + 16-byte proof.
pub const CONNECT_MIN: usize = 251;
/// Largest native datagram, excluding the game-server-side trailer (spec §1).
pub const MAX_PACKET: usize = 1200;
/// `client_addr` trailer for IPv4: `ipv4(4) | port(2) | reserved(1) | family(1)`.
pub const TRAILER_V4_LEN: usize = 8;
