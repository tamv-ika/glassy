//! Byte-level wire format for glassy (SP1). Mirrored byte for byte by the C++ lib.

pub mod consts;
pub mod crypto;
pub mod error;
pub mod routing_ticket;
pub mod server_ticket;
pub mod varint;

pub use consts::*;
pub use error::Error;

/// Transport bitmask shared by routing tickets (spec §3.1) and server tickets (§3.2).
pub mod transport {
    pub const NATIVE: u8 = 1;
    pub const WEBRTC: u8 = 2;
    pub const WEBTRANSPORT: u8 = 4;
}
