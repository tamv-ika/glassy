//! Protocol constants for `ver` = 1. The C++ lib exports the same names.

/// Maximum native datagram payload size in bytes.
pub const MAX_DATAGRAM: usize = 1100;
/// Maximum size of one reassembled message in bytes.
pub const MAX_MESSAGE: usize = 262_144;
/// Receive window in bytes.
pub const RECV_WINDOW: usize = 524_288;
/// Maximum number of gaps tracked per stream.
pub const MAX_STREAM_GAPS: usize = 32;
/// Size of the anti-replay window.
pub const REPLAY_WINDOW: usize = 256;
/// Maximum size of the connect-info JSON in bytes.
pub const MAX_CONNECT_INFO_JSON: usize = 4096;
