//! Byte-level wire format for glassy (SP1). Mirrored byte for byte by the C++ lib.

pub mod consts;
pub mod error;
pub mod varint;

pub use consts::*;
pub use error::Error;
