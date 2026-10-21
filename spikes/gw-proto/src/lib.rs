//! Userspace gateway prototype for the SP0 spikes (S1, S2, S4).
//!
//! THROWAWAY: nothing outside `spikes/` may depend on this crate.

pub mod connect_info;
pub mod ice;
pub mod quic;
pub mod relay;
pub mod stun;
pub mod ticket;
