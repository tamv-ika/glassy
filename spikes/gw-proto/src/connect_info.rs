//! ConnectInfo JSON handed to browser test pages, mimicking what the broker returns (spec §5.3).

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::ice::ice_pwd;
use crate::ticket::{KeyRing, RoutingTicket, seal, to_sni_labels, to_ufrag};

#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectInfo {
    pub session_id: String,
    pub webrtc: WebRtcInfo,
    pub webtransport: WebTransportInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WebRtcInfo {
    pub ufrag: String,
    pub pwd: String,
    pub ip: String,
    pub port: u16,
    pub dtls_fp: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WebTransportInfo {
    pub host: String,
    pub port: u16,
    pub path: String,
    pub cert_sha256: String,
}

pub struct MintParams {
    pub k_gw: [u8; 16],
    pub key_id: u8,
    pub k_gs: [u8; 32],
    pub server_id: [u8; 16],
    pub transports: u8,
    pub expiry_secs: u32,
    pub gateway: SocketAddr,
    pub sni_suffix: String,
    pub dtls_fp: String,
    pub cert_sha256: String,
}

/// Mints one player's ticket and renders it in every encoding the browser transports need.
pub fn mint(p: &MintParams, now: u32) -> ConnectInfo {
    let session_id: [u8; 8] = rand::random();
    let nonce: [u8; 12] = rand::random();
    let ticket = RoutingTicket {
        server_id: p.server_id,
        session_id,
        expiry: now.saturating_add(p.expiry_secs),
        transports: p.transports,
        flags: 0,
    };
    let sealed = seal(&ticket, &KeyRing::new(p.key_id, p.k_gw), nonce);
    let ufrag = to_ufrag(&sealed);
    ConnectInfo {
        session_id: hex::encode(session_id),
        webrtc: WebRtcInfo {
            pwd: ice_pwd(&p.k_gs, &ufrag),
            ufrag,
            ip: p.gateway.ip().to_string(),
            port: p.gateway.port(),
            dtls_fp: p.dtls_fp.clone(),
        },
        webtransport: WebTransportInfo {
            host: format!("{}.{}", to_sni_labels(&sealed), p.sni_suffix),
            port: p.gateway.port(),
            path: "/glassy".into(),
            cert_sha256: p.cert_sha256.clone(),
        },
    }
}
