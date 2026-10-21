//! Relay behaviour for WebRTC first packets: STUN binding requests routed by the ufrag ticket.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use gw_proto::relay::{Backend, Backends, RelayConfig, RelayHandle, RetryMode, spawn};
use gw_proto::stun::build_binding_request;
use gw_proto::ticket::{KeyRing, RoutingTicket, seal, to_ufrag, transports};
use tokio::net::UdpSocket;
use tokio::time::timeout;

const SERVER_A1: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xa1];
const DTLS_LIKE: [u8; 6] = [0x16, 0xfe, 0xfd, 1, 2, 3];

/// UDP echo backend that also counts every datagram it receives.
async fn echo_backend() -> (SocketAddr, Arc<AtomicUsize>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = seen.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            counter.fetch_add(1, Ordering::SeqCst);
            let _ = sock.send_to(&buf[..n], from).await;
        }
    });
    (addr, seen)
}

async fn start_relay(backend: SocketAddr) -> RelayHandle {
    let mut backends = Backends::new();
    backends.insert(
        SERVER_A1,
        Backend {
            webrtc: Some(backend),
            wt: None,
        },
    );
    spawn(RelayConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        ring: KeyRing::new(1, [0x11; 16]),
        backends,
        retry: RetryMode::Never,
        retry_key: [0x33; 32],
        sni_suffix: "wt.test".into(),
        unconfirmed_timeout: Duration::from_secs(5),
        confirmed_timeout: Duration::from_secs(60),
        hello_timeout: Duration::from_millis(100),
    })
    .await
    .unwrap()
}

fn ticket_ufrag(expiry: u32) -> String {
    let t = RoutingTicket {
        server_id: SERVER_A1,
        session_id: [7; 8],
        expiry,
        transports: transports::WEBRTC,
        flags: 0,
    };
    to_ufrag(&seal(&t, &KeyRing::new(1, [0x11; 16]), [5; 12]))
}

async fn client(relay: &RelayHandle) -> UdpSocket {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.connect(relay.local_addr).await.unwrap();
    sock
}

async fn recv_within(sock: &UdpSocket, ms: u64) -> Option<Vec<u8>> {
    let mut buf = [0u8; 2048];
    match timeout(Duration::from_millis(ms), sock.recv(&mut buf)).await {
        Ok(Ok(n)) => Some(buf[..n].to_vec()),
        _ => None,
    }
}

#[tokio::test]
async fn stun_with_valid_ticket_routes_to_backend_and_back() {
    let (backend, _) = echo_backend().await;
    let relay = start_relay(backend).await;
    let c = client(&relay).await;
    let stun = build_binding_request(&format!("{}:cli1", ticket_ufrag(u32::MAX)), [1; 12]);
    c.send(&stun).await.unwrap();
    assert_eq!(recv_within(&c, 1000).await, Some(stun));
    assert_eq!(relay.stats().flows, 1);
    assert_eq!(relay.stats().confirmed, 1);
}

#[tokio::test]
async fn followup_packet_same_tuple_forwarded() {
    let (backend, _) = echo_backend().await;
    let relay = start_relay(backend).await;
    let c = client(&relay).await;
    c.send(&build_binding_request(
        &format!("{}:cli1", ticket_ufrag(u32::MAX)),
        [1; 12],
    ))
    .await
    .unwrap();
    recv_within(&c, 1000).await.expect("STUN echo");
    c.send(&DTLS_LIKE).await.unwrap();
    assert_eq!(recv_within(&c, 1000).await, Some(DTLS_LIKE.to_vec()));
}

#[tokio::test]
async fn unknown_tuple_non_first_packet_dropped() {
    let (backend, seen) = echo_backend().await;
    let relay = start_relay(backend).await;
    let stranger = client(&relay).await;
    stranger.send(&DTLS_LIKE).await.unwrap();
    assert_eq!(recv_within(&stranger, 200).await, None);
    assert_eq!(relay.stats().dropped_unknown_flow, 1);
    assert_eq!(seen.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn expired_ticket_dropped_silently() {
    let (backend, seen) = echo_backend().await;
    let relay = start_relay(backend).await;
    let c = client(&relay).await;
    c.send(&build_binding_request(
        &format!("{}:cli1", ticket_ufrag(1)),
        [1; 12],
    ))
    .await
    .unwrap();
    assert_eq!(recv_within(&c, 200).await, None);
    assert_eq!(seen.load(Ordering::SeqCst), 0);
    assert_eq!(relay.stats().dropped_bad_ticket, 1);
    assert_eq!(relay.stats().flows, 0);
}

#[tokio::test]
async fn duplicate_stun_same_tuple_single_flow() {
    let (backend, _) = echo_backend().await;
    let relay = start_relay(backend).await;
    let c = client(&relay).await;
    let stun = build_binding_request(&format!("{}:cli1", ticket_ufrag(u32::MAX)), [1; 12]);
    c.send(&stun).await.unwrap();
    c.send(&stun).await.unwrap();
    assert_eq!(recv_within(&c, 1000).await, Some(stun.clone()));
    assert_eq!(recv_within(&c, 1000).await, Some(stun));
    assert_eq!(relay.stats().flows, 1);
}
