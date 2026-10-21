//! Relay behaviour for WebTransport first packets: Retry offload, ClientHello buffering and
//! routing by the ticket carried in the SNI.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use gw_proto::quic::client_hello::build_client_hello;
use gw_proto::quic::crypto_frames::crypto_frame;
use gw_proto::quic::initial::protect_client_initial;
use gw_proto::quic::retry::validate_token;
use gw_proto::relay::{Backend, Backends, RelayConfig, RelayHandle, RetryMode, spawn, unix_now};
use gw_proto::ticket::{KeyRing, RoutingTicket, seal, to_sni_labels, transports};
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

const SERVER_A2: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xa2];
const RETRY_KEY: [u8; 32] = [0x33; 32];
const CLIENT_DCID: [u8; 8] = [1; 8];
const CLIENT_SCID: [u8; 8] = [2; 8];

type Received = Arc<Mutex<Vec<Vec<u8>>>>;

#[derive(Clone, Copy)]
enum Part {
    Whole,
    First,
    Second,
}

/// UDP echo backend that records every datagram it receives.
async fn echo_backend() -> (SocketAddr, Received) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let seen: Received = Arc::default();
    let log = seen.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            log.lock().unwrap().push(buf[..n].to_vec());
            let _ = sock.send_to(&buf[..n], from).await;
        }
    });
    (addr, seen)
}

async fn start_relay(backend: SocketAddr, retry: RetryMode) -> RelayHandle {
    let mut backends = Backends::new();
    backends.insert(
        SERVER_A2,
        Backend {
            webrtc: None,
            wt: Some(backend),
        },
    );
    spawn(RelayConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        ring: KeyRing::new(1, [0x11; 16]),
        backends,
        retry,
        retry_key: RETRY_KEY,
        sni_suffix: "wt.test".into(),
        unconfirmed_timeout: Duration::from_secs(5),
        confirmed_timeout: Duration::from_secs(60),
        hello_timeout: Duration::from_millis(100),
    })
    .await
    .unwrap()
}

fn ticket_host() -> String {
    let t = RoutingTicket {
        server_id: SERVER_A2,
        session_id: [9; 8],
        expiry: u32::MAX,
        transports: transports::WEBTRANSPORT,
        flags: 0,
    };
    format!(
        "{}.wt.test",
        to_sni_labels(&seal(&t, &KeyRing::new(1, [0x11; 16]), [4; 12]))
    )
}

fn client_initial(dcid: &[u8], token: &[u8], part: Part) -> Vec<u8> {
    let ch = build_client_hello(&ticket_host(), 1500);
    let half = ch.len() / 2;
    let payload = match part {
        Part::Whole => crypto_frame(0, &ch),
        Part::First => crypto_frame(0, &ch[..half]),
        Part::Second => crypto_frame(u64::try_from(half).unwrap(), &ch[half..]),
    };
    protect_client_initial(dcid, &CLIENT_SCID, token, 0, &payload)
}

async fn client(relay: &RelayHandle) -> UdpSocket {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.connect(relay.local_addr).await.unwrap();
    sock
}

/// Polls until the backend has seen `n` datagrams or the deadline passes.
async fn backend_sees(seen: &Received, n: usize) -> Vec<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(1);
    while seen.lock().unwrap().len() < n && Instant::now() < deadline {
        sleep(Duration::from_millis(10)).await;
    }
    seen.lock().unwrap().clone()
}

/// Splits a Retry packet into (retry SCID, token).
fn parse_retry(b: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let dcid_len = usize::from(b[5]);
    let scid_at = 6 + dcid_len + 1;
    let scid_len = usize::from(b[6 + dcid_len]);
    let token_at = scid_at + scid_len;
    (
        b[scid_at..token_at].to_vec(),
        b[token_at..b.len() - 16].to_vec(),
    )
}

async fn get_retry(c: &UdpSocket) -> (Vec<u8>, Vec<u8>) {
    c.send(&client_initial(&CLIENT_DCID, b"", Part::Whole))
        .await
        .unwrap();
    let mut buf = [0u8; 2048];
    let n = timeout(Duration::from_secs(1), c.recv(&mut buf))
        .await
        .expect("Retry")
        .unwrap();
    assert_eq!(buf[0] & 0xf0, 0xf0, "long header Retry packet");
    parse_retry(&buf[..n])
}

#[tokio::test]
async fn initial_without_token_gets_retry() {
    let (backend, seen) = echo_backend().await;
    let relay = start_relay(backend, RetryMode::Always).await;
    let c = client(&relay).await;
    let (rscid, token) = get_retry(&c).await;
    let me = c.local_addr().unwrap();
    assert_eq!(
        validate_token(&RETRY_KEY, &token, me, &rscid, u64::from(unix_now())),
        Ok(CLIENT_DCID.to_vec())
    );
    assert_eq!(relay.stats().retries_sent, 1);
    assert!(backend_sees(&seen, 1).await.is_empty());
}

#[tokio::test]
async fn retry_then_token_routes_with_token_intact() {
    let (backend, seen) = echo_backend().await;
    let relay = start_relay(backend, RetryMode::Always).await;
    let c = client(&relay).await;
    let (rscid, token) = get_retry(&c).await;
    let second = client_initial(&rscid, &token, Part::Whole);
    c.send(&second).await.unwrap();
    assert_eq!(backend_sees(&seen, 1).await, vec![second]);
    assert_eq!(relay.stats().flows, 1);
}

#[tokio::test]
async fn initial_with_sni_ticket_routes() {
    let (backend, seen) = echo_backend().await;
    let relay = start_relay(backend, RetryMode::Never).await;
    let c = client(&relay).await;
    let pkt = client_initial(&CLIENT_DCID, b"", Part::Whole);
    c.send(&pkt).await.unwrap();
    assert_eq!(backend_sees(&seen, 1).await, vec![pkt]);
}

#[tokio::test]
async fn split_client_hello_two_packets_out_of_order_routes() {
    let (backend, seen) = echo_backend().await;
    let relay = start_relay(backend, RetryMode::Never).await;
    let c = client(&relay).await;
    let first = client_initial(&CLIENT_DCID, b"", Part::First);
    let second = client_initial(&CLIENT_DCID, b"", Part::Second);
    c.send(&second).await.unwrap();
    c.send(&first).await.unwrap();
    assert_eq!(backend_sees(&seen, 2).await, vec![second, first]);
}

#[tokio::test]
async fn incomplete_hello_times_out_and_clears() {
    let (backend, seen) = echo_backend().await;
    let relay = start_relay(backend, RetryMode::Never).await;
    let c = client(&relay).await;
    c.send(&client_initial(&CLIENT_DCID, b"", Part::Second))
        .await
        .unwrap();
    sleep(Duration::from_millis(150)).await;
    let stats = relay.stats();
    assert_eq!((stats.hello_timeouts, stats.flows), (1, 0));
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn duplicate_initial_same_tuple_single_flow() {
    let (backend, seen) = echo_backend().await;
    let relay = start_relay(backend, RetryMode::Never).await;
    let c = client(&relay).await;
    let pkt = client_initial(&CLIENT_DCID, b"", Part::Whole);
    c.send(&pkt).await.unwrap();
    c.send(&pkt).await.unwrap();
    assert_eq!(backend_sees(&seen, 2).await.len(), 2);
    assert_eq!(relay.stats().flows, 1);
}
