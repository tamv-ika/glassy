//! Userspace UDP relay: classify first packets, route them by ticket, then forward by 5-tuple.
//!
//! Each flow owns an upstream socket bound to an ephemeral port, which is the SNAT mapping
//! the spec describes for the gateway (§4.2). This is the Mode K shape without the XDP fast path.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use crate::quic::client_hello::{HelloParse, parse_sni};
use crate::quic::crypto_frames::CryptoAssembler;
use crate::quic::initial::{client_initial_keys, decrypt_initial, parse_initial_header};
use crate::quic::retry::{build_retry, mint_token, validate_token};
use crate::stun::server_ufrag;
use crate::ticket::{KeyRing, from_sni, from_ufrag, open};

/// Datagram buffer size; game traffic is never fragmented (spec §4.6).
const MAX_DATAGRAM: usize = 2048;
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);
/// A ClientHello may span at most this many Initial datagrams before the gateway gives up.
const MAX_HELLO_DATAGRAMS: usize = 2;
/// Upper bound on buffered CRYPTO bytes per pending handshake.
const MAX_HELLO_BYTES: usize = 8192;
/// Retry tokens only need to survive one client round trip.
const RETRY_TOKEN_LIFETIME_SECS: u64 = 10;

#[derive(Clone, Debug, Default)]
pub struct Backend {
    pub webrtc: Option<SocketAddr>,
    pub wt: Option<SocketAddr>,
}

/// Game servers keyed by `server_id`.
pub type Backends = HashMap<[u8; 16], Backend>;

/// Loads `{"<32 hex server_id>": {"webrtc": "ip:port", "wt": "ip:port"}}`.
pub fn load_backends(path: &Path) -> anyhow::Result<Backends> {
    #[derive(serde::Deserialize)]
    struct Entry {
        webrtc: Option<SocketAddr>,
        wt: Option<SocketAddr>,
    }
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let raw: HashMap<String, Entry> = serde_json::from_str(&text)?;
    raw.into_iter()
        .map(|(id, e)| {
            let bytes: [u8; 16] = hex::decode(&id)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("server_id {id} is not 16 bytes"))?;
            Ok((
                bytes,
                Backend {
                    webrtc: e.webrtc,
                    wt: e.wt,
                },
            ))
        })
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryMode {
    Always,
    Never,
}

pub struct RelayConfig {
    pub listen: SocketAddr,
    pub ring: KeyRing,
    pub backends: Backends,
    pub retry: RetryMode,
    pub retry_key: [u8; 32],
    pub sni_suffix: String,
    pub unconfirmed_timeout: Duration,
    pub confirmed_timeout: Duration,
    pub hello_timeout: Duration,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelayStats {
    pub flows: usize,
    pub confirmed: usize,
    pub dropped_unknown_flow: u64,
    pub dropped_bad_ticket: u64,
    pub retries_sent: u64,
    pub hello_timeouts: u64,
}

/// First-byte demultiplexing of packets that do not belong to a flow (spec §2.2).
#[derive(Debug, PartialEq, Eq)]
pub enum FirstPacket {
    Stun,
    QuicLong,
    Other,
}

pub fn classify(first_byte: u8) -> FirstPacket {
    match first_byte {
        0x00..=0x03 => FirstPacket::Stun,
        0xc0..=0xff => FirstPacket::QuicLong,
        _ => FirstPacket::Other,
    }
}

struct Flow {
    upstream: Arc<UdpSocket>,
    /// Milliseconds since `Shared::epoch` of the last packet in either direction.
    last_seen: Arc<AtomicU64>,
    /// Set once the backend has answered; unconfirmed flows expire sooner.
    confirmed: Arc<AtomicBool>,
    reader: JoinHandle<()>,
}

#[derive(Default)]
struct Counters {
    dropped_unknown_flow: AtomicU64,
    dropped_bad_ticket: AtomicU64,
    retries_sent: AtomicU64,
    hello_timeouts: AtomicU64,
}

/// Initial datagrams held until the ClientHello reveals the SNI ticket.
struct PendingHello {
    datagrams: Vec<Vec<u8>>,
    crypto: CryptoAssembler,
    started: Instant,
}

type HelloKey = (SocketAddr, Vec<u8>);

struct Shared {
    flows: Mutex<HashMap<SocketAddr, Flow>>,
    pending: Mutex<HashMap<HelloKey, PendingHello>>,
    counters: Counters,
    epoch: Instant,
}

impl Shared {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

pub struct RelayHandle {
    pub local_addr: SocketAddr,
    shared: Arc<Shared>,
}

impl RelayHandle {
    pub fn stats(&self) -> RelayStats {
        let flows = self.shared.flows.lock().expect("flow table lock");
        let c = &self.shared.counters;
        RelayStats {
            flows: flows.len(),
            confirmed: flows
                .values()
                .filter(|f| f.confirmed.load(Ordering::Relaxed))
                .count(),
            dropped_unknown_flow: c.dropped_unknown_flow.load(Ordering::Relaxed),
            dropped_bad_ticket: c.dropped_bad_ticket.load(Ordering::Relaxed),
            retries_sent: c.retries_sent.load(Ordering::Relaxed),
            hello_timeouts: c.hello_timeouts.load(Ordering::Relaxed),
        }
    }
}

/// Binds the listening socket and runs the relay on background tasks.
pub async fn spawn(cfg: RelayConfig) -> anyhow::Result<RelayHandle> {
    let sock = Arc::new(UdpSocket::bind(cfg.listen).await?);
    let local_addr = sock.local_addr()?;
    let shared = Arc::new(Shared {
        flows: Mutex::new(HashMap::new()),
        pending: Mutex::new(HashMap::new()),
        counters: Counters::default(),
        epoch: Instant::now(),
    });
    let cfg = Arc::new(cfg);
    tokio::spawn(sweep(shared.clone(), cfg.clone()));
    tokio::spawn(serve(sock, shared.clone(), cfg));
    Ok(RelayHandle { local_addr, shared })
}

async fn serve(sock: Arc<UdpSocket>, shared: Arc<Shared>, cfg: Arc<RelayConfig>) {
    let mut buf = [0u8; MAX_DATAGRAM];
    loop {
        let Ok((n, client)) = sock.recv_from(&mut buf).await else {
            continue;
        };
        if n == 0 {
            continue;
        }
        let pkt = &buf[..n];
        let existing = {
            let flows = shared.flows.lock().expect("flow table lock");
            flows.get(&client).map(|f| {
                f.last_seen.store(shared.now_ms(), Ordering::Relaxed);
                f.upstream.clone()
            })
        };
        if let Some(upstream) = existing {
            let _ = upstream.send(pkt).await;
            continue;
        }
        match classify(pkt[0]) {
            FirstPacket::Stun => match route_stun(pkt, &cfg) {
                Some(backend) => {
                    if let Ok(upstream) = open_flow(&sock, &shared, client, backend).await {
                        let _ = upstream.send(pkt).await;
                    }
                }
                None => {
                    shared
                        .counters
                        .dropped_bad_ticket
                        .fetch_add(1, Ordering::Relaxed);
                }
            },
            FirstPacket::QuicLong => handle_quic(pkt, client, &sock, &shared, &cfg).await,
            FirstPacket::Other => {
                shared
                    .counters
                    .dropped_unknown_flow
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

enum HelloStep {
    Wait,
    Route(String, Vec<Vec<u8>>),
    Fail,
}

/// Handles a long-header packet from an unknown 5-tuple: Retry offload, then ClientHello
/// buffering until the SNI ticket names a backend (spec §3.6).
async fn handle_quic(
    pkt: &[u8],
    client: SocketAddr,
    sock: &Arc<UdpSocket>,
    shared: &Arc<Shared>,
    cfg: &Arc<RelayConfig>,
) {
    let counters = &shared.counters;
    let Ok(hdr) = parse_initial_header(pkt) else {
        counters
            .dropped_unknown_flow
            .fetch_add(1, Ordering::Relaxed);
        return;
    };
    let now = u64::from(unix_now());
    if cfg.retry == RetryMode::Always {
        // No token, or a NEW_TOKEN token (first bit set) that only the server could validate.
        let has_retry_token = hdr.token.first().is_some_and(|b| b & 0x80 == 0);
        if !has_retry_token {
            let rscid: [u8; 8] = rand::random();
            let token = mint_token(
                &cfg.retry_key,
                hdr.dcid,
                client,
                &rscid,
                now + RETRY_TOKEN_LIFETIME_SECS,
            );
            let _ = sock
                .send_to(&build_retry(hdr.scid, &rscid, hdr.dcid, &token), client)
                .await;
            counters.retries_sent.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if validate_token(&cfg.retry_key, hdr.token, client, hdr.dcid, now).is_err() {
            counters.dropped_bad_ticket.fetch_add(1, Ordering::Relaxed);
            return;
        }
    }
    let Ok(initial) = decrypt_initial(pkt, &client_initial_keys(hdr.dcid)) else {
        counters.dropped_bad_ticket.fetch_add(1, Ordering::Relaxed);
        return;
    };

    let key: HelloKey = (client, hdr.dcid.to_vec());
    let (step, armed) = {
        let mut pending = shared.pending.lock().expect("pending lock");
        let armed = !pending.contains_key(&key);
        let hello = pending.entry(key.clone()).or_insert_with(|| PendingHello {
            datagrams: Vec::new(),
            crypto: CryptoAssembler::new(MAX_HELLO_BYTES),
            started: Instant::now(),
        });
        hello.datagrams.push(pkt.to_vec());
        let parsed = hello
            .crypto
            .ingest_payload(&initial.payload)
            .and_then(|()| parse_sni(hello.crypto.contiguous()));
        let wait = matches!(parsed, Ok(HelloParse::Incomplete))
            && hello.datagrams.len() < MAX_HELLO_DATAGRAMS;
        let started = hello.started;
        let step = match parsed {
            _ if wait => HelloStep::Wait,
            Ok(HelloParse::Sni(host)) => HelloStep::Route(
                host,
                pending
                    .remove(&key)
                    .map(|h| h.datagrams)
                    .unwrap_or_default(),
            ),
            _ => {
                pending.remove(&key);
                HelloStep::Fail
            }
        };
        (step, armed.then_some(started))
    };

    match step {
        HelloStep::Wait => {
            if let Some(started) = armed {
                arm_hello_timeout(shared.clone(), key, started, cfg.hello_timeout);
            }
        }
        HelloStep::Route(host, datagrams) => match route_sni(&host, cfg) {
            Some(backend) => {
                if let Ok(upstream) = open_flow(sock, shared, client, backend).await {
                    for d in datagrams {
                        let _ = upstream.send(&d).await;
                    }
                }
            }
            None => {
                counters.dropped_bad_ticket.fetch_add(1, Ordering::Relaxed);
            }
        },
        HelloStep::Fail => {
            counters.dropped_bad_ticket.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Drops a ClientHello that never completed, so half-open handshakes cannot pin memory.
fn arm_hello_timeout(shared: Arc<Shared>, key: HelloKey, started: Instant, after: Duration) {
    tokio::spawn(async move {
        tokio::time::sleep(after).await;
        let mut pending = shared.pending.lock().expect("pending lock");
        if pending.get(&key).is_some_and(|h| h.started == started) {
            pending.remove(&key);
            shared
                .counters
                .hello_timeouts
                .fetch_add(1, Ordering::Relaxed);
        }
    });
}

/// Resolves the WebTransport backend named by the ticket in the SNI.
fn route_sni(host: &str, cfg: &RelayConfig) -> Option<SocketAddr> {
    let ticket = open(
        &from_sni(host, &cfg.sni_suffix).ok()?,
        &cfg.ring,
        unix_now(),
    )
    .ok()?;
    cfg.backends.get(&ticket.server_id)?.wt
}

/// Resolves the WebRTC backend named by the ticket in the STUN USERNAME.
fn route_stun(pkt: &[u8], cfg: &RelayConfig) -> Option<SocketAddr> {
    let ufrag = server_ufrag(pkt).ok()?;
    let ticket = open(&from_ufrag(ufrag).ok()?, &cfg.ring, unix_now()).ok()?;
    cfg.backends.get(&ticket.server_id)?.webrtc
}

/// Creates the SNAT flow for `client` and starts relaying backend replies back to it.
async fn open_flow(
    sock: &Arc<UdpSocket>,
    shared: &Arc<Shared>,
    client: SocketAddr,
    backend: SocketAddr,
) -> anyhow::Result<Arc<UdpSocket>> {
    let bind: SocketAddr = if backend.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()?;
    let upstream = Arc::new(UdpSocket::bind(bind).await?);
    upstream.connect(backend).await?;

    let last_seen = Arc::new(AtomicU64::new(shared.now_ms()));
    let confirmed = Arc::new(AtomicBool::new(false));
    let reader = tokio::spawn(relay_replies(
        upstream.clone(),
        sock.clone(),
        client,
        shared.clone(),
        last_seen.clone(),
        confirmed.clone(),
    ));
    let flow = Flow {
        upstream: upstream.clone(),
        last_seen,
        confirmed,
        reader,
    };
    if let Some(old) = shared
        .flows
        .lock()
        .expect("flow table lock")
        .insert(client, flow)
    {
        old.reader.abort();
    }
    Ok(upstream)
}

async fn relay_replies(
    upstream: Arc<UdpSocket>,
    sock: Arc<UdpSocket>,
    client: SocketAddr,
    shared: Arc<Shared>,
    last_seen: Arc<AtomicU64>,
    confirmed: Arc<AtomicBool>,
) {
    let mut buf = [0u8; MAX_DATAGRAM];
    while let Ok(n) = upstream.recv(&mut buf).await {
        // Confirm before forwarding so observers that saw the reply also see the flag.
        confirmed.store(true, Ordering::Relaxed);
        last_seen.store(shared.now_ms(), Ordering::Relaxed);
        let _ = sock.send_to(&buf[..n], client).await;
    }
}

/// Expires idle flows: unconfirmed ones quickly, confirmed ones after the normal idle timeout.
async fn sweep(shared: Arc<Shared>, cfg: Arc<RelayConfig>) {
    let mut tick = tokio::time::interval(SWEEP_INTERVAL);
    loop {
        tick.tick().await;
        let now = shared.now_ms();
        let unconfirmed_ms = u64::try_from(cfg.unconfirmed_timeout.as_millis()).unwrap_or(u64::MAX);
        let confirmed_ms = u64::try_from(cfg.confirmed_timeout.as_millis()).unwrap_or(u64::MAX);
        shared
            .flows
            .lock()
            .expect("flow table lock")
            .retain(|_, f| {
                let limit = if f.confirmed.load(Ordering::Relaxed) {
                    confirmed_ms
                } else {
                    unconfirmed_ms
                };
                let alive = now.saturating_sub(f.last_seen.load(Ordering::Relaxed)) < limit;
                if !alive {
                    f.reader.abort();
                }
                alive
            });
    }
}

pub fn unix_now() -> u32 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    u32::try_from(secs).unwrap_or(u32::MAX)
}
