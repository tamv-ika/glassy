//! S1 spike server: WebTransport echo used to check that browsers accept a ticket hostname with
//! `serverCertificateHashes` even though the certificate's SAN does not match (spec §3.6).
//!
//! THROWAWAY: SP0 spike code.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, bail};
use wtransport::endpoint::IncomingSession;
use wtransport::{Endpoint, Identity, ServerConfig};

/// Upper bound on an echoed stream; spike messages are tiny.
const MAX_STREAM_BYTES: usize = 64 * 1024;

struct Args {
    port: u16,
    cert: String,
    key: String,
}

fn parse_args() -> anyhow::Result<Args> {
    let mut args = Args {
        port: 7102,
        cert: String::new(),
        key: String::new(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let value = it.next().with_context(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--port" => args.port = value.parse()?,
            "--cert" => args.cert = value,
            "--key" => args.key = value,
            other => bail!("unknown flag {other}"),
        }
    }
    if args.cert.is_empty() || args.key.is_empty() {
        bail!("usage: s1-wt-server --port N --cert PEM --key PEM");
    }
    Ok(args)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = parse_args()?;
    let identity = Identity::load_pemfiles(&args.cert, &args.key).await?;
    // IPv4 only: the spike containers have no IPv6, so a dual-stack bind would fail.
    let config = ServerConfig::builder()
        .with_bind_address(SocketAddr::from(([127, 0, 0, 1], args.port)))
        .with_identity(identity)
        .keep_alive_interval(Some(Duration::from_secs(3)))
        .build();
    let server = Endpoint::server(config)?;
    println!("READY {}", args.port);
    loop {
        let incoming = server.accept().await;
        tokio::spawn(async move {
            if let Err(e) = echo_session(incoming).await {
                eprintln!("session ended: {e:#}");
            }
        });
    }
}

async fn echo_session(incoming: IncomingSession) -> anyhow::Result<()> {
    let request = incoming.await?;
    eprintln!(
        "session request authority={} path={}",
        request.authority(),
        request.path()
    );
    let conn = request.accept().await?;
    loop {
        tokio::select! {
            stream = conn.accept_bi() => {
                let (mut send, mut recv) = stream?;
                tokio::spawn(async move {
                    let mut data = Vec::new();
                    let mut buf = [0u8; 4096];
                    while let Ok(Some(n)) = recv.read(&mut buf).await {
                        data.extend_from_slice(&buf[..n]);
                        if data.len() > MAX_STREAM_BYTES {
                            return;
                        }
                    }
                    let _ = send.write_all(&data).await;
                    let _ = send.finish().await;
                });
            }
            datagram = conn.receive_datagram() => {
                conn.send_datagram(datagram?.payload())?;
            }
        }
    }
}
