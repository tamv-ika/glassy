//! CLI for the SP0 gateway prototype: `relay` runs the gateway, `mint` prints a ConnectInfo.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand, ValueEnum};
use gw_proto::connect_info::{MintParams, mint};
use gw_proto::relay::{RelayConfig, RetryMode, load_backends, spawn};
use gw_proto::ticket::{KeyRing, transports};

#[derive(Parser)]
#[command(about = "SP0 gateway prototype (throwaway)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum RetryArg {
    Always,
    Never,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the relay until killed; prints `READY <addr>` once listening.
    Relay {
        #[arg(long)]
        listen: SocketAddr,
        #[arg(long)]
        k_gw: String,
        #[arg(long)]
        key_id: u8,
        #[arg(long)]
        backends: PathBuf,
        #[arg(long, value_enum)]
        retry: RetryArg,
        #[arg(long)]
        retry_key: String,
        #[arg(long)]
        sni_suffix: String,
    },
    /// Mint a ticket and print the ConnectInfo JSON on stdout.
    Mint {
        #[arg(long)]
        k_gw: String,
        #[arg(long)]
        key_id: u8,
        #[arg(long)]
        k_gs: String,
        #[arg(long)]
        server_id: String,
        /// Comma-separated subset of native,webrtc,webtransport.
        #[arg(long)]
        transports: String,
        #[arg(long)]
        expiry_secs: u32,
        #[arg(long)]
        gateway: SocketAddr,
        #[arg(long)]
        sni_suffix: String,
        #[arg(long)]
        dtls_fp: String,
        #[arg(long)]
        cert_sha256: String,
    },
}

fn hex_array<const N: usize>(name: &str, s: &str) -> anyhow::Result<[u8; N]> {
    hex::decode(s)
        .with_context(|| format!("--{name} is not hex"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("--{name} must be {N} bytes"))
}

fn parse_transports(s: &str) -> anyhow::Result<u8> {
    s.split(',').try_fold(0u8, |acc, t| {
        Ok(acc
            | match t.trim() {
                "native" => transports::NATIVE,
                "webrtc" => transports::WEBRTC,
                "webtransport" => transports::WEBTRANSPORT,
                other => bail!("unknown transport {other}"),
            })
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Relay {
            listen,
            k_gw,
            key_id,
            backends,
            retry,
            retry_key,
            sni_suffix,
        } => {
            let handle = spawn(RelayConfig {
                listen,
                ring: KeyRing::new(key_id, hex_array("k-gw", &k_gw)?),
                backends: load_backends(&backends)?,
                retry: match retry {
                    RetryArg::Always => RetryMode::Always,
                    RetryArg::Never => RetryMode::Never,
                },
                retry_key: hex_array("retry-key", &retry_key)?,
                sni_suffix,
                unconfirmed_timeout: Duration::from_secs(5),
                confirmed_timeout: Duration::from_secs(60),
                hello_timeout: Duration::from_millis(100),
            })
            .await?;
            println!("READY {}", handle.local_addr);
            tokio::signal::ctrl_c().await?;
        }
        Cmd::Mint {
            k_gw,
            key_id,
            k_gs,
            server_id,
            transports,
            expiry_secs,
            gateway,
            sni_suffix,
            dtls_fp,
            cert_sha256,
        } => {
            let info = mint(
                &MintParams {
                    k_gw: hex_array("k-gw", &k_gw)?,
                    key_id,
                    k_gs: hex_array("k-gs", &k_gs)?,
                    server_id: hex_array("server-id", &server_id)?,
                    transports: parse_transports(&transports)?,
                    expiry_secs,
                    gateway,
                    sni_suffix,
                    dtls_fp,
                    cert_sha256,
                },
                gw_proto::relay::unix_now(),
            );
            println!("{}", serde_json::to_string(&info)?);
        }
    }
    Ok(())
}
