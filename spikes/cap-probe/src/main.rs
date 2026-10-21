//! S3 spike: probes a NIC's XDP and AF_XDP capabilities and prints them as one JSON object
//! (spec §8 capability detector, §11 S3). Must run as root: it attaches XDP programs.
//!
//! THROWAWAY: SP0 spike code.

mod afxdp;
mod sysinfo;
mod xdp;

use std::path::PathBuf;
use std::process::ExitCode;

use serde_json::{Value, json};

/// Outcome of one capability probe; `error` holds the OS or tool message on failure.
pub struct Probe {
    ok: bool,
    error: Option<String>,
}

impl Probe {
    fn ok() -> Self {
        Self {
            ok: true,
            error: None,
        }
    }

    fn failed(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(error.into()),
        }
    }

    fn to_json(&self) -> Value {
        json!({ "ok": self.ok, "error": self.error })
    }
}

struct Args {
    iface: String,
    bpf_dir: PathBuf,
}

fn parse_args() -> Result<Args, String> {
    let mut iface = None;
    let mut bpf_dir = None;
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--iface" => iface = Some(value),
            "--bpf-dir" => bpf_dir = Some(PathBuf::from(value)),
            other => return Err(format!("unknown flag {other}")),
        }
    }
    Ok(Args {
        iface: iface.ok_or("--iface is required")?,
        bpf_dir: bpf_dir.ok_or("--bpf-dir is required")?,
    })
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{e}\nusage: cap-probe --iface IF --bpf-dir DIR");
            return ExitCode::from(2);
        }
    };
    let iface = args.iface.as_str();
    let pass = args.bpf_dir.join("xdp_pass.o");
    let channels = sysinfo::channels(iface);
    let report = json!({
        "kernel": sysinfo::kernel_release(),
        "btf": sysinfo::has_btf(),
        "driver": sysinfo::driver(iface),
        "mtu": sysinfo::mtu(iface),
        "channels": { "combined": channels.combined, "max_combined": channels.max_combined },
        "xdp_native": xdp::probe(iface, "xdpdrv", &pass).to_json(),
        "xdp_generic": xdp::probe(iface, "xdpgeneric", &pass).to_json(),
        "afxdp_copy": afxdp::probe(iface, afxdp::XDP_COPY).to_json(),
        "afxdp_zerocopy": afxdp::probe(iface, afxdp::XDP_ZEROCOPY).to_json(),
    });
    println!("{report}");
    ExitCode::SUCCESS
}
