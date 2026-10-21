//! Native and generic XDP attach probes through iproute2's libbpf loader.

use std::path::Path;
use std::process::Command;

use crate::Probe;

/// Attaches `obj` in `mode` (`xdpdrv` or `xdpgeneric`) and detaches it again.
pub fn probe(iface: &str, mode: &str, obj: &Path) -> Probe {
    let obj = obj.to_string_lossy();
    if let Err(e) = ip(&[
        "-force", "link", "set", "dev", iface, mode, "obj", &obj, "sec", "xdp",
    ]) {
        return Probe::failed(e);
    }
    // A program left attached would change the outcome of the probes that follow.
    match ip(&["link", "set", "dev", iface, mode, "off"]) {
        Ok(()) => Probe::ok(),
        Err(e) => Probe::failed(format!("detach: {e}")),
    }
}

fn ip(args: &[&str]) -> Result<(), String> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| format!("ip: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}
