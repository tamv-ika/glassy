//! Host and NIC facts that decide which data-plane mode a node can run (spec §8).

use std::fs;
use std::path::Path;
use std::process::Command;

/// Queue counts from `ethtool -l`; `None` where the driver reports `n/a`.
#[derive(Debug, PartialEq, Eq)]
pub struct Channels {
    pub combined: Option<u32>,
    pub max_combined: Option<u32>,
}

/// Parses `ethtool -l` output: the first `Combined:` is the maximum, the second the current value.
pub fn parse_channels(out: &str) -> Channels {
    let mut values = out
        .lines()
        .filter_map(|line| line.strip_prefix("Combined:"))
        .map(|v| v.trim().parse::<u32>().ok());
    let max_combined = values.next().flatten();
    let combined = values.next().flatten();
    Channels {
        combined,
        max_combined,
    }
}

/// Extracts the `driver:` line from `ethtool -i` output.
pub fn parse_driver(out: &str) -> Option<String> {
    out.lines()
        .find_map(|line| line.strip_prefix("driver:"))
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

pub fn kernel_release() -> String {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .map_or_else(|_| String::new(), |s| s.trim().to_string())
}

pub fn has_btf() -> bool {
    Path::new("/sys/kernel/btf/vmlinux").exists()
}

/// The driver bound to `iface`: the sysfs symlink for PCI NICs, `ethtool -i` for virtual ones
/// such as veth that have no `device` directory.
pub fn driver(iface: &str) -> Option<String> {
    let link = format!("/sys/class/net/{iface}/device/driver");
    if let Ok(target) = fs::read_link(&link) {
        return target.file_name().map(|n| n.to_string_lossy().into_owned());
    }
    parse_driver(&ethtool(&["-i", iface])?)
}

pub fn mtu(iface: &str) -> Option<u32> {
    fs::read_to_string(format!("/sys/class/net/{iface}/mtu"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

pub fn channels(iface: &str) -> Channels {
    parse_channels(&ethtool(&["-l", iface]).unwrap_or_default())
}

fn ethtool(args: &[&str]) -> Option<String> {
    let out = Command::new("ethtool").args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENA_CHANNELS: &str = "Channel parameters for ens5:\nPre-set maximums:\nRX:\t\tn/a\nTX:\t\tn/a\nOther:\t\tn/a\nCombined:\t8\nCurrent hardware settings:\nRX:\t\tn/a\nTX:\t\tn/a\nOther:\t\tn/a\nCombined:\t4\n";
    const VETH_CHANNELS: &str = "Channel parameters for capx0:\nPre-set maximums:\nRX:\t\t4\nTX:\t\t4\nOther:\t\tn/a\nCombined:\tn/a\nCurrent hardware settings:\nRX:\t\t1\nTX:\t\t1\nOther:\t\tn/a\nCombined:\tn/a\n";

    #[test]
    fn channels_reads_max_then_current_combined() {
        let c = parse_channels(ENA_CHANNELS);
        assert_eq!(
            c,
            Channels {
                combined: Some(4),
                max_combined: Some(8)
            }
        );
    }

    #[test]
    fn channels_maps_na_to_none() {
        let c = parse_channels(VETH_CHANNELS);
        assert_eq!(
            c,
            Channels {
                combined: None,
                max_combined: None
            }
        );
    }

    #[test]
    fn channels_of_unexpected_output_is_all_none() {
        let c = parse_channels("netlink error: Operation not supported\n");
        assert_eq!(
            c,
            Channels {
                combined: None,
                max_combined: None
            }
        );
    }

    #[test]
    fn driver_line_is_extracted() {
        let out = "driver: ena\nversion: 6.18.0\nfirmware-version: \nbus-info: 0000:00:05.0\n";
        assert_eq!(parse_driver(out).as_deref(), Some("ena"));
    }

    #[test]
    fn driver_missing_is_none() {
        assert_eq!(parse_driver("version: 1.0\n"), None);
    }
}
