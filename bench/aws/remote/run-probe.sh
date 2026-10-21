#!/usr/bin/env bash
# Runs on the S3 probe instances (Amazon Linux 2023), driven by s3-ena-probe.sh over SSH.
# Every mode except setup prints one JSON object on stdout.
#
#   setup                 install the toolchain, build cap-probe and the XDP objects (DUT)
#   setup-gen             make a traffic generator available: pktgen, else Python (generator)
#   probe                 cap-probe as booted, then again after preparing the NIC for native XDP
#   reflect-on            attach xdp_reflect.o (native, falling back to generic)
#   reflect-off           detach it
#   measure SECS          rx/tx packet rates and allowance counters over SECS seconds
#   generate DST_IP SECS  flood 64-byte UDP to DST_IP:9 from every CPU for SECS seconds
#
# THROWAWAY: SP0 benchmark tooling.
set -euo pipefail
cd "$(dirname "$0")"

IFACE=$(ip -o -4 route show default | awk '{print $5; exit}')
CAP_PROBE=./cap-probe/target/release/cap-probe
BPF_DIR=./cap-probe/bpf
# cap-probe uses edition 2024.
MIN_RUST=1.85.0

setup() {
  sudo dnf install -y -q clang llvm libbpf-devel cargo ethtool jq iproute >&2
  local have
  have=$(cargo --version 2>/dev/null | awk '{print $2}')
  if [[ $(printf '%s\n%s\n' "$MIN_RUST" "${have:-0}" | sort -V | head -1) != "$MIN_RUST" ]]; then
    echo "cargo ${have:-missing} < $MIN_RUST; installing a toolchain with rustup" >&2
    curl --proto '=https' -sSf https://sh.rustup.rs | sh -s -- -y -q --profile minimal >&2
  fi
  if [[ -f $HOME/.cargo/env ]]; then
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
  fi
  make -C "$BPF_DIR" -s >&2
  # Two jobs, as everywhere in this repo (CONVENTIONS §3).
  (cd cap-probe && CARGO_BUILD_JOBS=2 cargo build --release -q) >&2
}

cap_probe() {
  sudo "$CAP_PROBE" --iface "$IFACE" --bpf-dir "$BPF_DIR"
}

combined() { # $1 = 1 for the maximum, 2 for the current value
  ethtool -l "$IFACE" 2>/dev/null | awk -v want="$1" '/^Combined:/ {n++; if (n == want) print $2}'
}

# ENA only takes native XDP with MTU <= ~3498 and at most half of the maximum channels in use,
# while EC2 boots with MTU 9001 and every channel in use.
prepare_xdp() {
  local mtu_before max cur new
  mtu_before=$(cat "/sys/class/net/$IFACE/mtu")
  sudo ip link set dev "$IFACE" mtu 1500
  max=$(combined 1)
  cur=$(combined 2)
  new=$cur
  if [[ $max =~ ^[0-9]+$ && $cur =~ ^[0-9]+$ ]] && ((cur * 2 > max)); then
    new=$((max / 2))
    sudo ethtool -L "$IFACE" combined "$new"
  fi
  jq -n --argjson mtu_before "$mtu_before" --arg max "$max" --arg before "$cur" --arg after "$new" \
    '{mtu_before: $mtu_before, mtu: 1500, max_combined: $max,
      combined_before: $before, combined: $after}'
}

probe() {
  local booted prepared after
  booted=$(cap_probe)
  prepared=$(prepare_xdp)
  after=$(cap_probe)
  jq -n --argjson booted "$booted" --argjson prepared "$prepared" --argjson after "$after" \
    '{as_booted: $booted, prepare_xdp: $prepared, after_prepare: $after}'
}

reflect_on() {
  local mode err
  for mode in xdpdrv xdpgeneric; do
    if err=$(sudo ip -force link set dev "$IFACE" "$mode" obj "$BPF_DIR/xdp_reflect.o" sec xdp 2>&1); then
      jq -n --arg mode "$mode" '{mode: $mode}'
      return 0
    fi
    echo "$mode attach failed: $err" >&2
  done
  return 1
}

reflect_off() {
  sudo ip link set dev "$IFACE" xdpdrv off 2>/dev/null || true
  sudo ip link set dev "$IFACE" xdpgeneric off 2>/dev/null || true
  echo '{}'
}

snapshot() {
  ethtool -S "$IFACE" | awk -F: 'NF == 2 {gsub(/[ \t]/, "", $1); gsub(/[ \t]/, "", $2); print $1, $2}' | sort
}

# rx_pps counts what reached the DUT's queues, tx_pps what xdp_reflect sent back with XDP_TX.
measure() {
  local secs=$1 before after
  before=$(snapshot)
  sleep "$secs"
  after=$(snapshot)
  join <(echo "$before") <(echo "$after") |
    awk '$2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ {d = $3 - $2; if (d != 0 || $1 ~ /allowance/) print $1, d}' |
    jq -R -s --argjson secs "$secs" '
      split("\n") | map(select(length > 0) | split(" ") | {(.[0]): (.[1] | tonumber)}) | add // {}
      | . as $d
      | def rate(re): ([$d | to_entries[] | select(.key | test(re)) | .value] | add // 0) / $secs;
        {seconds: $secs,
         rx_pps: rate("^queue_[0-9]+_rx_cnt$"),
         tx_pps: rate("^queue_[0-9]+_rx_xdp_tx$"),
         allowance_exceeded: ($d | with_entries(select(.key | test("allowance_exceeded$")))),
         deltas: $d}'
}

pgset() { echo "$2" | sudo tee "$1" >/dev/null; }

# pktgen ships in the kernel's modules-extra package, whose name follows the kernel package
# (kernel6.12-modules-extra on AL2023's 6.12 AMI). Whether it is there is checked here, before
# the run depends on it.
setup_gen() {
  if ! sudo modprobe pktgen 2>/dev/null; then
    local kpkg
    kpkg=$(rpm -qf "/lib/modules/$(uname -r)" --qf '%{NAME}\n' 2>/dev/null | head -1)
    kpkg=${kpkg%-core}
    kpkg=${kpkg%-modules}
    sudo dnf install -y -q "${kpkg:-kernel}-modules-extra-$(uname -r)" >&2 || true
  fi
  if sudo modprobe pktgen 2>/dev/null; then
    echo '{"generator": "pktgen"}'
  else
    echo "pktgen unavailable; falling back to a userspace generator" >&2
    command -v python3 >/dev/null
    echo '{"generator": "python"}'
  fi
}

generate() {
  if [[ -d /proc/net/pktgen ]]; then
    pktgen "$@"
  else
    python_flood "$@"
  fi
}

# Far slower than pktgen, but enough to see whether xdp_reflect keeps up and which allowance
# counters move. 18-byte payloads make 64-byte Ethernet frames.
python_flood() {
  local dst=$1 secs=$2 threads
  threads=$(nproc)
  python3 - "$dst" "$secs" "$threads" <<'PY' |
import os, socket, sys, time
dst, secs, n = sys.argv[1], float(sys.argv[2]), int(sys.argv[3])
pids = []
for i in range(n):
    pid = os.fork()
    if pid == 0:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("", 10000 + i))
        sent, end = 0, time.monotonic() + secs
        while time.monotonic() < end:
            for _ in range(256):
                try:
                    s.sendto(b"\0" * 18, (dst, 9))
                    sent += 1
                except OSError:
                    pass
        os.write(1, f"{sent}\n".encode())
        os._exit(0)
    pids.append(pid)
for pid in pids:
    os.waitpid(pid, 0)
PY
    jq -s --argjson secs "$secs" --argjson threads "$threads" \
      '{generator: "python", threads: $threads, sent: add, pps: (add / $secs)}'
}

pktgen() {
  local dst=$1 secs=$2 mac threads t dev
  # Resolve the DUT's MAC: send one datagram so ARP runs, then read the neighbour table.
  echo -n x >"/dev/udp/$dst/9" || true
  sleep 1
  mac=$(ip neigh show "$dst" dev "$IFACE" | awk '{print $3; exit}')
  [[ -n $mac ]] || { echo "no neighbour entry for $dst" >&2; return 1; }
  threads=$(nproc)
  for ((t = 0; t < threads; t++)); do
    pgset "/proc/net/pktgen/kpktgend_$t" rem_device_all
    pgset "/proc/net/pktgen/kpktgend_$t" "add_device $IFACE@$t"
    dev=/proc/net/pktgen/$IFACE@$t
    pgset "$dev" "count 0"
    pgset "$dev" "pkt_size 64"
    pgset "$dev" "delay 0"
    pgset "$dev" "dst $dst"
    pgset "$dev" "dst_mac $mac"
    pgset "$dev" "udp_dst_min 9"
    pgset "$dev" "udp_dst_max 9"
    # Distinct source ports per thread spread the flood across the DUT's RSS queues.
    pgset "$dev" "udp_src_min $((10000 + t * 64))"
    pgset "$dev" "udp_src_max $((10000 + t * 64 + 63))"
    pgset "$dev" "flag UDPSRC_RND"
    pgset "$dev" "flag QUEUE_MAP_CPU"
  done
  # "start" blocks until stopped, so bound it and stop explicitly.
  sudo timeout "$secs" sh -c 'echo start > /proc/net/pktgen/pgctrl' || true
  pgset /proc/net/pktgen/pgctrl stop
  local results=()
  for ((t = 0; t < threads; t++)); do
    results+=("$(grep -h 'pps' "/proc/net/pktgen/$IFACE@$t" | tr -s ' ' | head -1)")
  done
  printf '%s\n' "${results[@]}" |
    jq -R -s --arg mac "$mac" --argjson threads "$threads" \
      '{generator: "pktgen", threads: $threads, dst_mac: $mac,
        results: (split("\n") | map(select(length > 0)))}'
}

case ${1:-} in
  setup) setup ;;
  probe) probe ;;
  reflect-on) reflect_on ;;
  reflect-off) reflect_off ;;
  measure) measure "${2:?seconds}" ;;
  setup-gen) setup_gen ;;
  generate) generate "${2:?destination IP}" "${3:?seconds}" ;;
  *)
    echo "usage: $0 setup|setup-gen|probe|reflect-on|reflect-off|measure SECS|generate DST_IP SECS" >&2
    exit 2
    ;;
esac
