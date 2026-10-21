#!/usr/bin/env bash
# Runs cap-probe against a veth pair and checks the capabilities veth is known to have:
# native and generic XDP, AF_XDP copy mode, and no zero-copy. Then checks that xdp_reflect.o
# bounces UDP sent to port 9. Needs root (netns, XDP, AF_XDP).
# Build first: make -C bpf && cargo build --release
set -euo pipefail
cd "$(dirname "$0")/.."

ip netns add capns
cleanup() {
  ip link del cap0 2>/dev/null || true
  ip netns del capns 2>/dev/null || true
}
trap cleanup EXIT
ip link add cap0 type veth peer name cap1 netns capns
ip link set cap0 up
ip -n capns link set cap1 up

out=$(./target/release/cap-probe --iface cap0 --bpf-dir ./bpf)
echo "$out"
# Zero-copy must fail because veth lacks it, not because the copy-mode probe still holds queue 0.
jq -e '.driver == "veth" and .xdp_native.ok == true and .xdp_generic.ok == true
       and .afxdp_copy.ok == true and .afxdp_zerocopy.ok == false
       and (.afxdp_zerocopy.error | test("not supported"))' <<<"$out"

# xdp_reflect.o on the far end must send a UDP datagram to port 9 straight back.
ip addr add 10.99.0.1/24 dev cap0
ip -n capns addr add 10.99.0.2/24 dev cap1
# veth hands locally sent UDP over with a partial checksum (TX offload); native XDP drops that
# metadata, so the reflected copy would fail checksum checks. Packets from a real NIC carry
# complete checksums, so make the sender compute them too.
ethtool -K cap0 tx-checksum-ip-generic off >/dev/null
for mode in xdpgeneric xdpdrv; do
  if [[ $mode == xdpdrv ]]; then
    # Native XDP_TX on veth lands in the peer's NAPI queue, which only exists while the peer
    # has an XDP program of its own.
    ip link set dev cap0 xdpdrv obj ./bpf/xdp_pass.o sec xdp
  fi
  ip -n capns link set dev cap1 "$mode" obj ./bpf/xdp_reflect.o sec xdp
  python3 - "$mode" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.99.0.1", 0))
s.settimeout(2)
s.sendto(b"glassy-reflect", ("10.99.0.2", 9))
data, peer = s.recvfrom(64)
assert data == b"glassy-reflect" and peer == ("10.99.0.2", 9), (data, peer)
print(f"reflect {sys.argv[1]}: ok")
PY
  ip -n capns link set dev cap1 "$mode" off
  ip link set dev cap0 xdpdrv off
done
