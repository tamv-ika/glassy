#!/usr/bin/env bash
# Fuzz smoke run (spec §7): every Rust (cargo-fuzz) and C++ (libFuzzer + ASan/UBSan) target for
# <seconds> each, one fuzzing process at a time (CONVENTIONS §3).
#
# Usage: scripts/fuzz_smoke.sh <seconds> [corpus_root]
#
# corpus_root (default build-fuzz/corpus, not committed) gets one directory per kind, the layout
# scripts/differential.sh reads, so `scripts/differential.sh fuzz/seeds build-fuzz/corpus`
# replays everything the fuzzers kept. Seeds come from fuzz/seeds/ (`differential.sh --seed`).
# Crash inputs land in build-fuzz/artifacts/.
#
# Needs a nightly toolchain, cargo-fuzz and clang (CC/CXX override clang-18/clang++-18).
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 || ! $1 =~ ^[0-9]+$ ]]; then
  echo "usage: $0 <seconds> [corpus_root]" >&2
  exit 2
fi
secs=$1
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
build=$repo/build-fuzz
corpus=$(mkdir -p "${2:-$build/corpus}" && cd "${2:-$build/corpus}" && pwd)
seeds=$repo/fuzz/seeds
artifacts=$build/artifacts
rust_bin=$repo/crates/glassy-proto/fuzz/target/x86_64-unknown-linux-gnu/release

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

echo "== build Rust fuzz targets"
(cd "$repo/crates/glassy-proto" && cargo +nightly fuzz build)

echo "== build C++ fuzz targets"
cmake -S "$repo/cpp/glassy-proto" -B "$build" -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER="${CC:-clang-18}" -DCMAKE_CXX_COMPILER="${CXX:-clang++-18}" \
  -DGLASSY_PROTO_FUZZ=ON -DGLASSY_PROTO_TESTS=OFF >/dev/null
cmake --build "$build" --parallel 2

# <name> <binary> <corpus kind> <seed kind>...: new inputs go to $corpus/<corpus kind>.
failed=()
fuzz() {
  local name=$1 bin=$2 kind=$3
  shift 3
  local dirs=("$corpus/$kind")
  for s in "$@"; do
    dirs+=("$seeds/$s")
  done
  mkdir -p "$corpus/$kind" "$artifacts"
  echo "== fuzz $name for ${secs}s"
  # -jobs=1 runs the fuzzer in one child that logs to fuzz-0.log in the working directory.
  if (cd "$work" && "$bin" -max_total_time="$secs" -jobs=1 -workers=1 -rss_limit_mb=2048 \
    -artifact_prefix="$artifacts/$name-" "${dirs[@]}" >/dev/null 2>&1); then
    grep -E '^#[0-9]+.*DONE' "$work/fuzz-0.log" | tail -1 || true
  else
    echo "CRASH in $name; log tail:"
    tail -40 "$work/fuzz-0.log" || true
    failed+=("$name")
  fi
  rm -f "$work/fuzz-0.log"
}

fuzz rust-connect "$rust_bin/connect" connect connect
fuzz rust-routing_ticket "$rust_bin/routing_ticket" routing_ticket routing_ticket
fuzz rust-retry_token "$rust_bin/retry_token" retry_token retry_token
fuzz rust-connect_info "$rust_bin/connect_info" connect_info connect_info
fuzz cpp-fuzz_native "$build/fuzz_native" connect connect
fuzz cpp-fuzz_frames "$build/fuzz_frames" frames frames
fuzz cpp-fuzz_server_ticket "$build/fuzz_server_ticket" server_ticket server_ticket
fuzz cpp-fuzz_connect_info "$build/fuzz_connect_info" connect_info connect_info
fuzz cpp-fuzz_retry "$build/fuzz_retry" retry_token retry_token
fuzz cpp-fuzz_wt "$build/fuzz_wt" wt wt_stream wt_path

if [[ ${#failed[@]} -ne 0 ]]; then
  echo "FAIL: ${failed[*]}"
  exit 1
fi
echo PASS
