#!/usr/bin/env bash
# Rust/C++ differential runner (spec §7): feeds every corpus file to both decode CLIs and
# compares their canonical one-line JSON results line by line.
#
# Usage:
#   scripts/differential.sh <corpus_root>...  compare both CLIs on every <root>/<kind>/* file
#   scripts/differential.sh --seed            regenerate fuzz/seeds/ from vectors/*.json
#
# A corpus root holds one directory per kind (fuzz/seeds/ and the fuzz_smoke.sh corpus root
# share this layout). `wt/`, the fuzz_wt corpus, feeds both wt_stream and wt_path; other
# directories are ignored.
#
# GLASSY_RUST_CLI / GLASSY_CPP_CLI override the binaries (build them with
# `cargo build -p glassy-proto-cli` and the `glassy_proto_cli` CMake target).
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
rust_cli=${GLASSY_RUST_CLI:-$repo/target/debug/glassy-proto-cli}
cpp_cli=${GLASSY_CPP_CLI:-$repo/build/glassy_proto_cli}
kinds=(frames connect server_ticket retry_token connect_info wt_stream wt_path)

usage() {
  echo "usage: $0 <corpus_root>... | --seed" >&2
  exit 2
}

need_cli() {
  if [[ ! -x $2 ]]; then
    echo "error: $1 cli not found: $2" >&2
    exit 2
  fi
}

# Corpus subdirectories whose files are inputs for kind $1.
subdirs_for() {
  case $1 in
    wt_stream | wt_path) echo "$1 wt" ;;
    *) echo "$1" ;;
  esac
}

[[ $# -ge 1 ]] || usage

if [[ $1 == --seed ]]; then
  [[ $# -eq 1 ]] || usage
  need_cli rust "$rust_cli"
  "$rust_cli" seed "$repo/vectors" "$repo/fuzz/seeds"
  exit 0
fi

for root in "$@"; do
  if [[ ! -d $root ]]; then
    echo "error: corpus dir not found: $root" >&2
    exit 2
  fi
done
need_cli rust "$rust_cli"
need_cli c++ "$cpp_cli"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

total=0
mismatches=0
empty_kinds=()
for kind in "${kinds[@]}"; do
  : >"$tmp/files"
  read -ra subs <<<"$(subdirs_for "$kind")"
  for root in "$@"; do
    # A root may lack some kinds (a fuzz corpus only has the kinds its targets wrote).
    : >"$tmp/part"
    for sub in "${subs[@]}"; do
      if [[ -d $root/$sub ]]; then
        find "$root/$sub" -maxdepth 1 -type f | LC_ALL=C sort >>"$tmp/part"
      fi
    done
    if [[ -s $tmp/part ]]; then
      cat "$tmp/part" >>"$tmp/files"
    else
      echo "$root/$kind: 0 inputs (skipped)"
    fi
  done
  # Every kind must be exercised by some root, so a broken corpus path cannot pass silently.
  if [[ ! -s $tmp/files ]]; then
    echo "error: no inputs for $kind" >&2
    empty_kinds+=("$kind")
    continue
  fi

  : >"$tmp/in"
  while IFS= read -r f; do
    xxd -p "$f" | tr -d '\n' >>"$tmp/in"
    echo >>"$tmp/in"
  done <"$tmp/files"

  # A crash or a usage error is a failure of its own, not a mismatch.
  "$rust_cli" "$kind" <"$tmp/in" >"$tmp/rust"
  "$cpp_cli" "$kind" <"$tmp/in" >"$tmp/cpp"

  n=$(wc -l <"$tmp/files")
  for side in rust cpp; do
    got=$(wc -l <"$tmp/$side")
    if [[ $got -ne $n ]]; then
      echo "error: $side cli printed $got lines for $n $kind inputs" >&2
      exit 1
    fi
  done

  paste -d '\t' "$tmp/files" "$tmp/rust" "$tmp/cpp" | awk -F '\t' -v kind="$kind" '
    $2 != $3 { printf "DIFF %s %s\n  rust: %s\n  cpp:  %s\n", kind, $1, $2, $3 }' >"$tmp/diff"
  bad=$(grep -c '^DIFF' "$tmp/diff" || true)
  cat "$tmp/diff"
  echo "$kind: $n inputs, $bad mismatches"
  total=$((total + n))
  mismatches=$((mismatches + bad))
done

echo "differential: $total inputs, $mismatches mismatches"
if [[ $mismatches -ne 0 || $total -eq 0 || ${#empty_kinds[@]} -ne 0 ]]; then
  echo FAIL
  exit 1
fi
echo PASS
