#!/usr/bin/env bash
# Prints core_bytes=<n>, the size of glassy_proto_core as the difference between the size_probe
# and size_baseline executables, and fails when it exceeds the 40 KB budget.
# Usage: check_size.sh <build_dir>
set -euo pipefail

limit=40960
build_dir="${1:?usage: check_size.sh <build_dir>}"

probe="$build_dir/size_probe"
baseline="$build_dir/size_baseline"
for f in "$probe" "$baseline"; do
  if [[ ! -f "$f" ]]; then
    echo "check_size: missing $f (build targets size_probe and size_baseline)" >&2
    exit 2
  fi
done

core_bytes=$(($(stat -c%s "$probe") - $(stat -c%s "$baseline")))
echo "core_bytes=$core_bytes"
if ((core_bytes > limit)); then
  echo "check_size: core is $core_bytes bytes, over the $limit byte budget" >&2
  exit 1
fi
