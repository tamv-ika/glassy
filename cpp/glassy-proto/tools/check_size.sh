#!/usr/bin/env bash
# Prints core_bytes=<n>, the size of glassy_proto_core as the difference in text+data (Berkeley
# `size`) between the size_probe and size_baseline executables, and fails when it exceeds the
# 40 KB budget. `size` is byte-exact; file sizes are 4 KiB page-granular. The build dir must be
# configured as MinSizeRel (-Os for glassy_proto_core), so the number does not depend on the
# build type the caller happened to choose.
# Usage: check_size.sh <build_dir>
set -euo pipefail

limit=40960
build_dir="${1:?usage: check_size.sh <build_dir>}"

build_type=$(sed -n 's/^CMAKE_BUILD_TYPE:[A-Z]*=//p' "$build_dir/CMakeCache.txt" 2>/dev/null || true)
if [[ "$build_type" != "MinSizeRel" ]]; then
  echo "check_size: $build_dir is configured as '${build_type:-unknown}'; configure with -DCMAKE_BUILD_TYPE=MinSizeRel" >&2
  exit 2
fi

probe="$build_dir/size_probe"
baseline="$build_dir/size_baseline"
for f in "$probe" "$baseline"; do
  if [[ ! -f "$f" ]]; then
    echo "check_size: missing $f (build targets size_probe and size_baseline)" >&2
    exit 2
  fi
done

# Berkeley format: header line, then "text data bss dec hex filename".
text_data() { size -B "$1" | awk 'NR == 2 { print $1 + $2 }'; }

core_bytes=$(($(text_data "$probe") - $(text_data "$baseline")))
echo "core_bytes=$core_bytes"
if ((core_bytes > limit)); then
  echo "check_size: core is $core_bytes bytes, over the $limit byte budget" >&2
  exit 1
fi
