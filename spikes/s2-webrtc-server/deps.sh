#!/usr/bin/env bash
# Builds libdatachannel v0.24.6 into spikes/.deps (data channels only, GnuTLS when available).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
deps="$here/../.deps"
src="$deps/src/libdatachannel"
jobs="${CMAKE_BUILD_PARALLEL_LEVEL:-2}"

use_gnutls=1
if ! pkg-config --exists gnutls; then
  if ! apt-get install -y libgnutls28-dev; then
    echo "libgnutls28-dev unavailable; building libdatachannel against OpenSSL" >&2
    use_gnutls=0
  fi
fi

if [ ! -d "$src" ]; then
  git clone --recurse-submodules --depth 1 --shallow-submodules -b v0.24.6 \
    https://github.com/paullouisageneau/libdatachannel "$src"
fi

cmake -S "$src" -B "$src/build" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$deps" \
  -DUSE_GNUTLS="$use_gnutls" -DNO_MEDIA=ON -DNO_WEBSOCKET=ON -DNO_EXAMPLES=ON -DNO_TESTS=ON
cmake --build "$src/build" --parallel "$jobs"
cmake --install "$src/build"
echo "libdatachannel installed into $deps (USE_GNUTLS=$use_gnutls)"
