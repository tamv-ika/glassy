#!/usr/bin/env bash
# Builds ngtcp2 v1.25.0 (GnuTLS crypto backend) and nghttp3 (QPACK only) into spikes/.deps.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
deps="$here/../.deps"
jobs="${CMAKE_BUILD_PARALLEL_LEVEL:-2}"
nghttp3_tag="v1.18.0"

if ! pkg-config --exists gnutls; then
  # ngtcp2's crypto backend needs GnuTLS >= 3.7.5; there is no fallback for this spike.
  apt-get install -y libgnutls28-dev
fi

build() {
  local name=$1 url=$2 tag=$3
  shift 3
  local src="$deps/src/$name"
  [ -d "$src" ] || git clone --recurse-submodules --depth 1 --shallow-submodules -b "$tag" "$url" "$src"
  cmake -S "$src" -B "$src/build" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$deps" \
    -DCMAKE_PREFIX_PATH="$deps" -DENABLE_LIB_ONLY=ON "$@"
  cmake --build "$src/build" --parallel "$jobs"
  cmake --install "$src/build"
}

build nghttp3 https://github.com/ngtcp2/nghttp3 "$nghttp3_tag"
build ngtcp2 https://github.com/ngtcp2/ngtcp2 v1.25.0 -DENABLE_GNUTLS=ON -DENABLE_OPENSSL=OFF
echo "ngtcp2 v1.25.0 + nghttp3 $nghttp3_tag installed into $deps"
