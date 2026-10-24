// libFuzzer target: the game server's parse-only read of a QUIC Retry token (spec §3.6).
#include <cstddef>
#include <cstdint>
#include <span>

#include "glassy/proto/retry.h"

using namespace glassy::proto;

namespace {

void require(bool ok) {
  if (!ok) __builtin_trap();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const std::span<const uint8_t> in(data, size);
  auto r = retry_token_odcid(in);
  if (!r.ok()) return 0;
  // byte0 | ODCID | expiry (8) | tag (16), ODCIL 8..=20 (RFC 9000 §7.2).
  const auto odcid = r.value();
  require(odcid.size() >= 8 && odcid.size() <= 20);
  require(1 + odcid.size() + 8 + 16 == size);
  require(odcid.data() == data + 1);
  return 0;
}
