#include "glassy/proto/retry.h"

namespace glassy::proto {
namespace {
constexpr size_t kMinOdcil = 8;
constexpr size_t kMaxOdcil = 20;
constexpr size_t kExpiryLen = 8;
constexpr size_t kTagLen = 16;
}  // namespace

Result<std::span<const uint8_t>> retry_token_odcid(std::span<const uint8_t> token) {
  if (token.empty()) return Error::kBadLength;
  const uint8_t byte0 = token[0];
  if ((byte0 & 0x80) != 0) return Error::kBadTokenType;
  const size_t odcil = byte0;
  if (odcil < kMinOdcil || odcil > kMaxOdcil) return Error::kBadOdcil;
  if (token.size() != 1 + odcil + kExpiryLen + kTagLen) return Error::kBadLength;
  return token.subspan(1, odcil);
}

}  // namespace glassy::proto
