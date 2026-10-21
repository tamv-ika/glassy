#include "retry_token.hpp"

namespace glassy {
namespace {

constexpr size_t kMinOdcil = 8;
constexpr size_t kMaxOdcil = 20;

}  // namespace

std::optional<std::vector<uint8_t>> parse_nss_token(std::span<const uint8_t> token) {
  if (token.empty() || (token[0] & 0x80) != 0) {
    return std::nullopt;
  }
  const size_t odcil = token[0] & 0x7f;
  if (odcil < kMinOdcil || odcil > kMaxOdcil || token.size() < 1 + odcil) {
    return std::nullopt;
  }
  return std::vector<uint8_t>(token.begin() + 1, token.begin() + 1 + static_cast<ptrdiff_t>(odcil));
}

}  // namespace glassy
