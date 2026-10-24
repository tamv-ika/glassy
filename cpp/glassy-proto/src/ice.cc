#include "glassy/proto/ice.h"

#include "base64.h"
#include "sha256_nettle.h"

namespace glassy::proto {

std::array<char, 43> ice_pwd(const Key32& k_gs, std::string_view ufrag) {
  constexpr char kInfo[] = "glassy-ice";
  const Key32 k_ice = hkdf_sha256_32(
      k_gs, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(kInfo), sizeof(kInfo) - 1));
  const Key32 mac = hmac_sha256(
      k_ice,
      std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(ufrag.data()), ufrag.size()));
  std::array<char, 43> out{};
  // 32 bytes always encode to exactly 43 characters, so this cannot fail.
  (void)base64_encode(Base64Alphabet::kStd, mac, out);
  return out;
}

}  // namespace glassy::proto
