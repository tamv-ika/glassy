// The only translation unit that includes nettle.
#include "sha256_nettle.h"

#include <nettle/hkdf.h>
#include <nettle/hmac.h>

namespace glassy::proto {
namespace {

// nettle's generic callbacks take a void* context; thin wrappers avoid function-pointer casts.
void hmac_update(void* ctx, size_t len, const uint8_t* data) {
  hmac_sha256_update(static_cast<hmac_sha256_ctx*>(ctx), len, data);
}

void hmac_digest(void* ctx, size_t len, uint8_t* dst) {
  hmac_sha256_digest(static_cast<hmac_sha256_ctx*>(ctx), len, dst);
}

}  // namespace

Key32 hkdf_sha256_32(const Key32& ikm, std::span<const uint8_t> info) {
  hmac_sha256_ctx ctx;
  // An empty HMAC key equals the RFC 5869 default salt of HashLen zero bytes.
  hmac_sha256_set_key(&ctx, 0, nullptr);
  Key32 prk{};
  hkdf_extract(&ctx, hmac_update, hmac_digest, prk.size(), ikm.size(), ikm.data(), prk.data());
  hmac_sha256_set_key(&ctx, prk.size(), prk.data());
  Key32 okm{};
  hkdf_expand(&ctx, hmac_update, hmac_digest, prk.size(), info.size(), info.data(), okm.size(),
              okm.data());
  return okm;
}

Key32 hmac_sha256(std::span<const uint8_t> key, std::span<const uint8_t> msg) {
  hmac_sha256_ctx ctx;
  hmac_sha256_set_key(&ctx, key.size(), key.data());
  hmac_sha256_update(&ctx, msg.size(), msg.data());
  Key32 mac{};
  hmac_sha256_digest(&ctx, mac.size(), mac.data());
  return mac;
}

}  // namespace glassy::proto
