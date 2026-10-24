#ifndef GLASSY_PROTO_SHA256_NETTLE_H_
#define GLASSY_PROTO_SHA256_NETTLE_H_

#include <cstdint>
#include <span>

#include "glassy/proto/aead.h"

namespace glassy::proto {

// HKDF-SHA256 (RFC 5869) with an empty salt, 32-byte output.
Key32 hkdf_sha256_32(const Key32& ikm, std::span<const uint8_t> info);

// HMAC-SHA256 (RFC 2104).
Key32 hmac_sha256(std::span<const uint8_t> key, std::span<const uint8_t> msg);

}  // namespace glassy::proto

#endif  // GLASSY_PROTO_SHA256_NETTLE_H_
