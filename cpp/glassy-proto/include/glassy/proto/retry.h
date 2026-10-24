#ifndef GLASSY_PROTO_RETRY_H_
#define GLASSY_PROTO_RETRY_H_

#include <cstdint>
#include <span>

#include "glassy/proto/result.h"

namespace glassy::proto {

// Reads the ODCID of a Retry token without checking tag or expiry (spec §3.6): the game server
// trusts tokens that came through the gateway, which validates them. Token layout:
// byte0 (0 | ODCIL) | ODCID | expiry (u64) | tag (16). The returned span points into `token`.
// Errors in order: kBadLength (empty), kBadTokenType (bit 7 set), kBadOdcil (not 8..20),
// kBadLength (size mismatch).
Result<std::span<const uint8_t>> retry_token_odcid(std::span<const uint8_t> token);

}  // namespace glassy::proto

#endif  // GLASSY_PROTO_RETRY_H_
