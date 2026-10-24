#ifndef GLASSY_PROTO_SRC_PACKET_INTERNAL_H_
#define GLASSY_PROTO_SRC_PACKET_INTERNAL_H_

#include <array>
#include <cstdint>
#include <span>

#include "glassy/proto/aead.h"

namespace glassy::proto::internal {

// `type | session_id | connect_seq | server_nonce`.
inline constexpr size_t kReplyHeadLen = 33;

// Writes `head(33) | AEAD(body) | tag` to `out` (33 + body.size() + 16 bytes). The AAD is the
// head followed by conn_id; the nonce is server_nonce | pn 0 (spec §4.3).
void seal_reply(uint8_t type, const std::array<uint8_t, 8>& session_id, uint64_t connect_seq,
                const std::array<uint8_t, 16>& server_nonce, std::span<const uint8_t> body,
                const std::array<uint8_t, 16>& conn_id, const Key32& key_s2c,
                std::span<uint8_t> out);

// Proof nonce: conn_id | 0^8 (spec §4.2).
Nonce24 proof_nonce(const std::array<uint8_t, 16>& conn_id);

void put_u64(uint64_t v, uint8_t* p);
uint64_t get_u64(const uint8_t* p);

}  // namespace glassy::proto::internal

#endif  // GLASSY_PROTO_SRC_PACKET_INTERNAL_H_
