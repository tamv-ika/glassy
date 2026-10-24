#ifndef GLASSY_PROTO_AEAD_H_
#define GLASSY_PROTO_AEAD_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "glassy/proto/result.h"

namespace glassy::proto {

using Key32 = std::array<uint8_t, 32>;
using Nonce24 = std::array<uint8_t, 24>;
inline constexpr size_t kAeadTagLen = 16;

// XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha-03). Writes `ciphertext | tag` to `out`
// (pt.size() + 16 bytes) and returns the byte count; kBufferTooSmall otherwise.
Result<size_t> xchacha_seal(const Key32& key, const Nonce24& nonce, std::span<const uint8_t> aad,
                            std::span<const uint8_t> pt, std::span<uint8_t> out);

// Inputs shorter than the tag give kTruncated, a bad tag kAuthFailed, a small `out`
// (sealed.size() - 16 bytes needed) kBufferTooSmall. `out` is untouched on failure.
Result<size_t> xchacha_open(const Key32& key, const Nonce24& nonce, std::span<const uint8_t> aad,
                            std::span<const uint8_t> sealed, std::span<uint8_t> out);

// Packet nonce: server_nonce (16) | pn (u64 big-endian).
Nonce24 packet_nonce(const std::array<uint8_t, 16>& server_nonce, uint64_t pn);

}  // namespace glassy::proto

#endif  // GLASSY_PROTO_AEAD_H_
