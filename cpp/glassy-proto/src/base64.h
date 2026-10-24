#ifndef GLASSY_PROTO_BASE64_H_
#define GLASSY_PROTO_BASE64_H_

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "glassy/proto/result.h"

namespace glassy::proto {

// RFC 4648 alphabets, always without padding (spec: std for ICE ufrag/pwd, url elsewhere).
enum class Base64Alphabet : uint8_t { kStd, kUrl };

// Strict decoder matching the Rust `base64` crate configured without padding: rejects '=',
// characters outside the alphabet, impossible lengths (len % 4 == 1) and non-zero trailing
// bits, all as kBadEncoding. kBufferTooSmall if `out` cannot hold the decoded bytes.
// Allocation-free; returns the number of bytes written.
Result<size_t> base64_decode(Base64Alphabet alphabet, std::string_view in, std::span<uint8_t> out);

// Encodes without padding; returns the number of characters written, kBufferTooSmall otherwise.
Result<size_t> base64_encode(Base64Alphabet alphabet, std::span<const uint8_t> in,
                             std::span<char> out);

}  // namespace glassy::proto

#endif  // GLASSY_PROTO_BASE64_H_
