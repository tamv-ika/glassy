#ifndef GLASSY_PROTO_VARINT_H_
#define GLASSY_PROTO_VARINT_H_

#include <cstddef>
#include <cstdint>
#include <span>

#include "glassy/proto/result.h"

namespace glassy::proto {

// RFC 9000 §16 variable-length integers; the encoder emits the shortest form and the decoder
// rejects longer forms (kNonCanonicalVarint). Values above 2^62 - 1 give kValueTooLarge.
inline constexpr uint64_t kVarintMax = (uint64_t{1} << 62) - 1;

struct VarintRead {
  uint64_t value = 0;
  size_t len = 0;
};

// Returns the number of bytes written; kBufferTooSmall if `out` cannot hold the encoding.
Result<size_t> varint_encode(uint64_t v, std::span<uint8_t> out);
Result<VarintRead> varint_decode(std::span<const uint8_t> in);

}  // namespace glassy::proto

#endif  // GLASSY_PROTO_VARINT_H_
