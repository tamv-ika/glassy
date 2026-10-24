#include "glassy/proto/varint.h"

namespace glassy::proto {

namespace {

size_t encoded_len(uint64_t v) {
  if (v <= 63) return 1;
  if (v <= 16383) return 2;
  if (v <= 1073741823) return 4;
  return 8;
}

}  // namespace

Result<size_t> varint_encode(uint64_t v, std::span<uint8_t> out) {
  if (v > kVarintMax) return Error::kValueTooLarge;
  const size_t len = encoded_len(v);
  if (out.size() < len) return Error::kBufferTooSmall;
  // The top two bits of the first byte carry log2 of the length (RFC 9000 §16).
  const uint64_t tag = len == 1 ? 0 : len == 2 ? 1 : len == 4 ? 2 : 3;
  const uint64_t tagged = v | (tag << (len * 8 - 2));
  for (size_t i = 0; i < len; ++i) {
    out[i] = static_cast<uint8_t>(tagged >> ((len - 1 - i) * 8));
  }
  return len;
}

Result<VarintRead> varint_decode(std::span<const uint8_t> in) {
  if (in.empty()) return Error::kTruncated;
  const size_t len = size_t{1} << (in[0] >> 6);
  if (in.size() < len) return Error::kTruncated;
  uint64_t v = in[0] & 0x3f;
  for (size_t i = 1; i < len; ++i) v = (v << 8) | in[i];
  // Canonical form: the value must not fit in a shorter encoding.
  if (encoded_len(v) != len) return Error::kNonCanonicalVarint;
  return VarintRead{v, len};
}

}  // namespace glassy::proto
