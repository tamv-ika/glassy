#include "base64.h"

namespace glassy::proto {
namespace {

constexpr char kStdTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
constexpr char kUrlTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const char* table_of(Base64Alphabet a) { return a == Base64Alphabet::kStd ? kStdTable : kUrlTable; }

// Returns the 6-bit value of `c`, or -1 outside the alphabet ('=' included).
int sextet(Base64Alphabet a, char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  const bool std_alpha = a == Base64Alphabet::kStd;
  if (c == (std_alpha ? '+' : '-')) return 62;
  if (c == (std_alpha ? '/' : '_')) return 63;
  return -1;
}

}  // namespace

Result<size_t> base64_decode(Base64Alphabet alphabet, std::string_view in, std::span<uint8_t> out) {
  const size_t rem = in.size() % 4;
  if (rem == 1) return Error::kBadEncoding;
  const size_t out_len = in.size() / 4 * 3 + (rem == 0 ? 0 : rem - 1);
  // Check the content before the buffer so errors do not depend on the caller's buffer size.
  size_t o = 0;
  uint32_t acc = 0;
  int bits = 0;
  for (char c : in) {
    const int v = sextet(alphabet, c);
    if (v < 0) return Error::kBadEncoding;
    acc = (acc << 6) | static_cast<uint32_t>(v);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      if (o < out.size()) out[o] = static_cast<uint8_t>(acc >> bits);
      ++o;
      acc &= (uint32_t{1} << bits) - 1;
    }
  }
  // The leftover bits are the unused tail of the final character and must be zero.
  if (acc != 0) return Error::kBadEncoding;
  if (out_len > out.size()) return Error::kBufferTooSmall;
  return out_len;
}

Result<size_t> base64_encode(Base64Alphabet alphabet, std::span<const uint8_t> in,
                             std::span<char> out) {
  const size_t full = in.size() / 3;
  const size_t rem = in.size() % 3;
  const size_t out_len = full * 4 + (rem == 0 ? 0 : rem + 1);
  if (out.size() < out_len) return Error::kBufferTooSmall;
  const char* t = table_of(alphabet);
  size_t o = 0;
  size_t i = 0;
  for (; i + 3 <= in.size(); i += 3) {
    const uint32_t v = (uint32_t{in[i]} << 16) | (uint32_t{in[i + 1]} << 8) | in[i + 2];
    out[o++] = t[(v >> 18) & 63];
    out[o++] = t[(v >> 12) & 63];
    out[o++] = t[(v >> 6) & 63];
    out[o++] = t[v & 63];
  }
  if (rem != 0) {
    uint32_t v = uint32_t{in[i]} << 16;
    if (rem == 2) v |= uint32_t{in[i + 1]} << 8;
    out[o++] = t[(v >> 18) & 63];
    out[o++] = t[(v >> 12) & 63];
    if (rem == 2) out[o++] = t[(v >> 6) & 63];
  }
  return out_len;
}

}  // namespace glassy::proto
