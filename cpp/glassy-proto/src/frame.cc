#include "glassy/proto/frame.h"

#include <algorithm>

#include "glassy/proto/consts.h"
#include "glassy/proto/varint.h"

namespace glassy::proto {

namespace {

constexpr uint8_t kTypeAck = 0x01;
constexpr uint8_t kTypeStream = 0x02;
constexpr uint8_t kTypeDatagram = 0x03;

// offset + len must stay within the varint range. The sum cannot wrap because len is a
// decoded varint or a span size, so it saturates at worst.
bool stream_end_ok(uint64_t offset, uint64_t len) {
  return offset <= kVarintMax && len <= kVarintMax - offset;
}

// Decodes the body after the type byte; returns bytes consumed after the type byte.
Result<size_t> decode_ack(std::span<const uint8_t> body, Frame& out) {
  if (body.size() < 7) return Error::kTruncated;
  const uint8_t mask = body[6];
  uint64_t bits = ~uint64_t{0};
  size_t used = 7;
  for (int i = 0; i < 8; ++i) {
    if (!(mask & (1u << i))) continue;
    if (used >= body.size()) return Error::kTruncated;
    const uint8_t b = body[used];
    // A sent 0xFF byte has a shorter canonical encoding (spec §5.2).
    if (b == 0xFF) return Error::kNonCanonicalAck;
    ++used;
    bits &= ~(uint64_t{0xFF} << (8 * i));
    bits |= uint64_t{b} << (8 * i);
  }
  out.type = FrameType::kAck;
  out.ack.largest_pn_low = (uint32_t{body[0]} << 24) | (uint32_t{body[1]} << 16) |
                           (uint32_t{body[2]} << 8) | uint32_t{body[3]};
  out.ack.ack_delay = static_cast<uint16_t>((body[4] << 8) | body[5]);
  out.ack.ack_bits = bits;
  return used;
}

Result<size_t> decode_stream(std::span<const uint8_t> body, Frame& out) {
  const auto off = varint_decode(body);
  if (!off.ok()) return off.error();
  const auto len = varint_decode(body.subspan(off.value().len));
  if (!len.ok()) return len.error();
  // Checked before the data bytes so an overflowing frame reports kValueTooLarge even when
  // it is also truncated.
  if (!stream_end_ok(off.value().value, len.value().value)) return Error::kValueTooLarge;
  const size_t start = off.value().len + len.value().len;
  if (len.value().value > body.size() - start) return Error::kTruncated;
  const size_t n = static_cast<size_t>(len.value().value);
  out.type = FrameType::kStream;
  out.offset = off.value().value;
  out.data = body.subspan(start, n);
  return start + n;
}

Result<size_t> decode_datagram(std::span<const uint8_t> body, Frame& out) {
  const auto len = varint_decode(body);
  if (!len.ok()) return len.error();
  // Checked before the data bytes, like the Rust reference.
  if (len.value().value > kMaxDatagram) return Error::kTooLarge;
  const size_t start = len.value().len;
  const size_t n = static_cast<size_t>(len.value().value);
  if (n > body.size() - start) return Error::kTruncated;
  out.type = FrameType::kDatagram;
  out.data = body.subspan(start, n);
  return start + n;
}

}  // namespace

Result<bool> FrameReader::next(Frame& out) {
  if (failed_ != Error::kOk) return failed_;
  if (rest_.empty()) return false;
  const uint8_t type = rest_[0];
  const auto body = rest_.subspan(1);
  out = Frame{};
  Result<size_t> used = Error::kBadType;
  switch (type) {
    case kTypeAck:
      if (seen_ack_) {
        failed_ = Error::kDuplicateAck;
        return failed_;
      }
      seen_ack_ = true;
      used = decode_ack(body, out);
      break;
    case kTypeStream:
      used = decode_stream(body, out);
      break;
    case kTypeDatagram:
      used = decode_datagram(body, out);
      break;
    default:
      break;
  }
  if (!used.ok()) {
    failed_ = used.error();
    return failed_;
  }
  rest_ = body.subspan(used.value());
  return true;
}

Result<size_t> encode_ack(const AckFrame& ack, std::span<uint8_t> out) {
  // Canonical form (spec §5.2): 0xFF bytes are never sent, so the mask is derived.
  uint8_t mask = 0;
  uint8_t present[8];
  size_t n = 0;
  for (int i = 0; i < 8; ++i) {
    const auto b = static_cast<uint8_t>(ack.ack_bits >> (8 * i));
    if (b != 0xFF) {
      mask = static_cast<uint8_t>(mask | (1u << i));
      present[n++] = b;
    }
  }
  const size_t total = 8 + n;
  if (out.size() < total) return Error::kBufferTooSmall;
  out[0] = kTypeAck;
  for (int i = 0; i < 4; ++i) out[1 + i] = static_cast<uint8_t>(ack.largest_pn_low >> (24 - 8 * i));
  out[5] = static_cast<uint8_t>(ack.ack_delay >> 8);
  out[6] = static_cast<uint8_t>(ack.ack_delay);
  out[7] = mask;
  std::copy(present, present + n, out.begin() + 8);
  return total;
}

Result<size_t> encode_stream(uint64_t offset, std::span<const uint8_t> data,
                             std::span<uint8_t> out) {
  if (!stream_end_ok(offset, data.size())) return Error::kValueTooLarge;
  if (out.empty()) return Error::kBufferTooSmall;
  size_t pos = 1;
  const auto o = varint_encode(offset, out.subspan(pos));
  if (!o.ok()) return o.error();
  pos += o.value();
  const auto l = varint_encode(data.size(), out.subspan(pos));
  if (!l.ok()) return l.error();
  pos += l.value();
  if (out.size() - pos < data.size()) return Error::kBufferTooSmall;
  out[0] = kTypeStream;
  std::copy(data.begin(), data.end(), out.begin() + pos);
  return pos + data.size();
}

Result<size_t> encode_datagram(std::span<const uint8_t> data, std::span<uint8_t> out) {
  if (data.size() > kMaxDatagram) return Error::kTooLarge;
  if (out.empty()) return Error::kBufferTooSmall;
  const auto l = varint_encode(data.size(), out.subspan(1));
  if (!l.ok()) return l.error();
  const size_t pos = 1 + l.value();
  if (out.size() - pos < data.size()) return Error::kBufferTooSmall;
  out[0] = kTypeDatagram;
  std::copy(data.begin(), data.end(), out.begin() + pos);
  return pos + data.size();
}

}  // namespace glassy::proto
