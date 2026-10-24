#include <algorithm>

#include "glassy/proto/consts.h"
#include "glassy/proto/packet.h"
#include "packet_internal.h"

namespace glassy::proto {
namespace {

constexpr size_t kHeaderLen = 13;

// `type | session_id | pn_low` then AEAD(body); the AAD is the 13 header bytes.
Result<size_t> seal(uint8_t type, const Key32& key, const std::array<uint8_t, 16>& server_nonce,
                    const std::array<uint8_t, 8>& session_id, uint64_t pn,
                    std::span<const uint8_t> body, std::span<uint8_t> out) {
  const size_t total = kHeaderLen + body.size() + kAeadTagLen;
  if (out.size() < total) return Error::kBufferTooSmall;
  out[0] = type;
  std::copy(session_id.begin(), session_id.end(), out.begin() + 1);
  // Only the low 32 bits travel; the receiver reconstructs the rest (RFC 9000 A.3).
  for (size_t i = 0; i < 4; ++i) out[9 + i] = static_cast<uint8_t>(pn >> ((3 - i) * 8));
  auto r = xchacha_seal(key, packet_nonce(server_nonce, pn), out.first(kHeaderLen), body,
                        out.subspan(kHeaderLen));
  if (!r.ok()) return r.error();
  return total;
}

Result<size_t> open(uint8_t type, const Key32& key, const std::array<uint8_t, 16>& server_nonce,
                    std::span<const uint8_t> b, uint64_t pn, std::span<uint8_t> out) {
  auto h = parse_header(b);
  if (!h.ok()) return h.error();
  if (h.value().type != type) return Error::kBadType;
  return xchacha_open(key, packet_nonce(server_nonce, pn), b.first(kHeaderLen),
                      b.subspan(kHeaderLen), out);
}

}  // namespace

Result<Header> parse_header(std::span<const uint8_t> b) {
  if (b.size() < kDataMin || b.size() > kMaxPacket) return Error::kBadLength;
  if (b[0] != kPacketData && b[0] != kPacketDisconnect) return Error::kBadType;
  Header h;
  h.type = b[0];
  std::copy_n(b.begin() + 1, 8, h.session_id.begin());
  h.pn_low = (uint32_t{b[9]} << 24) | (uint32_t{b[10]} << 16) | (uint32_t{b[11]} << 8) | b[12];
  return h;
}

Result<size_t> seal_data(const Key32& key, const std::array<uint8_t, 16>& server_nonce,
                         const std::array<uint8_t, 8>& session_id, uint64_t pn,
                         std::span<const uint8_t> frames, std::span<uint8_t> out) {
  if (frames.size() > kMaxFrames) return Error::kTooLarge;
  // pn 0 is reserved for ACCEPT/REJECT, so it is never a valid DATA number.
  if (pn == 0) return Error::kReplayed;
  return seal(kPacketData, key, server_nonce, session_id, pn, frames, out);
}

Result<size_t> open_data(const Key32& key, const std::array<uint8_t, 16>& server_nonce,
                         std::span<const uint8_t> b, uint64_t pn, std::span<uint8_t> out) {
  return open(kPacketData, key, server_nonce, b, pn, out);
}

Result<std::array<uint8_t, kDisconnectLen>> seal_disconnect(
    const Key32& key, const std::array<uint8_t, 16>& server_nonce,
    const std::array<uint8_t, 8>& session_id, uint64_t pn, uint8_t reason) {
  // pn 0 under key_s2c would reuse the ACCEPT/REJECT nonce (server_nonce | 0^8), spec §0.3.
  if (pn == 0) return Error::kReplayed;
  std::array<uint8_t, kDisconnectLen> out{};
  const uint8_t body[1] = {reason};
  auto r = seal(kPacketDisconnect, key, server_nonce, session_id, pn, body, out);
  if (!r.ok()) return r.error();
  return out;
}

Result<uint8_t> open_disconnect(const Key32& key, const std::array<uint8_t, 16>& server_nonce,
                                std::span<const uint8_t> b, uint64_t pn) {
  if (b.size() != kDisconnectLen) return Error::kBadLength;
  uint8_t reason[1] = {0};
  auto r = open(kPacketDisconnect, key, server_nonce, b, pn, reason);
  if (!r.ok()) return r.error();
  if (r.value() != 1) return Error::kBadLength;
  return reason[0];
}

}  // namespace glassy::proto
