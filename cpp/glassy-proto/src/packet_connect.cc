#include <algorithm>

#include "glassy/proto/consts.h"
#include "glassy/proto/packet.h"
#include "packet_internal.h"

namespace glassy::proto {
namespace internal {

Nonce24 proof_nonce(const std::array<uint8_t, 16>& conn_id) {
  Nonce24 n{};
  std::copy(conn_id.begin(), conn_id.end(), n.begin());
  return n;
}

void put_u64(uint64_t v, uint8_t* p) {
  for (size_t i = 0; i < 8; ++i) p[i] = static_cast<uint8_t>(v >> ((7 - i) * 8));
}

uint64_t get_u64(const uint8_t* p) {
  uint64_t v = 0;
  for (size_t i = 0; i < 8; ++i) v = (v << 8) | p[i];
  return v;
}

}  // namespace internal

namespace {

constexpr uint8_t kVersion = 1;
// type | ver | session_id | conn_id | connect_seq | routing_ticket | server_ticket_len
constexpr size_t kHeaderLen = 96;
constexpr size_t kProofLen = 16;

}  // namespace

Result<size_t> build_connect(const ConnectParams& p, std::span<uint8_t> out) {
  if (p.pad_to > kMaxPacket) return Error::kTooLarge;
  if (p.routing_ticket.size() != kRoutingTicketLen) return Error::kBadLength;
  const size_t tlen = p.server_ticket.size();
  if (tlen < kServerTicketNativeMin || tlen > kServerTicketMax) return Error::kBadLength;
  const size_t natural = kHeaderLen + tlen + kProofLen;
  const size_t total = std::max(natural, p.pad_to);
  if (out.size() < total) return Error::kBufferTooSmall;

  uint8_t* w = out.data();
  w[0] = kPacketConnect;
  w[1] = kVersion;
  std::copy(p.session_id.begin(), p.session_id.end(), w + 2);
  std::copy(p.conn_id.begin(), p.conn_id.end(), w + 10);
  internal::put_u64(p.connect_seq, w + 26);
  std::copy(p.routing_ticket.begin(), p.routing_ticket.end(), w + 34);
  w[94] = static_cast<uint8_t>(tlen >> 8);
  w[95] = static_cast<uint8_t>(tlen);
  std::copy(p.server_ticket.begin(), p.server_ticket.end(), w + kHeaderLen);
  const size_t signed_end = kHeaderLen + tlen;
  // Empty plaintext: the sealed output is exactly the 16-byte tag.
  auto sealed = xchacha_seal(p.key_c2s, internal::proof_nonce(p.conn_id), out.first(signed_end), {},
                             out.subspan(signed_end, kProofLen));
  if (!sealed.ok()) return sealed.error();
  std::fill(out.begin() + natural, out.begin() + total, uint8_t{0});
  return total;
}

Result<ConnectView> parse_connect(std::span<const uint8_t> b) {
  if (b.size() < kConnectMin || b.size() > kMaxPacket) return Error::kBadLength;
  if (b[0] != kPacketConnect) return Error::kBadType;
  if (b[1] != kVersion) return Error::kBadVersion;
  const size_t tlen = (size_t{b[94]} << 8) | b[95];
  if (tlen < kServerTicketNativeMin || tlen > kServerTicketMax ||
      kHeaderLen + tlen + kProofLen > b.size()) {
    return Error::kBadLength;
  }
  const size_t signed_end = kHeaderLen + tlen;
  const size_t proof_end = signed_end + kProofLen;
  ConnectView v;
  std::copy_n(b.begin() + 2, 8, v.session_id.begin());
  std::copy_n(b.begin() + 10, 16, v.conn_id.begin());
  v.connect_seq = internal::get_u64(b.data() + 26);
  v.routing_ticket = b.subspan(34, kRoutingTicketLen);
  v.server_ticket = b.subspan(kHeaderLen, tlen);
  v.proof_tag = b.subspan(signed_end, kProofLen);
  v.padding = b.subspan(proof_end);
  v.signed_prefix = b.first(signed_end);
  return v;
}

}  // namespace glassy::proto
