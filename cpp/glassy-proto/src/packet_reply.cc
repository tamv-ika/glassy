#include <algorithm>

#include "glassy/proto/packet.h"
#include "packet_internal.h"

namespace glassy::proto {
namespace internal {

void seal_reply(uint8_t type, const std::array<uint8_t, 8>& session_id, uint64_t connect_seq,
                const std::array<uint8_t, 16>& server_nonce, std::span<const uint8_t> body,
                const std::array<uint8_t, 16>& conn_id, const Key32& key_s2c,
                std::span<uint8_t> out) {
  out[0] = type;
  std::copy(session_id.begin(), session_id.end(), out.begin() + 1);
  put_u64(connect_seq, out.data() + 9);
  std::copy(server_nonce.begin(), server_nonce.end(), out.begin() + 17);
  std::array<uint8_t, kReplyHeadLen + 16> aad{};
  std::copy_n(out.begin(), kReplyHeadLen, aad.begin());
  std::copy(conn_id.begin(), conn_id.end(), aad.begin() + kReplyHeadLen);
  // Callers pass an `out` of exactly head + body + tag, so sealing cannot fail.
  (void)xchacha_seal(key_s2c, packet_nonce(server_nonce, 0), aad, body, out.subspan(kReplyHeadLen));
}

}  // namespace internal

namespace {

struct Opened {
  std::array<uint8_t, 8> session_id{};
  uint64_t connect_seq = 0;
  std::array<uint8_t, 16> server_nonce{};
  std::array<uint8_t, 10> body{};
  size_t body_len = 0;
};

Result<Opened> open_reply(std::span<const uint8_t> b, uint8_t type, size_t len,
                          const std::array<uint8_t, 16>& conn_id, const Key32& key_s2c) {
  using internal::kReplyHeadLen;
  if (b.size() != len) return Error::kBadLength;
  if (b[0] != type) return Error::kBadType;
  Opened o;
  std::copy_n(b.begin() + 1, 8, o.session_id.begin());
  o.connect_seq = internal::get_u64(b.data() + 9);
  std::copy_n(b.begin() + 17, 16, o.server_nonce.begin());
  std::array<uint8_t, kReplyHeadLen + 16> aad{};
  std::copy_n(b.begin(), kReplyHeadLen, aad.begin());
  std::copy(conn_id.begin(), conn_id.end(), aad.begin() + kReplyHeadLen);
  auto r =
      xchacha_open(key_s2c, packet_nonce(o.server_nonce, 0), aad, b.subspan(kReplyHeadLen), o.body);
  if (!r.ok()) return r.error();
  o.body_len = r.value();
  return o;
}

}  // namespace

Result<ReplyHeader> peek_reply(std::span<const uint8_t> b) {
  uint8_t want;
  if (b.size() == kAcceptLen) {
    want = kPacketAccept;
  } else if (b.size() == kRejectLen) {
    want = kPacketReject;
  } else {
    return Error::kBadLength;
  }
  if (b[0] != want) return Error::kBadType;
  ReplyHeader h;
  h.type = b[0];
  std::copy_n(b.begin() + 1, 8, h.session_id.begin());
  h.connect_seq = internal::get_u64(b.data() + 9);
  return h;
}

Result<Accept> open_accept(std::span<const uint8_t> b, const std::array<uint8_t, 16>& conn_id,
                           const Key32& key_s2c) {
  auto r = open_reply(b, kPacketAccept, kAcceptLen, conn_id, key_s2c);
  if (!r.ok()) return r.error();
  const Opened& o = r.value();
  if (o.body_len != 10) return Error::kBadLength;
  if ((o.body[0] & ~uint8_t{1}) != 0 || o.body[1] != 0) return Error::kReservedNonzero;
  Accept a;
  a.session_id = o.session_id;
  a.connect_seq = o.connect_seq;
  a.server_nonce = o.server_nonce;
  a.resumed = (o.body[0] & 1) == 1;
  a.server_time_ms = internal::get_u64(o.body.data() + 2);
  return a;
}

Result<Reject> open_reject(std::span<const uint8_t> b, const std::array<uint8_t, 16>& conn_id,
                           const Key32& key_s2c) {
  auto r = open_reply(b, kPacketReject, kRejectLen, conn_id, key_s2c);
  if (!r.ok()) return r.error();
  const Opened& o = r.value();
  if (o.body_len != 9) return Error::kBadLength;
  Reject x;
  x.session_id = o.session_id;
  x.connect_seq = o.connect_seq;
  x.server_nonce = o.server_nonce;
  x.reason = o.body[0];
  x.last_connect_seq = internal::get_u64(o.body.data() + 1);
  return x;
}

}  // namespace glassy::proto
