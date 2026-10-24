#include <algorithm>

#include "glassy/proto/packet.h"
#include "packet_internal.h"

namespace glassy::proto {

Result<VerifiedConnect> verify_connect(std::span<const uint8_t> b, const ServerKeyRing& ring,
                                       uint32_t now,
                                       const std::array<uint8_t, 16>& self_server_id) {
  auto parsed = parse_connect(b);
  if (!parsed.ok()) return parsed.error();
  const ConnectView& v = parsed.value();
  // Padding first: it is cheap and rejects a trailer that was never split off.
  if (std::any_of(v.padding.begin(), v.padding.end(), [](uint8_t x) { return x != 0; })) {
    return Error::kBadPadding;
  }
  auto ticket = open_server_ticket(v.server_ticket, ring, now, self_server_id, kTransportNative);
  if (!ticket.ok()) return ticket.error();
  VerifiedConnect out;
  out.ticket = ticket.value();
  if (out.ticket.session_id != v.session_id) return Error::kSessionMismatch;
  if (!out.ticket.has_native_keys) return Error::kBadTransport;
  // Empty plaintext, so the output buffer is never written.
  std::array<uint8_t, 0> none{};
  auto proof = [&] {
    std::array<uint8_t, kAeadTagLen> tag{};
    std::copy(v.proof_tag.begin(), v.proof_tag.end(), tag.begin());
    return xchacha_open(out.ticket.key_c2s, internal::proof_nonce(v.conn_id), v.signed_prefix, tag,
                        none);
  }();
  if (!proof.ok()) return proof.error();
  out.session_id = v.session_id;
  out.conn_id = v.conn_id;
  out.connect_seq = v.connect_seq;
  return out;
}

std::array<uint8_t, kAcceptLen> build_accept(const Accept& a,
                                             const std::array<uint8_t, 16>& conn_id,
                                             const Key32& key_s2c) {
  std::array<uint8_t, 10> body{};
  body[0] = a.resumed ? 1 : 0;
  internal::put_u64(a.server_time_ms, body.data() + 2);
  std::array<uint8_t, kAcceptLen> out{};
  internal::seal_reply(kPacketAccept, a.session_id, a.connect_seq, a.server_nonce, body, conn_id,
                       key_s2c, out);
  return out;
}

std::array<uint8_t, kRejectLen> build_reject(const Reject& r,
                                             const std::array<uint8_t, 16>& conn_id,
                                             const Key32& key_s2c) {
  std::array<uint8_t, 9> body{};
  body[0] = r.reason;
  internal::put_u64(r.last_connect_seq, body.data() + 1);
  std::array<uint8_t, kRejectLen> out{};
  internal::seal_reply(kPacketReject, r.session_id, r.connect_seq, r.server_nonce, body, conn_id,
                       key_s2c, out);
  return out;
}

}  // namespace glassy::proto
