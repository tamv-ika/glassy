#ifndef GLASSY_PROTO_PACKET_H_
#define GLASSY_PROTO_PACKET_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "glassy/proto/aead.h"
#include "glassy/proto/result.h"
#include "glassy/proto/server_ticket.h"

namespace glassy::proto {

// Native packet layer (spec §4). Mirrors crates/glassy-proto/src/packet.

inline constexpr uint8_t kPacketConnect = 0x80;
inline constexpr uint8_t kPacketAccept = 0x81;
inline constexpr uint8_t kPacketData = 0x82;
inline constexpr uint8_t kPacketDisconnect = 0x83;
inline constexpr uint8_t kPacketReject = 0x84;

inline constexpr size_t kConnectMin = 251;
inline constexpr size_t kRoutingTicketLen = 60;
// Smallest native server ticket (keys present, no metadata).
inline constexpr size_t kServerTicketNativeMin = 139;
inline constexpr size_t kAcceptLen = 59;
inline constexpr size_t kRejectLen = 58;
inline constexpr size_t kDataMin = 29;                 // 13 header + 16 tag
inline constexpr size_t kMaxFrames = 1200 - kDataMin;  // 1171
inline constexpr size_t kDisconnectLen = 30;

// REJECT reason codes (spec §4.6); unknown values must be tolerated by receivers.
inline constexpr uint8_t kRejectStaleConnectSeq = 1;
inline constexpr uint8_t kRejectKicked = 2;
inline constexpr uint8_t kRejectSessionClosed = 3;
inline constexpr uint8_t kRejectServerFull = 4;

// ---- CONNECT (spec §4.2) ----

struct ConnectParams {
  std::array<uint8_t, 8> session_id;
  std::array<uint8_t, 16> conn_id;
  uint64_t connect_seq;
  std::span<const uint8_t> routing_ticket;  // exactly 60 bytes
  std::span<const uint8_t> server_ticket;   // 139..458 bytes (native ticket)
  Key32 key_c2s;
  size_t pad_to;  // zero-padded up to this size; at most 1200, smaller values are ignored
};

// Writes the CONNECT into `out` and returns its length. pad_to > 1200 gives kTooLarge, a wrong
// ticket size kBadLength, a routing ticket that is not 60 bytes kBadLength, a short `out`
// kBufferTooSmall.
Result<size_t> build_connect(const ConnectParams& p, std::span<uint8_t> out);

// Zero-copy view of a structurally valid CONNECT; nothing is authenticated yet. Spans point into
// the parsed buffer.
struct ConnectView {
  std::array<uint8_t, 8> session_id{};
  std::array<uint8_t, 16> conn_id{};
  uint64_t connect_seq = 0;
  std::span<const uint8_t> routing_ticket;  // 60 bytes
  std::span<const uint8_t> server_ticket;
  std::span<const uint8_t> proof_tag;  // 16 bytes
  std::span<const uint8_t> padding;
  std::span<const uint8_t> signed_prefix;  // everything the proof covers
};

// Order: length 251..1200 (kBadLength), type (kBadType), version (kBadVersion), ticket length
// 139..458 and fitting the packet (kBadLength).
Result<ConnectView> parse_connect(std::span<const uint8_t> packet);

// ---- ACCEPT / REJECT (spec §4.3, §4.6) ----

struct Accept {
  std::array<uint8_t, 8> session_id{};
  uint64_t connect_seq = 0;
  std::array<uint8_t, 16> server_nonce{};
  bool resumed = false;
  uint64_t server_time_ms = 0;
};

struct Reject {
  std::array<uint8_t, 8> session_id{};
  uint64_t connect_seq = 0;
  std::array<uint8_t, 16> server_nonce{};
  uint8_t reason = 0;  // kept as received
  uint64_t last_connect_seq = 0;
};

struct ReplyHeader {
  uint8_t type = 0;
  std::array<uint8_t, 8> session_id{};
  uint64_t connect_seq = 0;
};

// Unauthenticated head of an ACCEPT/REJECT. Length not in {58, 59} is kBadLength; the type must
// then match the length (59 with 0x81, 58 with 0x84) or it is kBadType.
Result<ReplyHeader> peek_reply(std::span<const uint8_t> packet);

// Opens against the conn_id of the CONNECT being answered. Order: length, type, AEAD
// (kAuthFailed), then reserved bits (kReservedNonzero) for ACCEPT.
Result<Accept> open_accept(std::span<const uint8_t> packet, const std::array<uint8_t, 16>& conn_id,
                           const Key32& key_s2c);
Result<Reject> open_reject(std::span<const uint8_t> packet, const std::array<uint8_t, 16>& conn_id,
                           const Key32& key_s2c);

// ---- DATA / DISCONNECT (spec §4.4, §4.5) ----

struct Header {
  uint8_t type = 0;
  std::array<uint8_t, 8> session_id{};
  uint32_t pn_low = 0;
};

// Length 29..1200 (kBadLength), type DATA or DISCONNECT (kBadType).
Result<Header> parse_header(std::span<const uint8_t> packet);

// frames > 1171 bytes is kTooLarge (checked first), pn 0 is kReplayed (pn 0 is the ACCEPT nonce),
// `out` shorter than 29 + frames.size() is kBufferTooSmall. Returns the packet length.
Result<size_t> seal_data(const Key32& key, const std::array<uint8_t, 16>& server_nonce,
                         const std::array<uint8_t, 8>& session_id, uint64_t pn,
                         std::span<const uint8_t> frames, std::span<uint8_t> out);

// `pn` is the full number the caller reconstructed. Writes the frames to `out`, returns their
// length.
Result<size_t> open_data(const Key32& key, const std::array<uint8_t, 16>& server_nonce,
                         std::span<const uint8_t> packet, uint64_t pn, std::span<uint8_t> out);

// pn 0 is kReplayed (it would reuse the ACCEPT nonce under key_s2c).
Result<std::array<uint8_t, kDisconnectLen>> seal_disconnect(
    const Key32& key, const std::array<uint8_t, 16>& server_nonce,
    const std::array<uint8_t, 8>& session_id, uint64_t pn, uint8_t reason);

// Returns the reason byte as received.
Result<uint8_t> open_disconnect(const Key32& key, const std::array<uint8_t, 16>& server_nonce,
                                std::span<const uint8_t> packet, uint64_t pn);

// ---- Server side (glassy_proto_server) ----

struct VerifiedConnect {
  std::array<uint8_t, 8> session_id{};
  std::array<uint8_t, 16> conn_id{};
  uint64_t connect_seq = 0;
  ServerTicket ticket;
};

// Fixed order of spec §4.2: parse checks, padding all zero (kBadPadding), server ticket
// (open_server_ticket errors pass through, transport native), session match
// (kSessionMismatch), proof (kAuthFailed).
Result<VerifiedConnect> verify_connect(std::span<const uint8_t> packet, const ServerKeyRing& ring,
                                       const std::array<uint8_t, 16>& self_server_id, uint32_t now);

std::array<uint8_t, kAcceptLen> build_accept(const Accept& a,
                                             const std::array<uint8_t, 16>& conn_id,
                                             const Key32& key_s2c);
std::array<uint8_t, kRejectLen> build_reject(const Reject& r,
                                             const std::array<uint8_t, 16>& conn_id,
                                             const Key32& key_s2c);

}  // namespace glassy::proto

#endif  // GLASSY_PROTO_PACKET_H_
