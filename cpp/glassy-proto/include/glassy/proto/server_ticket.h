#ifndef GLASSY_PROTO_SERVER_TICKET_H_
#define GLASSY_PROTO_SERVER_TICKET_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "glassy/proto/aead.h"
#include "glassy/proto/result.h"

namespace glassy::proto {

// Transport bits (spec §3.1); a ticket carries exactly one, `via` is the one it arrived on.
inline constexpr uint8_t kTransportNative = 1;
inline constexpr uint8_t kTransportWebRtc = 2;
inline constexpr uint8_t kTransportWebTransport = 4;

inline constexpr size_t kServerTicketMin = 75;
inline constexpr size_t kServerTicketMax = 458;
inline constexpr size_t kServerKeyRingMax = 16;

// Plaintext server ticket (spec §3.2). Fixed-size storage keeps the codec allocation-free.
struct ServerTicket {
  std::array<char, 64> user_id{};  // user_id_len bytes of UTF-8, not NUL-terminated
  uint8_t user_id_len = 0;
  std::array<uint8_t, 16> server_id{};
  std::array<uint8_t, 8> session_id{};
  uint32_t expiry = 0;
  uint8_t transport = 0;
  bool has_native_keys = false;  // true iff transport is native
  Key32 key_c2s{};
  Key32 key_s2c{};
  std::array<uint8_t, 256> metadata{};
  uint16_t metadata_len = 0;
};

// Game-server ticket keys by key_id. Stores the derived K_ticket
// (HKDF-SHA256(K_gs, salt empty, info "glassy-server-ticket")), never K_gs.
class ServerKeyRing {
 public:
  ServerKeyRing() = default;
  ServerKeyRing(const ServerKeyRing&) = delete;
  ServerKeyRing& operator=(const ServerKeyRing&) = delete;
  ~ServerKeyRing();  // wipes every stored key

  // Adds a key or replaces the one with the same id; kTooLarge when 16 distinct ids are stored.
  Status insert(uint8_t key_id, const Key32& k_gs);

  // nullptr when `key_id` is unknown.
  const Key32* find(uint8_t key_id) const;

 private:
  struct Slot {
    Key32 key{};
    uint8_t id = 0;
    bool used = false;
  };
  std::array<Slot, kServerKeyRingMax> slots_{};
};

// Opens and validates a ticket in the fixed order of spec §3.2 (same as the Rust reference):
// size 75..458 (kBadLength), version (kBadVersion), key id (kUnknownKey), AEAD (kAuthFailed),
// user_id length 1..64 (kBadUserId), transport (kBadTransport), metadata_len > 256
// (kBadMetadata), exact body length (kBadLength), UTF-8 user_id (kBadUserId), server_id
// (kWrongServer), expiry < now (kExpired), transport != via (kBadTransport).
Result<ServerTicket> open_server_ticket(std::span<const uint8_t> ticket, const ServerKeyRing& ring,
                                        uint32_t now, const std::array<uint8_t, 16>& self_server_id,
                                        uint8_t via);

// RFC 3629 UTF-8 validation: rejects overlong forms, surrogates and values above U+10FFFF.
bool is_valid_utf8(std::span<const uint8_t> bytes);

}  // namespace glassy::proto

#endif  // GLASSY_PROTO_SERVER_TICKET_H_
