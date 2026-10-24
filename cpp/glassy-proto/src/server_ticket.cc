#include "glassy/proto/server_ticket.h"

#include <algorithm>

#include "monocypher.h"
#include "sha256_nettle.h"

namespace glassy::proto {
namespace {

constexpr uint8_t kVersion = 1;
constexpr size_t kHeaderLen = 2;  // ver | key_id, also the AAD
constexpr size_t kNonceLen = 24;
constexpr size_t kBodyStart = kHeaderLen + kNonceLen;
constexpr size_t kUserIdMax = 64;
constexpr size_t kMetadataMax = 256;
// Largest plaintext body: ticket max minus header, nonce and tag.
constexpr size_t kBodyMax = kServerTicketMax - kBodyStart - kAeadTagLen;

bool is_defined_transport(uint8_t t) {
  return t == kTransportNative || t == kTransportWebRtc || t == kTransportWebTransport;
}

// Sequential body reader; running out of bytes is always kBadLength.
class Reader {
 public:
  explicit Reader(std::span<const uint8_t> b) : b_(b) {}
  bool take(size_t n, std::span<const uint8_t>* out) {
    if (b_.size() < n) return false;
    *out = b_.first(n);
    b_ = b_.subspan(n);
    return true;
  }
  template <size_t N>
  bool array(std::array<uint8_t, N>* out) {
    std::span<const uint8_t> s;
    if (!take(N, &s)) return false;
    std::copy(s.begin(), s.end(), out->begin());
    return true;
  }
  bool u8(uint8_t* out) {
    std::span<const uint8_t> s;
    if (!take(1, &s)) return false;
    *out = s[0];
    return true;
  }
  size_t remaining() const { return b_.size(); }
  std::span<const uint8_t> rest() const { return b_; }

 private:
  std::span<const uint8_t> b_;
};

}  // namespace

bool is_valid_utf8(std::span<const uint8_t> b) {
  size_t i = 0;
  while (i < b.size()) {
    const uint8_t c = b[i];
    size_t extra;
    uint8_t lo = 0x80;  // allowed range of the first continuation byte
    uint8_t hi = 0xbf;
    if (c < 0x80) {
      ++i;
      continue;
    } else if (c >= 0xc2 && c <= 0xdf) {
      extra = 1;
    } else if (c >= 0xe0 && c <= 0xef) {
      extra = 2;
      if (c == 0xe0) lo = 0xa0;  // no overlong 3-byte forms
      if (c == 0xed) hi = 0x9f;  // no surrogates U+D800..U+DFFF
    } else if (c >= 0xf0 && c <= 0xf4) {
      extra = 3;
      if (c == 0xf0) lo = 0x90;  // no overlong 4-byte forms
      if (c == 0xf4) hi = 0x8f;  // nothing above U+10FFFF
    } else {
      return false;  // continuation byte as lead, 0xc0, 0xc1, 0xf5..0xff
    }
    if (b.size() - i <= extra) return false;
    if (b[i + 1] < lo || b[i + 1] > hi) return false;
    for (size_t k = 2; k <= extra; ++k) {
      if ((b[i + k] & 0xc0) != 0x80) return false;
    }
    i += extra + 1;
  }
  return true;
}

ServerKeyRing::~ServerKeyRing() {
  for (Slot& s : slots_) crypto_wipe(s.key.data(), s.key.size());
}

Status ServerKeyRing::insert(uint8_t key_id, const Key32& k_gs) {
  constexpr char kInfo[] = "glassy-server-ticket";
  Slot* target = nullptr;
  for (Slot& s : slots_) {
    if (s.used && s.id == key_id) {
      target = &s;
      break;
    }
  }
  if (target == nullptr) {
    for (Slot& s : slots_) {
      if (!s.used) {
        target = &s;
        break;
      }
    }
  }
  if (target == nullptr) return Error::kTooLarge;
  target->key = hkdf_sha256_32(
      k_gs, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(kInfo), sizeof(kInfo) - 1));
  target->id = key_id;
  target->used = true;
  return std::monostate{};
}

const Key32* ServerKeyRing::find(uint8_t key_id) const {
  for (const Slot& s : slots_) {
    if (s.used && s.id == key_id) return &s.key;
  }
  return nullptr;
}

Result<ServerTicket> open_server_ticket(std::span<const uint8_t> b, const ServerKeyRing& ring,
                                        uint32_t now, const std::array<uint8_t, 16>& self_server_id,
                                        uint8_t via) {
  if (b.size() < kServerTicketMin || b.size() > kServerTicketMax) return Error::kBadLength;
  if (b[0] != kVersion) return Error::kBadVersion;
  const Key32* key = ring.find(b[1]);
  if (key == nullptr) return Error::kUnknownKey;
  Nonce24 nonce{};
  std::copy_n(b.begin() + kHeaderLen, kNonceLen, nonce.begin());

  std::array<uint8_t, kBodyMax> body{};
  auto opened = xchacha_open(*key, nonce, b.first(kHeaderLen), b.subspan(kBodyStart), body);
  if (!opened.ok()) return opened.error();

  Reader r(std::span<const uint8_t>(body.data(), opened.value()));
  ServerTicket t;
  uint8_t user_id_len = 0;
  if (!r.u8(&user_id_len)) return Error::kBadLength;
  if (user_id_len < 1 || user_id_len > kUserIdMax) return Error::kBadUserId;
  std::span<const uint8_t> user_id;
  if (!r.take(user_id_len, &user_id)) return Error::kBadLength;
  if (!r.array(&t.server_id) || !r.array(&t.session_id)) return Error::kBadLength;
  std::array<uint8_t, 4> expiry{};
  if (!r.array(&expiry)) return Error::kBadLength;
  t.expiry = (uint32_t{expiry[0]} << 24) | (uint32_t{expiry[1]} << 16) |
             (uint32_t{expiry[2]} << 8) | expiry[3];
  if (!r.u8(&t.transport)) return Error::kBadLength;
  if (!is_defined_transport(t.transport)) return Error::kBadTransport;
  if (t.transport == kTransportNative) {
    t.has_native_keys = true;
    if (!r.array(&t.key_c2s) || !r.array(&t.key_s2c)) return Error::kBadLength;
  }
  std::array<uint8_t, 2> mlen{};
  if (!r.array(&mlen)) return Error::kBadLength;
  const size_t metadata_len = (size_t{mlen[0]} << 8) | mlen[1];
  if (metadata_len > kMetadataMax) return Error::kBadMetadata;
  // Neither missing nor trailing bytes are tolerated.
  if (r.remaining() != metadata_len) return Error::kBadLength;
  std::copy(r.rest().begin(), r.rest().end(), t.metadata.begin());
  t.metadata_len = static_cast<uint16_t>(metadata_len);

  if (!is_valid_utf8(user_id)) return Error::kBadUserId;
  std::copy(user_id.begin(), user_id.end(), t.user_id.begin());
  t.user_id_len = user_id_len;

  if (t.server_id != self_server_id) return Error::kWrongServer;
  if (t.expiry < now) return Error::kExpired;
  if (t.transport != via) return Error::kBadTransport;
  return t;
}

}  // namespace glassy::proto
