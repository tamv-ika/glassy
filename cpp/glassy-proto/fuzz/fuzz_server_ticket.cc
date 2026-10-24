// libFuzzer target: server ticket open (spec §3.2). The input is opened as is, which mostly
// stops at the AEAD; then its body region is sealed with the vectors' key under version 1,
// key id 1 and opened again, so the fuzzer also drives the plaintext body checks.
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "glassy/proto/aead.h"
#include "glassy/proto/server_ticket.h"

using namespace glassy::proto;

namespace {

void require(bool ok) {
  if (!ok) __builtin_trap();
}

constexpr uint32_t kNow = 1900000000;
constexpr size_t kHeaderLen = 2;
constexpr size_t kBodyStart = kHeaderLen + 24;

const ServerKeyRing& ring() {
  static ServerKeyRing* r = [] {
    auto* k = new ServerKeyRing;
    Key32 k_gs;
    k_gs.fill(0x22);
    require(k->insert(1, k_gs).ok());
    return k;
  }();
  return *r;
}

void open_all(std::span<const uint8_t> ticket) {
  std::array<uint8_t, 16> self;
  self.fill(0xab);
  for (uint8_t via : {kTransportNative, kTransportWebRtc, kTransportWebTransport}) {
    auto r = open_server_ticket(ticket, ring(), kNow, self, via);
    if (!r.ok()) continue;
    const ServerTicket& t = r.value();
    require(t.transport == via);
    require(t.user_id_len >= 1 && t.user_id_len <= t.user_id.size());
    require(t.metadata_len <= t.metadata.size());
    require(t.has_native_keys == (via == kTransportNative));
    require(t.expiry >= kNow && t.server_id == self);
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const std::span<const uint8_t> in(data, size);
  open_all(in);

  if (size < kServerTicketMin || size > kServerTicketMax) return 0;
  const Key32* key = ring().find(1);
  require(key != nullptr);
  std::vector<uint8_t> sealed(size);
  sealed[0] = 1;
  sealed[1] = 1;
  std::copy(in.begin() + kHeaderLen, in.begin() + kBodyStart, sealed.begin() + kHeaderLen);
  Nonce24 nonce;
  std::copy(in.begin() + kHeaderLen, in.begin() + kBodyStart, nonce.begin());
  const auto body = in.subspan(kBodyStart, size - kBodyStart - kAeadTagLen);
  auto n = xchacha_seal(*key, nonce, std::span(sealed).first(kHeaderLen), body,
                        std::span(sealed).subspan(kBodyStart));
  require(n.ok() && n.value() == size - kBodyStart);
  open_all(sealed);
  return 0;
}
