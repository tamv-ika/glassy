// libFuzzer target: every native packet parser (spec §4) on one raw datagram, with and without
// the gateway's client_addr trailer. Keys and ids are the vectors' values, so seeds built from
// vectors/native_packets.json reach the checks behind the AEAD.
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "glassy/proto/consts.h"
#include "glassy/proto/packet.h"
#include "glassy/proto/server_ticket.h"
#include "glassy/proto/trailer.h"

using namespace glassy::proto;

namespace {

void require(bool ok) {
  if (!ok) __builtin_trap();
}

template <size_t N>
std::array<uint8_t, N> filled(uint8_t v) {
  std::array<uint8_t, N> a;
  a.fill(v);
  return a;
}

constexpr uint32_t kNow = 1900000000;
const auto kConnId = filled<16>(0x66);
const auto kKeyC2s = filled<32>(0x44);
const auto kKeyS2c = filled<32>(0x55);
const auto kServerNonce = filled<16>(0x77);
const auto kServerId = filled<16>(0xab);

const ServerKeyRing& ring() {
  static ServerKeyRing* r = [] {
    auto* k = new ServerKeyRing;
    require(k->insert(1, filled<32>(0x22)).ok());
    return k;
  }();
  return *r;
}

void check_connect(std::span<const uint8_t> in) {
  auto p = parse_connect(in);
  if (p.ok()) {
    const ConnectView& v = p.value();
    require(in.size() >= kConnectMin && in.size() <= kMaxPacket);
    require(v.routing_ticket.size() == kRoutingTicketLen && v.proof_tag.size() == 16);
    require(v.signed_prefix.size() + 16 + v.padding.size() == in.size());
    require(v.signed_prefix.size() == 96 + v.server_ticket.size());
  }
  auto vc = verify_connect(in, ring(), kServerId, kNow);
  if (vc.ok()) {
    require(p.ok());
    for (uint8_t b : p.value().padding) require(b == 0);
    require(vc.value().ticket.transport == kTransportNative);
    require(vc.value().ticket.session_id == vc.value().session_id);
  }
}

void check_data(std::span<const uint8_t> in) {
  auto h = parse_header(in);
  if (!h.ok()) return;
  require(in.size() >= kDataMin && in.size() <= kMaxPacket);
  // The pn as a receiver right after the handshake would reconstruct it; either direction.
  const uint64_t pn = h.value().pn_low;
  std::array<uint8_t, kMaxFrames> frames;
  for (const Key32* key : {&kKeyC2s, &kKeyS2c}) {
    auto d = open_data(*key, kServerNonce, in, pn, frames);
    if (d.ok()) require(d.value() == in.size() - kDataMin);
    (void)open_disconnect(*key, kServerNonce, in, pn);
  }
}

void check_reply(std::span<const uint8_t> in) {
  auto peek = peek_reply(in);
  auto a = open_accept(in, kConnId, kKeyS2c);
  auto r = open_reject(in, kConnId, kKeyS2c);
  require(!(a.ok() && r.ok()));
  if (a.ok() || r.ok()) require(peek.ok());
  if (a.ok()) require(build_accept(a.value(), kConnId, kKeyS2c).size() == in.size());
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const std::span<const uint8_t> in(data, size);
  check_connect(in);
  check_reply(in);
  check_data(in);
  auto split = split_trailer(in);
  if (split.ok()) {
    require(split.value().payload.size() + kTrailerV4Len == size);
    check_connect(split.value().payload);
  }
  return 0;
}
