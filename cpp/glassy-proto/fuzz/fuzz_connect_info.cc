// libFuzzer target: ConnectInfo decoding (spec §3.5). Input: the base64url text.
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

#include "glassy/proto/connect_info.h"

using namespace glassy::proto;

namespace {

void require(bool ok) {
  if (!ok) __builtin_trap();
}

template <size_t N, size_t M>
void require_strings(const std::array<FixedString<N>, M>& a, uint8_t count) {
  require(count >= 1 && count <= M);
  for (size_t i = 0; i < count; ++i) require(a[i].len >= 1 && a[i].len <= N);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const std::string_view text(reinterpret_cast<const char*>(data), size);
  static auto* ci = new ConnectInfo;
  static auto* scratch = new std::vector<uint8_t>(kConnectInfoScratchMin);

  auto r = decode_connect_info(text, *ci, *scratch);
  if (!r.ok()) {
    require(!ci->has_native && !ci->has_webrtc && !ci->has_webtransport);
    return 0;
  }
  require(ci->has_native || ci->has_webrtc || ci->has_webtransport);
  if (ci->has_native) {
    require_strings(ci->native.gateways, ci->native.gateway_count);
    require(ci->native.server_ticket_len <= ci->native.server_ticket.size());
  }
  if (ci->has_webrtc) {
    require_strings(ci->webrtc.candidates, ci->webrtc.candidate_count);
    require(ci->webrtc.server_ticket_len <= ci->webrtc.server_ticket.size());
    require(ci->webrtc.dtls_fingerprint.len <= 128);
  }
  if (ci->has_webtransport) require(ci->webtransport.url.len <= 1024);
  return 0;
}
