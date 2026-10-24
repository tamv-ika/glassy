#ifndef GLASSY_PROTO_CONNECT_INFO_H_
#define GLASSY_PROTO_CONNECT_INFO_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "glassy/proto/result.h"

namespace glassy::proto {

// Inline string storage so the decoder never allocates; `len` bytes of `data` are used.
template <size_t N>
struct FixedString {
  std::array<char, N> data{};
  uint16_t len = 0;

  std::string_view view() const { return std::string_view(data.data(), len); }
};

inline constexpr size_t kConnectInfoMaxAddrs = 4;
inline constexpr size_t kConnectInfoMaxAddrLen = 64;
inline constexpr size_t kConnectInfoNativeTicketMax = 458;
inline constexpr size_t kConnectInfoBrowserTicketMax = 394;
// decode_connect_info() needs this much scratch space for the decoded JSON.
inline constexpr size_t kConnectInfoScratchMin = 4096;

// Native UDP endpoint data (spec §3.5); same fields as the Rust `NativeInfo`.
struct NativeInfo {
  std::array<FixedString<kConnectInfoMaxAddrLen>, kConnectInfoMaxAddrs> gateways{};
  uint8_t gateway_count = 0;
  std::array<uint8_t, 60> routing_ticket{};  // spec §3.1
  std::array<uint8_t, kConnectInfoNativeTicketMax> server_ticket{};
  uint16_t server_ticket_len = 0;
  std::array<uint8_t, 32> key_c2s{};
  std::array<uint8_t, 32> key_s2c{};
};

// WebRTC endpoint data (spec §3.5); same fields as the Rust `WebRtcInfo`.
struct WebRtcInfo {
  std::array<FixedString<kConnectInfoMaxAddrLen>, kConnectInfoMaxAddrs> candidates{};
  uint8_t candidate_count = 0;
  FixedString<80> ice_ufrag{};
  FixedString<43> ice_pwd{};
  FixedString<128> dtls_fingerprint{};
  std::array<uint8_t, kConnectInfoBrowserTicketMax> server_ticket{};
  uint16_t server_ticket_len = 0;
};

// WebTransport endpoint data (spec §3.5); same fields as the Rust `WtInfo`.
struct WtInfo {
  FixedString<1024> url{};
  std::array<uint8_t, 32> cert_sha256{};
};

// Decoded connect-info document (spec §3.5). A block is meaningful only when its has_* flag is
// set; the flags are all false after a failed decode.
struct ConnectInfo {
  std::array<uint8_t, 8> session_id{};
  uint32_t expiry = 0;
  bool has_native = false;
  bool has_webrtc = false;
  bool has_webtransport = false;
  NativeInfo native{};
  WebRtcInfo webrtc{};
  WtInfo webtransport{};
};

// Decodes base64url(JSON) connect-info into `out` without heap allocation; the JSON is decoded
// into `scratch`, which must hold kConnectInfoScratchMin bytes (else kBufferTooSmall, checked
// first). Applies the decode rules of crates/glassy-proto/src/connect_info.rs in the same order
// and with the same error codes:
//  1. base64url text over 5462 chars -> kTooLarge; bad base64url -> kBadEncoding; JSON over
//     4096 bytes -> kTooLarge.
//  2. `{`/`[` nesting (outside strings) deeper than 8 -> kBadJson.
//  3. Invalid UTF-8 anywhere, or not exactly one RFC 8259 JSON object -> kBadJson.
//  4. Top-level `v`: missing, duplicated or not an integer token -> kBadJson; another integer
//     -> kBadVersion. Judged before any other field.
//  5. Known fields: duplicate, wrong type or an escape in a string value -> kBadJson; keys with
//     an escape never match a known name. Unknown keys and values are ignored.
//  6. Missing `session_id`/`expiry`, no transport block, or a block missing a field -> kBadJson.
//  7. Values in fixed order: session_id, native, webrtc, webtransport.
Status decode_connect_info(std::string_view b64, ConnectInfo& out, std::span<uint8_t> scratch);

}  // namespace glassy::proto

#endif  // GLASSY_PROTO_CONNECT_INFO_H_
