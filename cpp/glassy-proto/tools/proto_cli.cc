// Decode CLI for the Rust/C++ differential runner (spec §7, scripts/differential.sh); the C++
// twin of crates/glassy-proto-cli. `glassy_proto_cli <kind>` reads one hex input per stdin line
// and prints one canonical JSON line per input: {"err":"<code>"} or {"ok":<object>}, no
// whitespace, keys in a fixed order, bytes as lowercase hex. Output must match the Rust CLI
// byte for byte.
#include <array>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "glassy/proto/connect_info.h"
#include "glassy/proto/error.h"
#include "glassy/proto/frame.h"
#include "glassy/proto/message.h"
#include "glassy/proto/packet.h"
#include "glassy/proto/retry.h"
#include "glassy/proto/server_ticket.h"
#include "glassy/proto/wt.h"

using namespace glassy::proto;

namespace {

// Fixed server-ticket context, the same values the vectors use.
constexpr uint8_t kGsKeyId = 1;
constexpr uint8_t kGsByte = 0x22;
constexpr uint32_t kNow = 1900000000;
constexpr uint8_t kSelfServerIdByte = 0xab;

using Bytes = std::span<const uint8_t>;

std::string hex(Bytes b) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string s;
  s.reserve(b.size() * 2);
  for (uint8_t v : b) {
    s.push_back(kDigits[v >> 4]);
    s.push_back(kDigits[v & 0x0f]);
  }
  return s;
}

bool unhex(std::string_view s, std::vector<uint8_t>& out) {
  auto nibble = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  if (s.size() % 2 != 0) return false;
  out.clear();
  for (size_t i = 0; i < s.size(); i += 2) {
    const int hi = nibble(s[i]);
    const int lo = nibble(s[i + 1]);
    if (hi < 0 || lo < 0) return false;
    out.push_back(static_cast<uint8_t>(hi << 4 | lo));
  }
  return true;
}

// serde_json's escaping, which the Rust CLI uses: short forms for \b \t \n \f \r, \u00xx
// (lowercase) for other control bytes, everything else (DEL, non-ASCII UTF-8) verbatim.
std::string json_string(std::string_view s) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out = "\"";
  for (char ch : s) {
    const auto c = static_cast<uint8_t>(ch);
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\b':
        out += "\\b";
        break;
      case '\t':
        out += "\\t";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\f':
        out += "\\f";
        break;
      case '\r':
        out += "\\r";
        break;
      default:
        if (c < 0x20) {
          out += "\\u00";
          out.push_back(kDigits[c >> 4]);
          out.push_back(kDigits[c & 0x0f]);
        } else {
          out.push_back(ch);
        }
    }
  }
  out += "\"";
  return out;
}

std::string_view text(Bytes b) {
  return std::string_view(reinterpret_cast<const char*>(b.data()), b.size());
}

std::string err(Error e) { return std::string("{\"err\":\"") + error_code(e) + "\"}"; }
std::string ok(const std::string& object) { return "{\"ok\":" + object + "}"; }

// Field order follows vectors/frames.json (serde_json writes keys sorted).
std::string frames(Bytes b) {
  // All-or-nothing (spec §5.0): validate the whole payload before printing any frame.
  FrameReader reader(b);
  std::string items;
  Frame f;
  for (;;) {
    auto r = reader.next(f);
    if (!r.ok()) return err(r.error());
    if (!r.value()) break;
    if (!items.empty()) items += ",";
    switch (f.type) {
      case FrameType::kAck: {
        char bits[17];
        std::snprintf(bits, sizeof bits, "%016llx",
                      static_cast<unsigned long long>(f.ack.ack_bits));
        items += std::string("{\"ack_bits_hex\":\"") + bits +
                 "\",\"ack_delay\":" + std::to_string(f.ack.ack_delay) +
                 ",\"largest_pn_low\":" + std::to_string(f.ack.largest_pn_low) +
                 ",\"type\":\"ack\"}";
        break;
      }
      case FrameType::kStream:
        items += "{\"data_hex\":\"" + hex(f.data) + "\",\"offset\":" + std::to_string(f.offset) +
                 ",\"type\":\"stream\"}";
        break;
      case FrameType::kDatagram:
        items += "{\"data_hex\":\"" + hex(f.data) + "\",\"type\":\"datagram\"}";
        break;
    }
  }
  return ok("{\"frames\":[" + items + "]}");
}

// Gateway view (spec §4.2): structure only, nothing is authenticated.
std::string connect(Bytes b) {
  auto r = parse_connect(b);
  if (!r.ok()) return err(r.error());
  const ConnectView& v = r.value();
  return ok("{\"session_id\":\"" + hex(v.session_id) + "\",\"conn_id\":\"" + hex(v.conn_id) +
            "\",\"connect_seq\":" + std::to_string(v.connect_seq) +
            ",\"server_ticket_len\":" + std::to_string(v.server_ticket.size()) +
            ",\"padding_len\":" + std::to_string(v.padding.size()) + "}");
}

// Opens with via = native, then WebRTC, then WebTransport; the first success wins. Every check
// before the transport one ignores `via`, so a native failure other than kBadTransport is the
// answer for all three. Same rule as the Rust CLI.
Result<ServerTicket> open_any_via(Bytes b) {
  ServerKeyRing ring;
  Key32 k_gs;
  k_gs.fill(kGsByte);
  if (!ring.insert(kGsKeyId, k_gs).ok()) return Error::kUnknownKey;
  std::array<uint8_t, 16> self;
  self.fill(kSelfServerIdByte);
  auto first = open_server_ticket(b, ring, kNow, self, kTransportNative);
  if (first.ok() || first.error() != Error::kBadTransport) return first;
  for (uint8_t via : {kTransportWebRtc, kTransportWebTransport}) {
    auto r = open_server_ticket(b, ring, kNow, self, via);
    if (r.ok()) return r;
  }
  return Error::kBadTransport;
}

std::string server_ticket(Bytes b) {
  auto r = open_any_via(b);
  if (!r.ok()) return err(r.error());
  const ServerTicket& t = r.value();
  return ok("{\"user_id\":" + json_string(std::string_view(t.user_id.data(), t.user_id_len)) +
            ",\"session_id\":\"" + hex(t.session_id) +
            "\",\"transport\":" + std::to_string(t.transport) +
            ",\"metadata_len\":" + std::to_string(t.metadata_len) + "}");
}

// Game-server parse mode (spec §3.6): no tag or expiry check.
std::string retry_token(Bytes b) {
  auto r = retry_token_odcid(b);
  if (!r.ok()) return err(r.error());
  return ok("{\"odcid\":\"" + hex(r.value()) + "\"}");
}

std::string connect_info(Bytes b) {
  // ConnectInfo holds every block inline (several KB); keep it off the stack.
  auto ci = std::make_unique<ConnectInfo>();
  std::vector<uint8_t> scratch(kConnectInfoScratchMin);
  auto r = decode_connect_info(text(b), *ci, scratch);
  if (!r.ok()) return err(r.error());
  auto flag = [](bool v) { return v ? "true" : "false"; };
  return ok("{\"session_id\":\"" + hex(ci->session_id) +
            "\",\"expiry\":" + std::to_string(ci->expiry) + ",\"native\":" + flag(ci->has_native) +
            ",\"webrtc\":" + flag(ci->has_webrtc) +
            ",\"webtransport\":" + flag(ci->has_webtransport) + "}");
}

// Same split loop as the wt_framing.json generator: stop on an incomplete header or body, and
// any header error fails the whole input.
std::string wt_stream(Bytes b) {
  Bytes rest = b;
  std::string messages;
  for (;;) {
    auto h = decode_message_header(rest);
    if (!h.ok()) return err(h.error());
    if (h.value().need_more) break;
    const size_t header_len = h.value().header_len;
    const size_t len = h.value().len;
    if (rest.size() - header_len < len) break;
    if (!messages.empty()) messages += ",";
    messages += "\"" + hex(rest.subspan(header_len, len)) + "\"";
    rest = rest.subspan(header_len + len);
  }
  return ok("{\"messages\":[" + messages + "],\"remainder\":\"" + hex(rest) + "\"}");
}

std::string wt_path(Bytes b) {
  std::array<uint8_t, kWtTicketMax> ticket;
  auto r = parse_wt_path(text(b), ticket);
  if (!r.ok()) return err(r.error());
  return ok("{\"ticket\":\"" + hex(Bytes(ticket.data(), r.value())) + "\"}");
}

using Decoder = std::string (*)(Bytes);

Decoder decoder(std::string_view kind) {
  if (kind == "frames") return frames;
  if (kind == "connect") return connect;
  if (kind == "server_ticket") return server_ticket;
  if (kind == "retry_token") return retry_token;
  if (kind == "connect_info") return connect_info;
  if (kind == "wt_stream") return wt_stream;
  if (kind == "wt_path") return wt_path;
  return nullptr;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "usage: glassy_proto_cli <kind> < hex-lines\n";
    return 2;
  }
  const Decoder decode = decoder(argv[1]);
  if (decode == nullptr) {
    std::cerr << "error: unknown kind \"" << argv[1] << "\"\n";
    return 2;
  }
  std::ios::sync_with_stdio(false);
  std::string line;
  std::vector<uint8_t> input;
  for (size_t n = 1; std::getline(std::cin, line); ++n) {
    while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
    if (!unhex(line, input)) {
      std::cerr << "error: line " << n << ": bad hex\n";
      return 2;
    }
    std::cout << decode(input) << '\n';
  }
  std::cout.flush();
  return std::cout ? 0 : 1;
}
