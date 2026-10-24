// Truncation sweep (C++ counterpart of crates/glassy-proto/tests/robustness.rs): every proper
// prefix of every valid vector input must be rejected, or at least must not crash for formats
// whose prefixes can legitimately decode. Meant to run under ASan/UBSan (GLASSY_PROTO_SANITIZE).
#include <gtest/gtest.h>

#include <array>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "glassy/proto/connect_info.h"
#include "glassy/proto/frame.h"
#include "glassy/proto/message.h"
#include "glassy/proto/packet.h"
#include "glassy/proto/retry.h"
#include "glassy/proto/server_ticket.h"
#include "glassy/proto/trailer.h"
#include "glassy/proto/wt.h"
#include "vectors.h"

using namespace glassy::proto;

namespace {

using Bytes = std::vector<uint8_t>;
// Returns true when the parser accepted the input.
using Accepts = std::function<bool(std::span<const uint8_t>)>;

std::vector<nlohmann::json> valid_cases(std::string_view file) {
  std::vector<nlohmann::json> out;
  const auto vectors = load_vectors(file);  // keep alive: the loop borrows from it
  for (const auto& c : vectors["cases"]) {
    if (!c.contains("error")) out.push_back(c);
  }
  return out;
}

Bytes hex_of(const nlohmann::json& c, const char* key) { return hex(c[key].get<std::string>()); }

template <size_t N>
std::array<uint8_t, N> arr(const nlohmann::json& c, const char* key) {
  const Bytes v = hex_of(c, key);
  EXPECT_EQ(v.size(), N) << key;
  std::array<uint8_t, N> out{};
  for (size_t i = 0; i < N && i < v.size(); ++i) out[i] = v[i];
  return out;
}

std::span<const uint8_t> prefix(const Bytes& b, size_t k) {
  return std::span<const uint8_t>(b.data(), k);
}

// Every proper prefix must be rejected; with `extend`, input + 0x00 as well.
void sweep(const std::string& name, const Bytes& input, bool extend, const Accepts& accepts) {
  ASSERT_TRUE(accepts(input)) << name << ": the full input must be accepted";
  for (size_t k = 0; k < input.size(); ++k) {
    EXPECT_FALSE(accepts(prefix(input, k))) << name << ": prefix of " << k << " bytes accepted";
  }
  if (extend) {
    Bytes longer = input;
    longer.push_back(0x00);
    EXPECT_FALSE(accepts(longer)) << name << ": input + 0x00 accepted";
  }
}

// CONNECT: trailing 0x00 bytes are padding, so a prefix that keeps every non-zero byte may be
// accepted and no extension check applies.
void sweep_padded(const std::string& name, const Bytes& input, const Accepts& accepts) {
  size_t significant = 0;
  for (size_t i = input.size(); i > 0; --i) {
    if (input[i - 1] != 0) {
      significant = i;
      break;
    }
  }
  ASSERT_TRUE(accepts(input)) << name << ": the full input must be accepted";
  for (size_t k = 0; k < significant; ++k) {
    EXPECT_FALSE(accepts(prefix(input, k))) << name << ": prefix of " << k << " bytes accepted";
  }
}

// Formats where a prefix can be valid: only checks that nothing crashes.
void sweep_no_crash(const Bytes& input, const Accepts& accepts) {
  for (size_t k = 0; k <= input.size(); ++k) (void)accepts(prefix(input, k));
  Bytes longer = input;
  longer.push_back(0x00);
  (void)accepts(longer);
}

}  // namespace

TEST(Robustness, EveryPrefixIsRejectedNativePacketsCore) {
  size_t ran = 0;
  for (const auto& c : valid_cases("native_packets.json")) {
    const std::string name = c["name"];
    const std::string packet = c["packet"];
    const std::string op = c["op"];
    SCOPED_TRACE(name);
    const Bytes pkt = c.contains("packet_hex") ? hex_of(c, "packet_hex") : Bytes{};
    if (packet == "connect" && op == "parse") {
      sweep_padded(name, pkt, [](auto b) { return parse_connect(b).ok(); });
#ifdef GLASSY_PROTO_HAS_SERVER
    } else if (packet == "connect" && op == "split_trailer") {
      sweep(name, pkt, false, [](auto b) { return split_trailer(b).ok(); });
#endif
    } else if ((packet == "accept" || packet == "reject") && op == "peek") {
      // Extension is checked too: the reply header has an exact length per type.
      sweep(name, pkt, true, [](auto b) { return peek_reply(b).ok(); });
    } else if (packet == "accept" && op == "open") {
      const auto conn = arr<16>(c, "conn_id_hex");
      const auto key = arr<32>(c, "key_s2c_hex");
      sweep(name, pkt, true, [&](auto b) { return open_accept(b, conn, key).ok(); });
    } else if (packet == "reject" && op == "open") {
      const auto conn = arr<16>(c, "conn_id_hex");
      const auto key = arr<32>(c, "key_s2c_hex");
      sweep(name, pkt, true, [&](auto b) { return open_reject(b, conn, key).ok(); });
    } else if (packet == "data" && op == "open") {
      const auto key = arr<32>(c, "key_hex");
      const auto nonce = arr<16>(c, "server_nonce_hex");
      const uint64_t pn = c["pn"].get<uint64_t>();
      std::array<uint8_t, 1200> out{};
      sweep(name, pkt, false, [&](auto b) { return open_data(key, nonce, b, pn, out).ok(); });
    } else if (packet == "disconnect" && op == "open") {
      const auto key = arr<32>(c, "key_hex");
      const auto nonce = arr<16>(c, "server_nonce_hex");
      const uint64_t pn = c["pn"].get<uint64_t>();
      sweep(name, pkt, true, [&](auto b) { return open_disconnect(key, nonce, b, pn).ok(); });
    } else if (packet == "data" && op == "parse_header") {
      // A header is a prefix of the packet, so longer inputs are valid; but every input shorter
      // than the minimum data packet (13 header + 16 tag) must be rejected.
      sweep_no_crash(pkt, [](auto b) { return parse_header(b).ok(); });
      for (size_t k = 0; k < kDataMin; ++k) {
        EXPECT_FALSE(parse_header(prefix(pkt, std::min(k, pkt.size()))).ok()) << k;
      }
    } else {
      continue;  // builders and pn/replay logic take no wire bytes
    }
    ++ran;
  }
  EXPECT_GT(ran, 0u);
}

TEST(Robustness, EveryPrefixIsRejectedConnectInfo) {
  auto ci = std::make_unique<ConnectInfo>();
  Bytes scratch(kConnectInfoScratchMin);
  for (const auto& c : valid_cases("connect_info.json")) {
    const std::string name = c["name"];
    SCOPED_TRACE(name);
    std::string input;
    ASSERT_NE(c.contains("json"), c.contains("input")) << "need exactly one of json/input";
    if (c.contains("json")) {
      // base64url without padding, as the server emits it.
      static const char kAlpha[] =
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
      const std::string j = c["json"];
      for (size_t i = 0; i < j.size(); i += 3) {
        uint32_t v = 0;
        const size_t n = std::min<size_t>(3, j.size() - i);
        for (size_t k = 0; k < 3; ++k) v = v << 8 | (k < n ? static_cast<uint8_t>(j[i + k]) : 0);
        for (size_t k = 0; k < n + 1; ++k) input.push_back(kAlpha[(v >> (18 - 6 * k)) & 63]);
      }
    } else {
      input = c["input"];
    }
    // Cutting only trailing JSON whitespace leaves a valid document (json cases only).
    size_t significant = SIZE_MAX;
    if (c.contains("json")) {
      const std::string j = c["json"];
      const size_t last = j.find_last_not_of(" \t\r\n");
      significant = last == std::string::npos ? 0 : last + 1;
    }
    ASSERT_TRUE(decode_connect_info(input, *ci, scratch).ok());
    for (size_t k = 0; k < input.size(); ++k) {
      const bool allowed = significant != SIZE_MAX && k * 3 / 4 >= significant;
      if (allowed) continue;
      EXPECT_FALSE(decode_connect_info(std::string_view(input).substr(0, k), *ci, scratch).ok())
          << "prefix of " << k << " chars accepted";
    }
  }
}

TEST(Robustness, EveryPrefixIsRejectedFramesAndStreams) {
  // A prefix cut on a frame boundary is itself a valid frame sequence: only no-crash holds.
  for (const auto& c : valid_cases("frames.json")) {
    sweep_no_crash(hex_of(c, "plaintext_hex"), [](auto b) {
      FrameReader reader(b);
      for (;;) {
        Frame f;
        const auto r = reader.next(f);
        if (!r.ok()) return false;
        if (!r.value()) return true;
      }
    });
  }
  // Prefixes of a message stream decode to fewer messages or need more bytes.
  for (const auto& c : valid_cases("wt_framing.json")) {
    if (c["kind"] != "stream") continue;
    sweep_no_crash(hex_of(c, "stream_hex"), [](auto b) { return decode_message_header(b).ok(); });
  }
}

#ifdef GLASSY_PROTO_HAS_SERVER

TEST(Robustness, EveryPrefixIsRejectedRetryToken) {
  size_t ran = 0;
  for (const auto& c : valid_cases("retry_token.json")) {
    const std::string name = c["name"];
    SCOPED_TRACE(name);
    sweep(name, hex_of(c, "token_hex"), true, [](auto b) { return retry_token_odcid(b).ok(); });
    ++ran;
  }
  EXPECT_GT(ran, 0u);
}

TEST(Robustness, EveryPrefixIsRejectedWtPath) {
  size_t ran = 0;
  for (const auto& c : valid_cases("wt_framing.json")) {
    if (c["kind"] != "path") continue;
    const std::string name = c["name"];
    SCOPED_TRACE(name);
    const std::string path = c["path"];
    const Bytes full = hex_of(c["expect"], "ticket_hex");
    // The ticket is opaque and variable-length, so a prefix may decode to a shorter ticket; it
    // must then be a byte prefix of the original and still pass the minimum-length check.
    for (size_t k = 0; k < path.size(); ++k) {
      std::array<uint8_t, kWtTicketMax> out{};
      const auto r = parse_wt_path(std::string_view(path).substr(0, k), out);
      if (!r.ok()) continue;
      EXPECT_GE(r.value(), kWtTicketMin) << "prefix of " << k << " chars";
      EXPECT_LT(r.value(), full.size()) << "prefix of " << k << " chars";
      ASSERT_LE(r.value(), full.size());
      EXPECT_TRUE(std::equal(out.begin(), out.begin() + r.value(), full.begin()))
          << "prefix of " << k << " chars altered the ticket";
    }
    std::array<uint8_t, kWtTicketMax> out{};
    EXPECT_FALSE(
        parse_wt_path(path.substr(0, std::min(path.size(), kWtPathPrefix.size())), out).ok());
    ++ran;
  }
  EXPECT_GT(ran, 0u);
}

TEST(Robustness, EveryPrefixIsRejectedServerTicketAndVerifyConnect) {
  ServerKeyRing ring;
  Key32 k_gs;
  k_gs.fill(0x22);
  ASSERT_TRUE(ring.insert(1, k_gs).ok());
  for (const auto& c : valid_cases("server_ticket.json")) {
    const std::string name = c["name"];
    SCOPED_TRACE(name);
    const auto sid = arr<16>(c, "self_server_id_hex");
    const uint32_t now = c["now"].get<uint32_t>();
    const uint8_t via = c["via"].get<uint8_t>();
    sweep(name, hex_of(c, "ticket_hex"), true,
          [&](auto b) { return open_server_ticket(b, ring, now, sid, via).ok(); });
  }
  for (const auto& c : valid_cases("native_packets.json")) {
    if (c["packet"] != "connect" || c["op"] != "verify") continue;
    const std::string name = c["name"];
    SCOPED_TRACE(name);
    const auto sid = arr<16>(c, "self_server_id_hex");
    const uint32_t now = c["now"].get<uint32_t>();
    sweep_padded(name, hex_of(c, "packet_hex"),
                 [&](auto b) { return verify_connect(b, ring, now, sid).ok(); });
  }
}

#endif  // GLASSY_PROTO_HAS_SERVER
