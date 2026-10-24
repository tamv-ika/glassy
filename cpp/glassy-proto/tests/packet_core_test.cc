#include <gtest/gtest.h>

#include <array>
#include <set>
#include <string>
#include <vector>

#include "glassy/proto/packet.h"
#include "glassy/proto/pn.h"
#include "vectors.h"

using namespace glassy::proto;

namespace {

template <size_t N>
std::array<uint8_t, N> arr(const nlohmann::json& c, const char* key) {
  const auto v = hex(c[key].get<std::string>());
  EXPECT_EQ(v.size(), N) << key;
  std::array<uint8_t, N> out{};
  for (size_t i = 0; i < N && i < v.size(); ++i) out[i] = v[i];
  return out;
}

std::vector<uint8_t> bytes(const nlohmann::json& c, const char* key) {
  return hex(c[key].get<std::string>());
}

// Compares a result against the case's `error` code; returns true when the case expected one.
template <class T>
bool expect_error(const nlohmann::json& c, const Result<T>& r) {
  if (!c.contains("error")) {
    EXPECT_TRUE(r.ok()) << error_code(r.error());
    return false;
  }
  EXPECT_FALSE(r.ok());
  EXPECT_STREQ(error_code(r.error()), c["error"].get<std::string>().c_str());
  return true;
}

}  // namespace

// Core ops only; verify_connect / build_accept / build_reject run in packet_server_test.cc and
// split_trailer in retry_test.cc.
TEST(PacketsCore, Vectors) {
  const auto file = load_vectors("native_packets.json");
  const std::set<std::string> elsewhere = {"connect/verify", "accept/build", "reject/build",
                                           "connect/split_trailer"};
  size_t ran = 0;
  size_t total = 0;
  for (const auto& c : file["cases"]) {
    ++total;
    const std::string packet = c["packet"];
    const std::string op = c["op"];
    const std::string name = c["name"];
    SCOPED_TRACE(name);
    if (elsewhere.count(packet + "/" + op)) continue;
    const auto& e = c.contains("expect") ? c["expect"] : c;

    if (packet == "connect" && op == "build") {
      const auto routing = bytes(c, "routing_ticket_hex");
      const auto ticket = bytes(c, "server_ticket_hex");
      ASSERT_EQ(routing.size(), 60u);
      const ConnectParams p{arr<8>(c, "session_id_hex"),
                            arr<16>(c, "conn_id_hex"),
                            c["connect_seq"].get<uint64_t>(),
                            routing,
                            ticket,
                            arr<32>(c, "key_c2s_hex"),
                            c["pad_to"].get<size_t>()};
      std::array<uint8_t, 1300> out{};
      auto r = build_connect(p, out);
      if (!expect_error(c, r)) {
        EXPECT_EQ(to_hex(std::span(out).first(r.value())), e["bytes_hex"].get<std::string>());
      }
    } else if (packet == "connect" && op == "parse") {
      auto r = parse_connect(bytes(c, "packet_hex"));
      if (!expect_error(c, r)) {
        const auto& v = r.value();
        EXPECT_EQ(to_hex(v.session_id), e["session_id_hex"].get<std::string>());
        EXPECT_EQ(to_hex(v.conn_id), e["conn_id_hex"].get<std::string>());
        EXPECT_EQ(v.connect_seq, e["connect_seq"].get<uint64_t>());
        EXPECT_EQ(to_hex(v.routing_ticket), e["routing_ticket_hex"].get<std::string>());
        EXPECT_EQ(to_hex(v.server_ticket), e["server_ticket_hex"].get<std::string>());
        EXPECT_EQ(to_hex(v.proof_tag), e["proof_tag_hex"].get<std::string>());
        EXPECT_EQ(v.padding.size(), e["padding_len"].get<size_t>());
      }
    } else if ((packet == "accept" || packet == "reject") && op == "peek") {
      auto r = peek_reply(bytes(c, "packet_hex"));
      if (!expect_error(c, r)) {
        EXPECT_EQ(r.value().type, e["type"].get<uint8_t>());
        EXPECT_EQ(to_hex(r.value().session_id), e["session_id_hex"].get<std::string>());
        EXPECT_EQ(r.value().connect_seq, e["connect_seq"].get<uint64_t>());
      }
    } else if (packet == "accept" && op == "open") {
      auto r =
          open_accept(bytes(c, "packet_hex"), arr<16>(c, "conn_id_hex"), arr<32>(c, "key_s2c_hex"));
      if (!expect_error(c, r)) {
        const auto& a = r.value();
        EXPECT_EQ(to_hex(a.session_id), e["session_id_hex"].get<std::string>());
        EXPECT_EQ(a.connect_seq, e["connect_seq"].get<uint64_t>());
        EXPECT_EQ(to_hex(a.server_nonce), e["server_nonce_hex"].get<std::string>());
        EXPECT_EQ(a.resumed, e["resumed"].get<bool>());
        EXPECT_EQ(a.server_time_ms, e["server_time_ms"].get<uint64_t>());
      }
    } else if (packet == "reject" && op == "open") {
      auto r =
          open_reject(bytes(c, "packet_hex"), arr<16>(c, "conn_id_hex"), arr<32>(c, "key_s2c_hex"));
      if (!expect_error(c, r)) {
        const auto& x = r.value();
        EXPECT_EQ(to_hex(x.session_id), e["session_id_hex"].get<std::string>());
        EXPECT_EQ(x.connect_seq, e["connect_seq"].get<uint64_t>());
        EXPECT_EQ(to_hex(x.server_nonce), e["server_nonce_hex"].get<std::string>());
        EXPECT_EQ(x.reason, e["reason"].get<uint8_t>());
        EXPECT_EQ(x.last_connect_seq, e["last_connect_seq"].get<uint64_t>());
      }
    } else if (packet == "data" && op == "seal") {
      const auto frames = bytes(c, "frames_hex");
      std::array<uint8_t, 1300> out{};
      auto r = seal_data(arr<32>(c, "key_hex"), arr<16>(c, "server_nonce_hex"),
                         arr<8>(c, "session_id_hex"), c["pn"].get<uint64_t>(), frames, out);
      if (!expect_error(c, r)) {
        EXPECT_EQ(to_hex(std::span(out).first(r.value())), e["bytes_hex"].get<std::string>());
      }
    } else if (packet == "data" && op == "open") {
      std::array<uint8_t, 1300> out{};
      auto r = open_data(arr<32>(c, "key_hex"), arr<16>(c, "server_nonce_hex"),
                         bytes(c, "packet_hex"), c["pn"].get<uint64_t>(), out);
      if (!expect_error(c, r)) {
        EXPECT_EQ(to_hex(std::span(out).first(r.value())), e["frames_hex"].get<std::string>());
      }
    } else if (packet == "data" && op == "parse_header") {
      auto r = parse_header(bytes(c, "packet_hex"));
      if (!expect_error(c, r)) {
        EXPECT_EQ(r.value().type, e["type"].get<uint8_t>());
        EXPECT_EQ(to_hex(r.value().session_id), e["session_id_hex"].get<std::string>());
        EXPECT_EQ(r.value().pn_low, e["pn_low"].get<uint32_t>());
      }
    } else if (packet == "disconnect" && op == "seal") {
      auto r = seal_disconnect(arr<32>(c, "key_hex"), arr<16>(c, "server_nonce_hex"),
                               arr<8>(c, "session_id_hex"), c["pn"].get<uint64_t>(),
                               c["reason"].get<uint8_t>());
      if (!expect_error(c, r)) {
        EXPECT_EQ(to_hex(r.value()), e["bytes_hex"].get<std::string>());
      }
    } else if (packet == "disconnect" && op == "open") {
      auto r = open_disconnect(arr<32>(c, "key_hex"), arr<16>(c, "server_nonce_hex"),
                               bytes(c, "packet_hex"), c["pn"].get<uint64_t>());
      if (!expect_error(c, r)) {
        EXPECT_EQ(r.value(), e["reason"].get<uint8_t>());
      }
    } else if (packet == "pn" && op == "decode_pn") {
      EXPECT_EQ(decode_pn(c["largest"].get<uint64_t>(), c["low"].get<uint32_t>()),
                e["pn"].get<uint64_t>());
    } else if (packet == "replay" && op == "window") {
      ReplayWindow w;
      for (const auto& pn : c["commits"]) w.commit(pn.get<uint64_t>());
      const Status s = w.check(c["check"].get<uint64_t>());
      expect_error(c, s);
    } else {
      FAIL() << "unsupported case " << packet << "/" << op;
    }
    ++ran;
  }
  EXPECT_EQ(total, 78u);
  EXPECT_EQ(ran, 62u);
}

TEST(PacketsCore, SealDataOutTooSmall) {
  const Key32 key{};
  const std::array<uint8_t, 16> nonce{};
  const std::array<uint8_t, 8> sid{};
  const std::array<uint8_t, 3> frames{1, 2, 3};
  std::array<uint8_t, 32> out{};
  // 13 header + 3 frames + 16 tag = 32 fits exactly; one byte less does not.
  auto ok = seal_data(key, nonce, sid, 1, frames, out);
  ASSERT_TRUE(ok.ok());
  EXPECT_EQ(ok.value(), 32u);
  auto small = seal_data(key, nonce, sid, 1, frames, std::span(out).first(31));
  ASSERT_FALSE(small.ok());
  EXPECT_EQ(small.error(), Error::kBufferTooSmall);
}

TEST(PacketsCore, SealDataCheckOrder) {
  const Key32 key{};
  const std::array<uint8_t, 16> nonce{};
  const std::array<uint8_t, 8> sid{};
  std::vector<uint8_t> big(1172);
  std::array<uint8_t, 1300> out{};
  // TooLarge wins over the pn 0 check.
  EXPECT_EQ(seal_data(key, nonce, sid, 0, big, out).error(), Error::kTooLarge);
  EXPECT_EQ(seal_data(key, nonce, sid, 0, std::span(big).first(1), out).error(), Error::kReplayed);
}

TEST(PacketsCore, BuildConnectOutTooSmall) {
  const std::vector<uint8_t> routing(60), ticket(139);
  ConnectParams p{{}, {}, 1, routing, ticket, {}, 0};
  std::array<uint8_t, 251> out{};
  auto r = build_connect(p, out);
  ASSERT_TRUE(r.ok());
  EXPECT_EQ(r.value(), 251u);
  EXPECT_EQ(build_connect(p, std::span(out).first(250)).error(), Error::kBufferTooSmall);
}
