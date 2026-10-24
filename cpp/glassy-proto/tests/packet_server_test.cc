#include <gtest/gtest.h>

#include <array>
#include <string>
#include <vector>

#include "glassy/proto/packet.h"
#include "glassy/proto/server_ticket.h"
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

}  // namespace

// verify_connect / build_accept / build_reject; the rest of the file runs in packet_core_test.cc.
TEST(PacketsServer, Vectors) {
  const auto file = load_vectors("native_packets.json");
  ServerKeyRing ring;
  ASSERT_TRUE(ring.insert(1, Key32{[] {
                            Key32 k;
                            k.fill(0x22);
                            return k;
                          }()})
                  .ok());
  size_t ran = 0;
  for (const auto& c : file["cases"]) {
    const std::string packet = c["packet"];
    const std::string op = c["op"];
    const std::string name = c["name"];
    SCOPED_TRACE(name);
    if (packet == "connect" && op == "verify") {
      auto r = verify_connect(hex(c["packet_hex"].get<std::string>()), ring,
                              arr<16>(c, "self_server_id_hex"), c["now"].get<uint32_t>());
      if (c.contains("error")) {
        ASSERT_FALSE(r.ok());
        EXPECT_STREQ(error_code(r.error()), c["error"].get<std::string>().c_str());
      } else {
        ASSERT_TRUE(r.ok()) << error_code(r.error());
        const auto& e = c["expect"];
        const auto& v = r.value();
        EXPECT_EQ(to_hex(v.session_id), e["session_id_hex"].get<std::string>());
        EXPECT_EQ(to_hex(v.conn_id), e["conn_id_hex"].get<std::string>());
        EXPECT_EQ(v.connect_seq, e["connect_seq"].get<uint64_t>());
        EXPECT_EQ(std::string(v.ticket.user_id.data(), v.ticket.user_id_len),
                  e["user_id"].get<std::string>());
      }
    } else if (packet == "accept" && op == "build") {
      const Accept a{arr<8>(c, "session_id_hex"), c["connect_seq"].get<uint64_t>(),
                     arr<16>(c, "server_nonce_hex"), c["resumed"].get<bool>(),
                     c["server_time_ms"].get<uint64_t>()};
      const auto b = build_accept(a, arr<16>(c, "conn_id_hex"), arr<32>(c, "key_s2c_hex"));
      EXPECT_EQ(to_hex(b), c["expect"]["bytes_hex"].get<std::string>());
    } else if (packet == "reject" && op == "build") {
      const Reject x{arr<8>(c, "session_id_hex"), c["connect_seq"].get<uint64_t>(),
                     arr<16>(c, "server_nonce_hex"), c["reason"].get<uint8_t>(),
                     c["last_connect_seq"].get<uint64_t>()};
      const auto b = build_reject(x, arr<16>(c, "conn_id_hex"), arr<32>(c, "key_s2c_hex"));
      EXPECT_EQ(to_hex(b), c["expect"]["bytes_hex"].get<std::string>());
    } else {
      continue;
    }
    ++ran;
  }
  EXPECT_EQ(ran, 12u);
}
