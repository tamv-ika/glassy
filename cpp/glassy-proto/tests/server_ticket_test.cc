#include "glassy/proto/server_ticket.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>

#include "vectors.h"

using namespace glassy::proto;

namespace {

template <size_t N>
std::array<uint8_t, N> arr(const std::string& hex_str) {
  auto v = hex(hex_str);
  EXPECT_EQ(v.size(), N);
  std::array<uint8_t, N> a{};
  std::copy_n(v.begin(), std::min(N, v.size()), a.begin());
  return a;
}

void fill_fixed_ring(ServerKeyRing& ring) {
  Key32 k_gs;
  k_gs.fill(0x22);
  ASSERT_TRUE(ring.insert(1, k_gs).ok());
}

}  // namespace

TEST(ServerTicket, Vectors) {
  const auto file = load_vectors("server_ticket.json");
  ServerKeyRing ring;
  fill_fixed_ring(ring);
  for (const auto& c : file["cases"]) {
    const std::string name = c["name"];
    SCOPED_TRACE(name);
    const auto ticket = hex(c["ticket_hex"].get<std::string>());
    auto r = open_server_ticket(ticket, ring, c["now"].get<uint32_t>(),
                                arr<16>(c["self_server_id_hex"].get<std::string>()),
                                c["via"].get<uint8_t>());
    if (c.contains("error")) {
      ASSERT_FALSE(r.ok());
      EXPECT_STREQ(error_code(r.error()), c["error"].get<std::string>().c_str());
      continue;
    }
    ASSERT_TRUE(r.ok()) << error_code(r.error());
    const auto& t = r.value();
    const auto& e = c["expect"];
    EXPECT_EQ(std::string(t.user_id.data(), t.user_id_len), e["user_id"].get<std::string>());
    EXPECT_EQ(to_hex(t.server_id), e["server_id_hex"].get<std::string>());
    EXPECT_EQ(to_hex(t.session_id), e["session_id_hex"].get<std::string>());
    EXPECT_EQ(t.expiry, e["expiry"].get<uint32_t>());
    EXPECT_EQ(t.transport, e["transport"].get<uint8_t>());
    EXPECT_EQ(t.has_native_keys, e.contains("key_c2s_hex"));
    if (t.has_native_keys) {
      EXPECT_EQ(to_hex(t.key_c2s), e["key_c2s_hex"].get<std::string>());
      EXPECT_EQ(to_hex(t.key_s2c), e["key_s2c_hex"].get<std::string>());
    }
    EXPECT_EQ(to_hex(std::span<const uint8_t>(t.metadata.data(), t.metadata_len)),
              e["metadata_hex"].get<std::string>());
  }
}

TEST(ServerTicket, KeyRingCapsAt16) {
  ServerKeyRing ring;
  Key32 k{};
  for (uint8_t id = 0; id < 16; ++id) {
    k[0] = id;
    EXPECT_TRUE(ring.insert(id, k).ok()) << int(id);
  }
  auto full = ring.insert(16, k);
  ASSERT_FALSE(full.ok());
  EXPECT_EQ(full.error(), Error::kTooLarge);
  // Replacing an existing id is still allowed when the ring is full.
  EXPECT_TRUE(ring.insert(3, k).ok());
}

TEST(ServerTicket, Utf8FollowsRfc3629) {
  EXPECT_TRUE(is_valid_utf8(std::span<const uint8_t>()));
  const uint8_t ok[] = {'a', 0xc3, 0xa9, 0xe2, 0x82, 0xac, 0xf0, 0x9f, 0x98, 0x80};
  EXPECT_TRUE(is_valid_utf8(ok));
  const uint8_t overlong2[] = {0xc0, 0x80};
  const uint8_t overlong3[] = {0xe0, 0x80, 0x80};
  const uint8_t surrogate[] = {0xed, 0xa0, 0x80};
  const uint8_t too_big[] = {0xf4, 0x90, 0x80, 0x80};
  const uint8_t overlong4[] = {0xf0, 0x80, 0x80, 0x80};
  const uint8_t truncated[] = {0xe2, 0x82};
  const uint8_t stray_cont[] = {0x80};
  const uint8_t f5[] = {0xf5, 0x80, 0x80, 0x80};
  EXPECT_FALSE(is_valid_utf8(overlong2));
  EXPECT_FALSE(is_valid_utf8(overlong3));
  EXPECT_FALSE(is_valid_utf8(surrogate));
  EXPECT_FALSE(is_valid_utf8(too_big));
  EXPECT_FALSE(is_valid_utf8(overlong4));
  EXPECT_FALSE(is_valid_utf8(truncated));
  EXPECT_FALSE(is_valid_utf8(stray_cont));
  EXPECT_FALSE(is_valid_utf8(f5));
}
