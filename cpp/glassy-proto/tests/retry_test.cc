#include "glassy/proto/retry.h"

#include <gtest/gtest.h>

#include <set>
#include <string>

#include "glassy/proto/trailer.h"
#include "vectors.h"

using namespace glassy::proto;

// C++ only parses (the gateway validates the tag), so tag/expiry cases are skipped and the
// structural error cases run in parse mode whatever their `mode` says.
TEST(Retry, ParseVectors) {
  const auto file = load_vectors("retry_token.json");
  const std::set<std::string> structural = {"bad_length", "bad_token_type", "bad_odcil"};
  size_t ran = 0;
  for (const auto& c : file["cases"]) {
    const std::string name = c["name"];
    SCOPED_TRACE(name);
    const auto token = hex(c["token_hex"].get<std::string>());
    auto r = retry_token_odcid(token);
    if (c.contains("error")) {
      const std::string code = c["error"];
      if (!structural.count(code)) continue;  // auth_failed / expired come from the tag check
      ASSERT_FALSE(r.ok());
      EXPECT_STREQ(error_code(r.error()), code.c_str());
    } else {
      ASSERT_TRUE(r.ok()) << error_code(r.error());
      EXPECT_EQ(to_hex(r.value()), c["expect"]["odcid_hex"].get<std::string>());
    }
    ++ran;
  }
  EXPECT_EQ(ran, 9u);
}

TEST(Trailer, SplitVectors) {
  const auto file = load_vectors("native_packets.json");
  size_t ran = 0;
  for (const auto& c : file["cases"]) {
    if (c["op"] != "split_trailer") continue;
    const std::string name = c["name"];
    SCOPED_TRACE(name);
    const auto pkt = hex(c["packet_hex"].get<std::string>());
    auto r = split_trailer(pkt);
    if (c.contains("error")) {
      ASSERT_FALSE(r.ok());
      EXPECT_STREQ(error_code(r.error()), c["error"].get<std::string>().c_str());
    } else {
      ASSERT_TRUE(r.ok()) << error_code(r.error());
      const auto& e = c["expect"];
      EXPECT_EQ(to_hex(r.value().payload), e["body_hex"].get<std::string>());
      EXPECT_EQ(to_hex(r.value().addr.ip), e["ip_hex"].get<std::string>());
      EXPECT_EQ(r.value().addr.port, e["port"].get<uint16_t>());
    }
    ++ran;
  }
  EXPECT_GE(ran, 3u);
}
