#include "retry_token.hpp"

#include <gtest/gtest.h>

#include "test_util.hpp"

TEST(RetryToken, RustVector) {
  auto v = load_json(GLASSY_VECTORS_DIR "/retry_token.json");
  EXPECT_EQ(glassy::parse_nss_token(unhex(v["token_hex"])), unhex(v["odcid_hex"]));
}

TEST(RetryToken, Rejects) {
  auto t = unhex("088394c8f03e51570800000000773594008fc3943538d3f2736f399447bed2acdd");
  auto new_token_type = t;
  new_token_type[0] |= 0x80;
  EXPECT_FALSE(glassy::parse_nss_token(new_token_type));
  auto short_odcid = t;
  short_odcid[0] = 7;
  EXPECT_FALSE(glassy::parse_nss_token(short_odcid));
  EXPECT_FALSE(glassy::parse_nss_token(std::span(t).first(5)));
}
