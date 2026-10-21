#include "h3_codec.hpp"

#include <gtest/gtest.h>

#include <string>

#include "test_util.hpp"

namespace {

void append_str(std::vector<uint8_t>& out, const std::string& s) {
  out.insert(out.end(), s.begin(), s.end());
}

}  // namespace

TEST(Varint, Rfc9000Examples) {
  // RFC 9000 Appendix A.1.
  EXPECT_EQ(glassy::varint_decode(unhex("c2197c5eff14e88c"))->first, 151288809941952652ull);
  EXPECT_EQ(glassy::varint_decode(unhex("9d7f3e7d"))->first, 494878333ull);
  EXPECT_EQ(glassy::varint_decode(unhex("7bbd"))->first, 15293ull);
  EXPECT_EQ(glassy::varint_decode(unhex("25"))->first, 37ull);
  EXPECT_FALSE(glassy::varint_decode(unhex("7b")));  // truncated two-byte varint
}

TEST(Varint, EncodeShortestForm) {
  uint8_t buf[8];
  EXPECT_EQ(glassy::varint_encode(37, buf), 1u);
  EXPECT_EQ(glassy::varint_encode(15293, buf), 2u);
  EXPECT_EQ(std::vector<uint8_t>(buf, buf + 2), unhex("7bbd"));
}

TEST(Settings, Roundtrip) {
  auto f = glassy::encode_settings_frame(glassy::kServerSettings);
  ASSERT_GE(f.size(), 2u);
  EXPECT_EQ(f[0], 0x04);
  auto len = glassy::varint_decode(std::span(f).subspan(1));
  ASSERT_TRUE(len);
  EXPECT_EQ(1 + len->second + len->first, f.size());
  EXPECT_EQ(glassy::decode_settings_payload(std::span(f).subspan(1 + len->second)),
            glassy::kServerSettings);
}

TEST(Qpack, StaticAndLiteral) {
  // Hand-built field section, no Huffman (RFC 9204 §4.5, static table in Appendix A).
  std::vector<uint8_t> block{0x00, 0x00};  // Required Insert Count 0, Base 0
  block.push_back(0xcf);                   // indexed static 15  :method CONNECT
  block.push_back(0xd7);                   // indexed static 23  :scheme https
  block.push_back(0x50);                   // literal, static name ref 0  :authority
  block.push_back(0x09);
  append_str(block, "x.wt.test");
  block.push_back(0x51);  // literal, static name ref 1  :path
  block.push_back(0x07);
  append_str(block, "/glassy");
  block.push_back(0x27);  // literal name, 3-bit length prefix saturated (7) ...
  block.push_back(0x02);  // ... plus 2 = 9 = strlen(":protocol")
  append_str(block, ":protocol");
  block.push_back(0x0c);
  append_str(block, "webtransport");

  auto h = glassy::qpack_decode_request(block);
  ASSERT_TRUE(h);
  EXPECT_EQ((*h)[":method"], "CONNECT");
  EXPECT_EQ((*h)[":scheme"], "https");
  EXPECT_EQ((*h)[":protocol"], "webtransport");
  EXPECT_EQ((*h)[":path"], "/glassy");
  EXPECT_EQ((*h)[":authority"], "x.wt.test");
}

TEST(Qpack, RejectsDynamicTableReference) {
  // Required Insert Count 1 needs a dynamic table, which this server never allows.
  EXPECT_FALSE(glassy::qpack_decode_request(unhex("0200c0")));
}

TEST(Response, Starts200) {
  auto r = glassy::encode_response_headers();
  EXPECT_EQ(std::vector<uint8_t>(r.begin(), r.begin() + 3), (std::vector<uint8_t>{0x00, 0x00, 0xd9}));
  // The response must itself decode as a valid field section.
  auto h = glassy::qpack_decode_request(r);
  ASSERT_TRUE(h);
  EXPECT_EQ((*h)[":status"], "200");
  EXPECT_EQ((*h)["sec-webtransport-http3-draft"], "draft02");
}
