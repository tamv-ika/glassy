#include "glassy/proto/message.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "glassy/proto/consts.h"
#include "vectors.h"

using namespace glassy::proto;

namespace {

struct Split {
  Error error = Error::kOk;
  std::vector<std::string> messages_hex;
  std::string remainder_hex;
};

// Mirrors `wf_split` in crates/glassy-proto/tests/vectors.rs: NeedMore stops, a header error
// is final (messages already sliced are discarded), an incomplete payload stops.
Split split(const std::vector<uint8_t>& stream) {
  Split out;
  std::span<const uint8_t> rest(stream);
  for (;;) {
    const auto h = decode_message_header(rest);
    if (!h.ok()) {
      out.error = h.error();
      out.messages_hex.clear();
      return out;
    }
    if (h.value().need_more) break;
    const size_t total = h.value().header_len + h.value().len;
    if (rest.size() < total) break;
    out.messages_hex.push_back(to_hex(rest.subspan(h.value().header_len, h.value().len)));
    rest = rest.subspan(total);
  }
  out.remainder_hex = to_hex(rest);
  return out;
}

}  // namespace

TEST(Message, Vectors) {
  const auto file = load_vectors("wt_framing.json");
  size_t ran = 0;
  for (const auto& c : file["cases"]) {
    if (c["kind"].get<std::string>() != "stream") continue;
    const std::string name = c["name"];
    SCOPED_TRACE(name);
    ++ran;
    const auto got = split(hex(c["stream_hex"].get<std::string>()));
    if (c.contains("error")) {
      EXPECT_STREQ(error_code(got.error), c["error"].get<std::string>().c_str());
      continue;
    }
    ASSERT_EQ(got.error, Error::kOk) << error_code(got.error);
    EXPECT_EQ(nlohmann::json(got.messages_hex), c["expect"]["messages_hex"]);
    EXPECT_EQ(got.remainder_hex, c["expect"]["remainder_hex"].get<std::string>());
  }
  EXPECT_EQ(ran, 8u);
}

TEST(Message, HeaderNeedMore) {
  EXPECT_TRUE(decode_message_header({}).value().need_more);
  const uint8_t a[] = {0x40};
  EXPECT_TRUE(decode_message_header(a).value().need_more);
  const uint8_t b[] = {0x80, 0x04, 0x00};
  EXPECT_TRUE(decode_message_header(b).value().need_more);
  const uint8_t c[] = {0x03, 'a'};
  const auto h = decode_message_header(c);
  ASSERT_TRUE(h.ok());
  EXPECT_FALSE(h.value().need_more);
  EXPECT_EQ(h.value().len, 3u);
  EXPECT_EQ(h.value().header_len, 1u);
}

TEST(Message, MaxMessageBoundary) {
  uint8_t buf[8];
  const auto n = encode_message_header(kMaxMessage, buf);
  ASSERT_TRUE(n.ok());
  ASSERT_EQ(n.value(), 4u);
  EXPECT_EQ(to_hex(std::span<const uint8_t>(buf, 4)), "80040000");
  const auto h = decode_message_header(std::span<const uint8_t>(buf, 4));
  ASSERT_TRUE(h.ok());
  EXPECT_EQ(h.value().len, kMaxMessage);
  EXPECT_EQ(h.value().header_len, 4u);

  EXPECT_EQ(encode_message_header(kMaxMessage + 1, buf).error(), Error::kTooLarge);
  const uint8_t over[] = {0x80, 0x04, 0x00, 0x01};
  EXPECT_EQ(decode_message_header(over).error(), Error::kTooLarge);
  uint8_t tiny[1];
  EXPECT_EQ(encode_message_header(kMaxMessage, tiny).error(), Error::kBufferTooSmall);
}

TEST(Message, NonCanonicalLength) {
  const uint8_t p[] = {0x40, 0x05};
  EXPECT_EQ(decode_message_header(p).error(), Error::kNonCanonicalVarint);
}
