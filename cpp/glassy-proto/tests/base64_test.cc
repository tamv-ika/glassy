// Strict base64 (no padding) behaviour shared by the ICE, WebTransport and connect_info codecs.
#include "base64.h"

#include <gtest/gtest.h>

#include <array>
#include <string_view>

using namespace glassy::proto;

namespace {

Result<size_t> dec(Base64Alphabet a, std::string_view s, std::array<uint8_t, 16>& out) {
  return base64_decode(a, s, out);
}

}  // namespace

TEST(Base64, DecodesStdAndUrlAlphabets) {
  std::array<uint8_t, 16> out{};
  auto r = dec(Base64Alphabet::kStd, "+/8", out);
  ASSERT_TRUE(r.ok());
  EXPECT_EQ(r.value(), 2u);
  EXPECT_EQ(out[0], 0xfb);
  EXPECT_EQ(out[1], 0xff);
  r = dec(Base64Alphabet::kUrl, "-_8", out);
  ASSERT_TRUE(r.ok());
  EXPECT_EQ(out[0], 0xfb);
  EXPECT_EQ(out[1], 0xff);
  EXPECT_EQ(dec(Base64Alphabet::kUrl, "+/8", out).error(), Error::kBadEncoding);
  EXPECT_EQ(dec(Base64Alphabet::kStd, "-_8", out).error(), Error::kBadEncoding);
}

TEST(Base64, RejectsPaddingBadCharsImpossibleLengthAndTrailingBits) {
  std::array<uint8_t, 16> out{};
  EXPECT_EQ(dec(Base64Alphabet::kUrl, "AA==", out).error(), Error::kBadEncoding);
  EXPECT_EQ(dec(Base64Alphabet::kUrl, "AA=", out).error(), Error::kBadEncoding);
  EXPECT_EQ(dec(Base64Alphabet::kUrl, "A!AA", out).error(), Error::kBadEncoding);
  EXPECT_EQ(dec(Base64Alphabet::kUrl, "A", out).error(), Error::kBadEncoding);
  EXPECT_EQ(dec(Base64Alphabet::kUrl, "AAAAA", out).error(), Error::kBadEncoding);
  // "AB" leaves 4 non-zero trailing bits; "AAB" leaves 2.
  EXPECT_EQ(dec(Base64Alphabet::kUrl, "AB", out).error(), Error::kBadEncoding);
  EXPECT_EQ(dec(Base64Alphabet::kUrl, "AAB", out).error(), Error::kBadEncoding);
  EXPECT_TRUE(dec(Base64Alphabet::kUrl, "AA", out).ok());
  EXPECT_TRUE(dec(Base64Alphabet::kUrl, "AAA", out).ok());
  auto empty = dec(Base64Alphabet::kUrl, "", out);
  ASSERT_TRUE(empty.ok());
  EXPECT_EQ(empty.value(), 0u);
}

TEST(Base64, SmallOutputBuffer) {
  std::array<uint8_t, 1> out{};
  EXPECT_EQ(base64_decode(Base64Alphabet::kUrl, "AAAA", out).error(), Error::kBufferTooSmall);
}

TEST(Base64, EncodeStdRoundTrip) {
  const std::array<uint8_t, 4> in = {0xfb, 0xff, 0x00, 0x01};
  std::array<char, 8> text{};
  auto n = base64_encode(Base64Alphabet::kStd, in, text);
  ASSERT_TRUE(n.ok());
  EXPECT_EQ(std::string_view(text.data(), n.value()), "+/8AAQ");
  std::array<char, 2> tiny{};
  EXPECT_EQ(base64_encode(Base64Alphabet::kStd, in, tiny).error(), Error::kBufferTooSmall);
}
