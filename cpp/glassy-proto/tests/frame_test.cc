#include "glassy/proto/frame.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include "glassy/proto/consts.h"
#include "glassy/proto/varint.h"
#include "vectors.h"

using namespace glassy::proto;

namespace {

// Decodes `plaintext` the way a caller does: one pass to the end, stopping at the first error.
struct Decoded {
  Error error = Error::kOk;
  std::vector<Frame> frames;
};

Decoded decode_all(const std::vector<uint8_t>& plaintext) {
  Decoded d;
  FrameReader reader(plaintext);
  for (;;) {
    Frame f;
    const auto r = reader.next(f);
    if (!r.ok()) {
      d.error = r.error();
      d.frames.clear();
      return d;
    }
    if (!r.value()) return d;
    // Borrowed data must lie inside the input.
    if (!f.data.empty()) {
      EXPECT_GE(f.data.data(), plaintext.data());
      EXPECT_LE(f.data.data() + f.data.size(), plaintext.data() + plaintext.size());
    }
    d.frames.push_back(f);
  }
}

std::string u64_hex_be(uint64_t v) {
  uint8_t b[8];
  for (int i = 0; i < 8; ++i) b[i] = static_cast<uint8_t>(v >> (56 - 8 * i));
  return to_hex(b);
}

std::vector<uint8_t> encode_frame(const Frame& f) {
  std::vector<uint8_t> buf(2048);
  Result<size_t> r = Error::kBadType;
  switch (f.type) {
    case FrameType::kAck:
      r = encode_ack(f.ack, buf);
      break;
    case FrameType::kStream:
      r = encode_stream(f.offset, f.data, buf);
      break;
    case FrameType::kDatagram:
      r = encode_datagram(f.data, buf);
      break;
  }
  EXPECT_TRUE(r.ok()) << error_code(r.error());
  buf.resize(r.ok() ? r.value() : 0);
  return buf;
}

}  // namespace

TEST(Frames, Vectors) {
  const auto file = load_vectors("frames.json");
  size_t ran = 0;
  for (const auto& c : file["cases"]) {
    const std::string name = c["name"];
    SCOPED_TRACE(name);
    const auto plaintext = hex(c["plaintext_hex"].get<std::string>());
    const auto d = decode_all(plaintext);
    ++ran;
    if (c.contains("error")) {
      EXPECT_STREQ(error_code(d.error), c["error"].get<std::string>().c_str());
      continue;
    }
    ASSERT_EQ(d.error, Error::kOk) << error_code(d.error);
    const auto& want = c["expect"]["frames"];
    ASSERT_EQ(d.frames.size(), want.size());
    std::vector<uint8_t> again;
    for (size_t i = 0; i < want.size(); ++i) {
      const auto& w = want[i];
      const Frame& f = d.frames[i];
      const std::string type = w["type"];
      if (type == "ack") {
        ASSERT_EQ(f.type, FrameType::kAck);
        EXPECT_EQ(f.ack.largest_pn_low, w["largest_pn_low"].get<uint32_t>());
        EXPECT_EQ(f.ack.ack_delay, w["ack_delay"].get<uint16_t>());
        EXPECT_EQ(u64_hex_be(f.ack.ack_bits), w["ack_bits_hex"].get<std::string>());
      } else if (type == "stream") {
        ASSERT_EQ(f.type, FrameType::kStream);
        EXPECT_EQ(f.offset, w["offset"].get<uint64_t>());
        EXPECT_EQ(to_hex(f.data), w["data_hex"].get<std::string>());
      } else {
        ASSERT_EQ(type, "datagram");
        ASSERT_EQ(f.type, FrameType::kDatagram);
        EXPECT_EQ(to_hex(f.data), w["data_hex"].get<std::string>());
      }
      const auto enc = encode_frame(f);
      again.insert(again.end(), enc.begin(), enc.end());
    }
    // Canonical encoding: re-encoding reproduces the input bytes.
    EXPECT_EQ(again, plaintext);
  }
  EXPECT_EQ(ran, 19u);
  EXPECT_EQ(file["cases"].size(), 19u);
}

TEST(Frames, ErrorIsSticky) {
  const std::vector<uint8_t> p = {0x03, 0x00, 0x04, 0x03, 0x00};
  FrameReader reader(p);
  Frame f;
  auto r = reader.next(f);
  ASSERT_TRUE(r.ok());
  EXPECT_TRUE(r.value());
  r = reader.next(f);
  EXPECT_EQ(r.error(), Error::kBadType);
  // The reader must not resume at the next frame boundary.
  r = reader.next(f);
  EXPECT_EQ(r.error(), Error::kBadType);
  r = reader.next(f);
  EXPECT_EQ(r.error(), Error::kBadType);
}

TEST(Frames, EndIsStable) {
  const std::vector<uint8_t> p = {0x03, 0x00};
  FrameReader reader(p);
  Frame f;
  EXPECT_TRUE(reader.next(f).value());
  for (int i = 0; i < 3; ++i) {
    const auto r = reader.next(f);
    ASSERT_TRUE(r.ok());
    EXPECT_FALSE(r.value());
  }
}

TEST(Frames, EncodeBufferTooSmall) {
  uint8_t small[3];
  EXPECT_EQ(encode_ack(AckFrame{1, 2, ~uint64_t{0}}, small).error(), Error::kBufferTooSmall);
  const std::vector<uint8_t> data(5, 1);
  EXPECT_EQ(encode_stream(0, data, small).error(), Error::kBufferTooSmall);
  EXPECT_EQ(encode_datagram(data, small).error(), Error::kBufferTooSmall);
  // Exactly fitting buffers succeed.
  uint8_t exact[7];
  EXPECT_EQ(encode_datagram(data, exact).value(), 7u);
}

TEST(Frames, EncodeLimits) {
  std::vector<uint8_t> out(2048);
  const std::vector<uint8_t> big(kMaxDatagram + 1, 7);
  EXPECT_EQ(encode_datagram(big, out).error(), Error::kTooLarge);
  EXPECT_TRUE(encode_datagram(std::span<const uint8_t>(big).first(kMaxDatagram), out).ok());
  const uint8_t one = 0;
  EXPECT_EQ(encode_stream(kVarintMax, std::span<const uint8_t>(&one, 1), out).error(),
            Error::kValueTooLarge);
  EXPECT_EQ(encode_stream(~uint64_t{0}, std::span<const uint8_t>(&one, 1), out).error(),
            Error::kValueTooLarge);
  EXPECT_TRUE(encode_stream(kVarintMax, {}, out).ok());
}

TEST(Frames, AckBitsRoundTrip) {
  const uint64_t cases[] = {~uint64_t{0}, 0, 0xFFFFFFFFFFFFFF00ull, 0xFFFFFFFF12FF34FFull, 1};
  for (const uint64_t bits : cases) {
    uint8_t buf[16];
    const AckFrame a{0x01020304, 0x0506, bits};
    const auto n = encode_ack(a, buf);
    ASSERT_TRUE(n.ok());
    FrameReader reader(std::span<const uint8_t>(buf, n.value()));
    Frame f;
    ASSERT_TRUE(reader.next(f).value());
    EXPECT_EQ(f.ack.ack_bits, bits);
  }
}
