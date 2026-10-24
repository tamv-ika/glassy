// Known-answer tests: RFC 9000 A.1 varints, draft-irtf-cfrg-xchacha-03 A.3.1, error code strings.
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <map>

#include "glassy/proto/aead.h"
#include "glassy/proto/consts.h"
#include "glassy/proto/error.h"
#include "glassy/proto/result.h"
#include "glassy/proto/varint.h"
#include "vectors.h"

using namespace glassy::proto;

namespace {

std::map<std::string, std::vector<uint8_t>> fixture_map(std::string_view file) {
  std::map<std::string, std::vector<uint8_t>> out;
  for (auto& [k, v] : load_fixture(file)) out[k] = std::move(v);
  return out;
}

template <size_t N>
std::array<uint8_t, N> to_array(const std::vector<uint8_t>& v) {
  std::array<uint8_t, N> a{};
  EXPECT_EQ(v.size(), N);
  std::copy_n(v.begin(), std::min(N, v.size()), a.begin());
  return a;
}

}  // namespace

// RFC 9000 Appendix A.1 examples; the non-canonical form is valid QUIC but rejected here.
TEST(Varint, Rfc9000Examples) {
  const std::map<std::string, uint64_t> expected = {
      {"eight_byte_151288809941952652", 151288809941952652ULL},
      {"four_byte_494878333", 494878333ULL},
      {"two_byte_15293", 15293ULL},
      {"one_byte_37", 37ULL},
  };
  for (const auto& [label, bytes] : load_fixture("varint.hex")) {
    SCOPED_TRACE(label);
    auto r = varint_decode(bytes);
    if (label == "two_byte_37_non_canonical") {
      ASSERT_FALSE(r.ok());
      EXPECT_EQ(r.error(), Error::kNonCanonicalVarint);
      continue;
    }
    ASSERT_TRUE(r.ok());
    EXPECT_EQ(r.value().value, expected.at(label));
    EXPECT_EQ(r.value().len, bytes.size());
    std::array<uint8_t, 8> out{};
    auto w = varint_encode(r.value().value, out);
    ASSERT_TRUE(w.ok());
    EXPECT_EQ(to_hex(std::span<const uint8_t>(out.data(), w.value())), to_hex(bytes));
  }
}

TEST(Varint, ShortestForm) {
  const struct {
    uint64_t v;
    size_t len;
  } cases[] = {{0, 1},          {63, 1},
               {64, 2},         {16383, 2},
               {16384, 4},      {(1ULL << 30) - 1, 4},
               {1ULL << 30, 8}, {(1ULL << 62) - 1, 8}};
  for (const auto& c : cases) {
    SCOPED_TRACE(c.v);
    std::array<uint8_t, 8> out{};
    auto w = varint_encode(c.v, out);
    ASSERT_TRUE(w.ok());
    EXPECT_EQ(w.value(), c.len);
    auto r = varint_decode(std::span<const uint8_t>(out.data(), w.value()));
    ASSERT_TRUE(r.ok());
    EXPECT_EQ(r.value().value, c.v);
    EXPECT_EQ(r.value().len, c.len);
  }
}

TEST(Varint, ErrorPaths) {
  std::array<uint8_t, 8> out{};
  auto too_big = varint_encode(1ULL << 62, out);
  ASSERT_FALSE(too_big.ok());
  EXPECT_EQ(too_big.error(), Error::kValueTooLarge);

  auto small = varint_encode(64, std::span<uint8_t>(out.data(), 1));
  ASSERT_FALSE(small.ok());
  EXPECT_EQ(small.error(), Error::kBufferTooSmall);

  const std::array<uint8_t, 1> half = {0x40};
  EXPECT_EQ(varint_decode(half).error(), Error::kTruncated);
  EXPECT_EQ(varint_decode(std::span<const uint8_t>()).error(), Error::kTruncated);
}

// draft-irtf-cfrg-xchacha-03 Appendix A.3.1.
TEST(Xchacha, DraftA31) {
  auto f = fixture_map("xchacha20poly1305.hex");
  const auto key = to_array<32>(f.at("key"));
  const auto nonce = to_array<24>(f.at("nonce"));
  const auto& aad = f.at("aad");
  const auto& pt = f.at("plaintext");
  std::vector<uint8_t> expected = f.at("ciphertext");
  expected.insert(expected.end(), f.at("tag").begin(), f.at("tag").end());

  std::vector<uint8_t> sealed(pt.size() + 16);
  auto w = xchacha_seal(key, nonce, aad, pt, sealed);
  ASSERT_TRUE(w.ok());
  ASSERT_EQ(w.value(), expected.size());
  EXPECT_EQ(to_hex(sealed), to_hex(expected));

  std::vector<uint8_t> plain(pt.size());
  auto o = xchacha_open(key, nonce, aad, sealed, plain);
  ASSERT_TRUE(o.ok());
  EXPECT_EQ(o.value(), pt.size());
  EXPECT_EQ(plain, pt);

  // Flipping any single bit (ciphertext or tag) must fail authentication.
  for (size_t i : {size_t{0}, sealed.size() / 2, sealed.size() - 1}) {
    auto bad = sealed;
    bad[i] ^= 0x01;
    auto r = xchacha_open(key, nonce, aad, bad, plain);
    ASSERT_FALSE(r.ok());
    EXPECT_EQ(r.error(), Error::kAuthFailed);
  }
  auto bad_aad = aad;
  bad_aad[0] ^= 0x80;
  EXPECT_EQ(xchacha_open(key, nonce, bad_aad, sealed, plain).error(), Error::kAuthFailed);
}

TEST(Xchacha, BufferAndLengthChecks) {
  const Key32 key{};
  const Nonce24 nonce{};
  const std::array<uint8_t, 4> pt = {1, 2, 3, 4};
  std::array<uint8_t, 19> small{};
  EXPECT_EQ(xchacha_seal(key, nonce, {}, pt, small).error(), Error::kBufferTooSmall);

  std::array<uint8_t, 20> sealed{};
  ASSERT_TRUE(xchacha_seal(key, nonce, {}, pt, sealed).ok());
  std::array<uint8_t, 3> small_out{};
  EXPECT_EQ(xchacha_open(key, nonce, {}, sealed, small_out).error(), Error::kBufferTooSmall);

  std::array<uint8_t, 15> short_sealed{};
  std::array<uint8_t, 4> out{};
  EXPECT_EQ(xchacha_open(key, nonce, {}, short_sealed, out).error(), Error::kTruncated);
}

TEST(Xchacha, PacketNonceLayout) {
  std::array<uint8_t, 16> sn{};
  for (size_t i = 0; i < sn.size(); ++i) sn[i] = static_cast<uint8_t>(i + 1);
  const auto n = packet_nonce(sn, 0x0102030405060708ULL);
  EXPECT_EQ(to_hex(n),
            "0102030405060708090a0b0c0d0e0f10"
            "0102030405060708");
}

TEST(Errors, CodesMatchRust) {
  const char* const kCodes[] = {
      "ok",
      "truncated",
      "bad_length",
      "bad_type",
      "bad_version",
      "unknown_key",
      "auth_failed",
      "expired",
      "reserved_nonzero",
      "bad_transport",
      "session_mismatch",
      "wrong_server",
      "bad_user_id",
      "bad_metadata",
      "bad_padding",
      "bad_trailer",
      "non_canonical_varint",
      "value_too_large",
      "too_large",
      "duplicate_ack",
      "non_canonical_ack",
      "bad_token_type",
      "bad_odcil",
      "bad_encoding",
      "bad_json",
      "too_old",
      "replayed",
      "buffer_too_small",
  };
  ASSERT_EQ(std::size(kCodes), 28u);
  for (size_t i = 0; i < std::size(kCodes); ++i) {
    EXPECT_STREQ(error_code(static_cast<Error>(i)), kCodes[i]) << "index " << i;
  }
  EXPECT_EQ(static_cast<uint8_t>(Error::kBufferTooSmall), 27);
}

TEST(Consts, MatchSpec) {
  EXPECT_EQ(kMaxDatagram, 1100u);
  EXPECT_EQ(kMaxMessage, 262144u);
  EXPECT_EQ(kRecvWindow, 524288u);
  EXPECT_EQ(kMaxStreamGaps, 32u);
  EXPECT_EQ(kReplayWindow, 256u);
  EXPECT_EQ(kMaxConnectInfoJson, 4096u);
  EXPECT_EQ(kMaxPacket, 1200u);
}

TEST(Result, ValueAndError) {
  Result<int> a(7);
  EXPECT_TRUE(a.ok());
  EXPECT_EQ(a.value(), 7);
  EXPECT_EQ(a.error(), Error::kOk);
  Result<int> b(Error::kTruncated);
  EXPECT_FALSE(b.ok());
  EXPECT_EQ(b.error(), Error::kTruncated);
  Status s{std::monostate{}};
  EXPECT_TRUE(s.ok());
}
