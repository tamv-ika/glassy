// ConnectInfo decoder against the Rust golden vectors (vectors/connect_info.json).
#include "glassy/proto/connect_info.h"

#include <gtest/gtest.h>

#include <atomic>
#include <cstdlib>
#include <memory>
#include <new>
#include <string>
#include <vector>

#include "base64.h"
#include "vectors.h"

using namespace glassy::proto;

// Global allocation counter for NoHeapAllocation. Replacing operator new affects this test
// binary only; counting is switched on just around the decode calls so gtest and nlohmann
// allocations do not show up.
namespace {
std::atomic<bool> g_counting{false};
std::atomic<size_t> g_allocations{0};
}  // namespace

void* operator new(size_t size) {
  if (g_counting.load(std::memory_order_relaxed)) {
    g_allocations.fetch_add(1, std::memory_order_relaxed);
  }
  void* p = std::malloc(size == 0 ? 1 : size);
  if (p == nullptr) std::abort();
  return p;
}
// The nothrow forms are replaced too (libstdc++ uses them internally), otherwise ASan sees
// a malloc/operator-new mismatch.
void* operator new(size_t size, const std::nothrow_t&) noexcept {
  return std::malloc(size == 0 ? 1 : size);
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, const std::nothrow_t&) noexcept { std::free(p); }
void operator delete(void* p, size_t) noexcept { std::free(p); }

namespace {

// Each case carries either `json` (base64url-encoded here) or the raw `input` string.
std::string case_input(const nlohmann::json& c) {
  if (c.contains("input")) return c["input"].get<std::string>();
  const std::string json = c["json"].get<std::string>();
  std::string out(json.size() / 3 * 4 + 4, '\0');
  auto r = base64_encode(Base64Alphabet::kUrl,
                         std::span(reinterpret_cast<const uint8_t*>(json.data()), json.size()),
                         std::span(out.data(), out.size()));
  EXPECT_TRUE(r.ok());
  out.resize(r.value());
  return out;
}

template <size_t N>
std::vector<std::string> strings(const std::array<FixedString<N>, kConnectInfoMaxAddrs>& a,
                                 uint8_t count) {
  std::vector<std::string> out;
  for (uint8_t i = 0; i < count; ++i) out.emplace_back(a[i].view());
  return out;
}

void expect_matches(const ConnectInfo& ci, const nlohmann::json& e) {
  EXPECT_EQ(to_hex(ci.session_id), e["session_id"].get<std::string>());
  EXPECT_EQ(ci.expiry, e["expiry"].get<uint32_t>());
  ASSERT_EQ(ci.has_native, e.contains("native"));
  ASSERT_EQ(ci.has_webrtc, e.contains("webrtc"));
  ASSERT_EQ(ci.has_webtransport, e.contains("webtransport"));
  if (ci.has_native) {
    const auto& n = e["native"];
    EXPECT_EQ(strings(ci.native.gateways, ci.native.gateway_count),
              n["gateways"].get<std::vector<std::string>>());
    EXPECT_EQ(to_hex(ci.native.routing_ticket), n["routing_ticket_hex"].get<std::string>());
    EXPECT_EQ(to_hex(std::span(ci.native.server_ticket.data(), ci.native.server_ticket_len)),
              n["server_ticket_hex"].get<std::string>());
    EXPECT_EQ(to_hex(ci.native.key_c2s), n["key_c2s_hex"].get<std::string>());
    EXPECT_EQ(to_hex(ci.native.key_s2c), n["key_s2c_hex"].get<std::string>());
  }
  if (ci.has_webrtc) {
    const auto& w = e["webrtc"];
    EXPECT_EQ(strings(ci.webrtc.candidates, ci.webrtc.candidate_count),
              w["candidates"].get<std::vector<std::string>>());
    EXPECT_EQ(ci.webrtc.ice_ufrag.view(), w["ice_ufrag"].get<std::string>());
    EXPECT_EQ(ci.webrtc.ice_pwd.view(), w["ice_pwd"].get<std::string>());
    EXPECT_EQ(ci.webrtc.dtls_fingerprint.view(), w["dtls_fingerprint"].get<std::string>());
    EXPECT_EQ(to_hex(std::span(ci.webrtc.server_ticket.data(), ci.webrtc.server_ticket_len)),
              w["server_ticket_hex"].get<std::string>());
  }
  if (ci.has_webtransport) {
    const auto& t = e["webtransport"];
    EXPECT_EQ(ci.webtransport.url.view(), t["url"].get<std::string>());
    EXPECT_EQ(to_hex(ci.webtransport.cert_sha256), t["cert_sha256_hex"].get<std::string>());
  }
}

}  // namespace

TEST(ConnectInfo, Vectors) {
  const auto file = load_vectors("connect_info.json");
  ASSERT_GE(file["cases"].size(), 73u);
  // Heap-allocated: ConnectInfo plus scratch is ~10KB, kept off the gtest stack.
  auto ci = std::make_unique<ConnectInfo>();
  std::vector<uint8_t> scratch(kConnectInfoScratchMin);
  for (const auto& c : file["cases"]) {
    const std::string name = c["name"];
    SCOPED_TRACE(name);
    const std::string input = case_input(c);
    const Status s = decode_connect_info(input, *ci, scratch);
    if (c.contains("error")) {
      ASSERT_FALSE(s.ok());
      EXPECT_STREQ(error_code(s.error()), c["error"].get<std::string>().c_str());
      EXPECT_FALSE(ci->has_native || ci->has_webrtc || ci->has_webtransport);
      continue;
    }
    ASSERT_TRUE(s.ok()) << error_code(s.error());
    expect_matches(*ci, c["expect"]);
  }
}

TEST(ConnectInfo, ScratchTooSmall) {
  const auto file = load_vectors("connect_info.json");
  const std::string input = case_input(file["cases"][0]);
  auto ci = std::make_unique<ConnectInfo>();
  std::vector<uint8_t> scratch(kConnectInfoScratchMin - 1);
  EXPECT_STREQ(error_code(decode_connect_info(input, *ci, scratch).error()), "buffer_too_small");
  // Checked before the input, so even an empty input reports the buffer.
  EXPECT_STREQ(error_code(decode_connect_info("", *ci, scratch).error()), "buffer_too_small");
  scratch.resize(kConnectInfoScratchMin);
  EXPECT_TRUE(decode_connect_info(input, *ci, scratch).ok());
}

TEST(ConnectInfo, NoHeapAllocation) {
  const auto file = load_vectors("connect_info.json");
  std::vector<std::string> inputs;
  for (const auto& c : file["cases"]) inputs.push_back(case_input(c));
  auto ci = std::make_unique<ConnectInfo>();
  std::vector<uint8_t> scratch(kConnectInfoScratchMin);

  // The counter must see allocations, or a zero below proves nothing.
  g_allocations = 0;
  g_counting = true;
  ::operator delete(::operator new(16));
  g_counting = false;
  ASSERT_EQ(g_allocations.load(), 1u);

  size_t ok = 0;
  g_allocations = 0;
  g_counting = true;
  for (const std::string& in : inputs) ok += decode_connect_info(in, *ci, scratch).ok() ? 1 : 0;
  g_counting = false;
  EXPECT_EQ(g_allocations.load(), 0u);
  // Success and error paths were both exercised.
  EXPECT_GT(ok, 0u);
  EXPECT_LT(ok, inputs.size());
}
