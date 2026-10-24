#include "glassy/proto/wt.h"

#include <gtest/gtest.h>

#include <array>
#include <string>

#include "vectors.h"

using namespace glassy::proto;

TEST(Wt, PathVectors) {
  const auto file = load_vectors("wt_framing.json");
  size_t ran = 0;
  for (const auto& c : file["cases"]) {
    if (c["kind"] != "path") continue;
    const std::string name = c["name"];
    SCOPED_TRACE(name);
    std::array<uint8_t, 394> out{};
    auto r = parse_wt_path(c["path"].get<std::string>(), out);
    if (c.contains("error")) {
      ASSERT_FALSE(r.ok());
      EXPECT_STREQ(error_code(r.error()), c["error"].get<std::string>().c_str());
    } else {
      ASSERT_TRUE(r.ok()) << error_code(r.error());
      EXPECT_EQ(to_hex(std::span<const uint8_t>(out.data(), r.value())),
                c["expect"]["ticket_hex"].get<std::string>());
    }
    ++ran;
  }
  EXPECT_EQ(ran, 10u);
}

TEST(Wt, SmallOutputBuffer) {
  std::array<uint8_t, 10> out{};
  auto r = parse_wt_path("/glassy?t=AAAA", out);
  ASSERT_FALSE(r.ok());
  EXPECT_EQ(r.error(), Error::kBufferTooSmall);
}
