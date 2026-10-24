#include "glassy/proto/ice.h"

#include <gtest/gtest.h>

#include <string>

#include "vectors.h"

using namespace glassy::proto;

TEST(Ice, Vectors) {
  const auto file = load_vectors("ice_pwd.json");
  for (const auto& c : file["cases"]) {
    SCOPED_TRACE(c["name"].get<std::string>());
    const auto k = hex(c["k_gs_hex"].get<std::string>());
    ASSERT_EQ(k.size(), 32u);
    Key32 key{};
    std::copy(k.begin(), k.end(), key.begin());
    const auto pwd = ice_pwd(key, c["ufrag"].get<std::string>());
    EXPECT_EQ(std::string(pwd.data(), pwd.size()), c["pwd"].get<std::string>());
  }
}
