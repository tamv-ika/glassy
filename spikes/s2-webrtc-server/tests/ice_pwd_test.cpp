#include "ice_pwd.hpp"

#include <gtest/gtest.h>

#include <fstream>
#include <map>
#include <regex>
#include <sstream>

namespace {

// Reads the flat {"key": "string", ...} JSON vectors written by the Rust tests.
std::map<std::string, std::string> load_json(const std::string& path) {
  std::ifstream in(path);
  std::stringstream ss;
  ss << in.rdbuf();
  const std::string text = ss.str();
  std::map<std::string, std::string> out;
  const std::regex field("\"([^\"]+)\"\\s*:\\s*\"([^\"]*)\"");
  for (auto it = std::sregex_iterator(text.begin(), text.end(), field); it != std::sregex_iterator();
       ++it) {
    out[(*it)[1]] = (*it)[2];
  }
  return out;
}

std::array<uint8_t, 32> hex32(const std::string& hex) {
  std::array<uint8_t, 32> out{};
  for (size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<uint8_t>(std::stoi(hex.substr(i * 2, 2), nullptr, 16));
  }
  return out;
}

}  // namespace

TEST(IcePwd, MatchesRustVector) {
  auto v = load_json(GLASSY_VECTORS_DIR "/ice_pwd.json");
  ASSERT_EQ(v.size(), 3u);
  EXPECT_EQ(glassy::ice_pwd(hex32(v["k_gs_hex"]), v["ufrag"]), v["pwd"]);
}

TEST(IcePwd, Length43) {
  // 32-byte HMAC in unpadded base64 is always 43 chars, above the ICE minimum of 22.
  EXPECT_EQ(glassy::ice_pwd(std::array<uint8_t, 32>{}, "x").size(), 43u);
}
