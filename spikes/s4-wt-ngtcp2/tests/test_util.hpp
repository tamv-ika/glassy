#pragma once

#include <cstdint>
#include <fstream>
#include <map>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

// Reads the flat {"key": "string", ...} JSON vectors written by the Rust tests.
inline std::map<std::string, std::string> load_json(const std::string& path) {
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

inline std::vector<uint8_t> unhex(const std::string& hex) {
  std::vector<uint8_t> out;
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    out.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
  }
  return out;
}
