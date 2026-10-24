#include "vectors.h"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>

namespace {

[[noreturn]] void die(const std::string& msg) {
  std::fprintf(stderr, "vectors: %s\n", msg.c_str());
  std::abort();
}

int nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

std::string trim(std::string_view s) {
  size_t b = s.find_first_not_of(" \t\r\n");
  if (b == std::string_view::npos) return {};
  size_t e = s.find_last_not_of(" \t\r\n");
  return std::string(s.substr(b, e - b + 1));
}

}  // namespace

nlohmann::json load_vectors(std::string_view file) {
  std::string path = std::string(GLASSY_VECTORS_DIR) + "/" + std::string(file);
  std::ifstream in(path);
  if (!in) die("cannot open " + path);
  return nlohmann::json::parse(in);
}

std::vector<uint8_t> hex(std::string_view s) {
  if (s.size() % 2 != 0) die("odd-length hex");
  std::vector<uint8_t> out;
  out.reserve(s.size() / 2);
  for (size_t i = 0; i < s.size(); i += 2) {
    int hi = nibble(s[i]), lo = nibble(s[i + 1]);
    if (hi < 0 || lo < 0) die("bad hex digit");
    out.push_back(static_cast<uint8_t>(hi << 4 | lo));
  }
  return out;
}

std::string to_hex(std::span<const uint8_t> bytes) {
  static const char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (uint8_t b : bytes) {
    out.push_back(kDigits[b >> 4]);
    out.push_back(kDigits[b & 0xf]);
  }
  return out;
}

std::vector<std::pair<std::string, std::vector<uint8_t>>> load_fixture(std::string_view file) {
  std::string path = std::string(GLASSY_FIXTURES_DIR) + "/" + std::string(file);
  std::ifstream in(path);
  if (!in) die("cannot open " + path);
  std::vector<std::pair<std::string, std::vector<uint8_t>>> out;
  std::string line;
  while (std::getline(in, line)) {
    std::string t = trim(line);
    if (t.empty() || t[0] == '#') continue;
    size_t colon = t.find(':');
    if (colon == std::string::npos) die("fixture line without ':' in " + path);
    out.emplace_back(trim(t.substr(0, colon)), hex(trim(t.substr(colon + 1))));
  }
  return out;
}
