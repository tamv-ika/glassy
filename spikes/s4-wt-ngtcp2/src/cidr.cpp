#include "cidr.hpp"

#include <arpa/inet.h>

#include <charconv>
#include <cstdint>
#include <optional>

namespace glassy {
namespace {

std::optional<uint32_t> parse_ipv4(std::string_view text) {
  const std::string s(text);
  in_addr addr{};
  if (inet_pton(AF_INET, s.c_str(), &addr) != 1) {
    return std::nullopt;
  }
  return ntohl(addr.s_addr);
}

}  // namespace

bool in_cidrs(std::string_view ip, const std::vector<std::string>& cidrs) {
  const auto addr = parse_ipv4(ip);
  if (!addr) {
    return false;
  }
  for (const auto& cidr : cidrs) {
    const auto slash = cidr.find('/');
    if (slash == std::string::npos) {
      continue;
    }
    const auto net = parse_ipv4(std::string_view(cidr).substr(0, slash));
    unsigned prefix = 0;
    const auto* first = cidr.data() + slash + 1;
    const auto* last = cidr.data() + cidr.size();
    if (!net || std::from_chars(first, last, prefix).ec != std::errc{} || prefix > 32) {
      continue;
    }
    const uint32_t mask = prefix == 0 ? 0 : ~uint32_t{0} << (32 - prefix);
    if ((*addr & mask) == (*net & mask)) {
      return true;
    }
  }
  return false;
}

}  // namespace glassy
