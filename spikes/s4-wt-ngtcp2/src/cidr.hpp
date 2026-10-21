#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace glassy {

// True when the IPv4 address `ip` falls in any "a.b.c.d/n" range. Used to trust Retry tokens
// only on packets that arrive from the gateway (spec §3.6, trusted_gateway_cidrs).
bool in_cidrs(std::string_view ip, const std::vector<std::string>& cidrs);

}  // namespace glassy
