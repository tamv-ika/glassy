#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace glassy {

// Server-side ICE password for `ufrag`, derived from the fleet key (spec §3.5):
// base64_std_nopad(HMAC-SHA256(HKDF-SHA256(ikm = k_gs, salt = none, info = "glassy-ice"), ufrag)).
std::string ice_pwd(const std::array<uint8_t, 32>& k_gs, std::string_view ufrag);

}  // namespace glassy
