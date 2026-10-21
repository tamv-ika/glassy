#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace glassy {

// Extracts the Original Destination Connection ID from a gateway-issued no-shared-state Retry
// token (draft-ietf-quic-retry-offload). The server must not validate the opaque part; it only
// reads the cleartext ODCID. Returns nullopt for NEW_TOKEN tokens (first bit set), an ODCIL
// outside 8..20, or a token too short to hold the ODCID.
std::optional<std::vector<uint8_t>> parse_nss_token(std::span<const uint8_t> token);

}  // namespace glassy
