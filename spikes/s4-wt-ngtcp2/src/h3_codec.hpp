#pragma once

// Minimal HTTP/3 pieces for a WebTransport-only server endpoint (spec §6.5).

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace glassy {

// QUIC variable-length integers (RFC 9000 §16).
size_t varint_encode(uint64_t v, uint8_t* out);
std::optional<std::pair<uint64_t, size_t>> varint_decode(std::span<const uint8_t> in);

using Settings = std::vector<std::pair<uint64_t, uint64_t>>;

// HTTP/3 SETTINGS frame (type 0x04) and the decoder for its payload (RFC 9114 §7.2.4).
std::vector<uint8_t> encode_settings_frame(const Settings& settings);
std::optional<Settings> decode_settings_payload(std::span<const uint8_t> payload);

// Decodes a request field section with nghttp3's QPACK decoder (no dynamic table).
std::optional<std::map<std::string, std::string>> qpack_decode_request(
    std::span<const uint8_t> block);

// ":status 200" plus "sec-webtransport-http3-draft: draft02", without Huffman coding.
std::vector<uint8_t> encode_response_headers();

// The superset of SETTINGS the server advertises, so browsers on any WT draft find theirs.
inline const Settings kServerSettings{
    {0x08, 1},        // SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 9220)
    {0x33, 1},        // SETTINGS_H3_DATAGRAM (RFC 9297)
    {0x2b603742, 1},  // SETTINGS_ENABLE_WEBTRANSPORT (draft-02)
    {0xc671706a, 1},  // SETTINGS_WT_MAX_SESSIONS (draft-07 and later)
};

}  // namespace glassy
