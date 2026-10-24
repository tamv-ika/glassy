#ifndef GLASSY_PROTO_WT_H_
#define GLASSY_PROTO_WT_H_

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "glassy/proto/result.h"

namespace glassy::proto {

inline constexpr std::string_view kWtPathPrefix = "/glassy?t=";
inline constexpr size_t kWtTicketB64Max = 526;
inline constexpr size_t kWtPathMax = 10 + kWtTicketB64Max;  // 536
inline constexpr size_t kWtTicketMin = 75;
inline constexpr size_t kWtTicketMax = 394;

// Extracts the server ticket from `/glassy?t=<base64url>` (spec §6.2) into `ticket_out` (needs
// kWtTicketMax bytes, else kBufferTooSmall) and returns its length. Check order: path longer
// than 536 -> kTooLarge; wrong prefix, '&' or '#' -> kBadEncoding; base64url failure
// (padding, bad character, non-zero trailing bits) -> kBadEncoding; ticket length outside
// [75, 394] -> kBadLength.
Result<size_t> parse_wt_path(std::string_view path, std::span<uint8_t> ticket_out);

}  // namespace glassy::proto

#endif  // GLASSY_PROTO_WT_H_
