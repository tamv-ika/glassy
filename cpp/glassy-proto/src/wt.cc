#include "glassy/proto/wt.h"

#include "base64.h"

namespace glassy::proto {

Result<size_t> parse_wt_path(std::string_view path, std::span<uint8_t> ticket_out) {
  if (path.size() > kWtPathMax) return Error::kTooLarge;
  if (!path.starts_with(kWtPathPrefix)) return Error::kBadEncoding;
  const std::string_view b64 = path.substr(kWtPathPrefix.size());
  if (b64.find_first_of("&#") != std::string_view::npos) return Error::kBadEncoding;
  // A caller buffer below the maximum is a usage error, reported before any decoding.
  if (ticket_out.size() < kWtTicketMax) return Error::kBufferTooSmall;
  auto n = base64_decode(Base64Alphabet::kUrl, b64, ticket_out);
  if (!n.ok()) return n.error();
  if (n.value() < kWtTicketMin || n.value() > kWtTicketMax) return Error::kBadLength;
  return n.value();
}

}  // namespace glassy::proto
