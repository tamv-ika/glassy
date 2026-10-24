// libFuzzer target: WebTransport request path (spec §6.2) and stream message framing
// (spec §5.3). The same input is read as a path and as stream bytes.
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "glassy/proto/consts.h"
#include "glassy/proto/message.h"
#include "glassy/proto/wt.h"

using namespace glassy::proto;

namespace {

void require(bool ok) {
  if (!ok) __builtin_trap();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::array<uint8_t, kWtTicketMax> ticket;
  auto p = parse_wt_path(std::string_view(reinterpret_cast<const char*>(data), size), ticket);
  if (p.ok()) require(size <= kWtPathMax && p.value() >= kWtTicketMin && p.value() <= kWtTicketMax);

  // Same split loop as the differential CLIs.
  std::span<const uint8_t> rest(data, size);
  for (;;) {
    auto h = decode_message_header(rest);
    if (!h.ok() || h.value().need_more) break;
    require(h.value().len <= kMaxMessage && h.value().header_len <= rest.size());
    if (rest.size() - h.value().header_len < h.value().len) break;
    rest = rest.subspan(h.value().header_len + h.value().len);
  }
  return 0;
}
