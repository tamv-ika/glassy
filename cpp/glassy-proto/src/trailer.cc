#include "glassy/proto/trailer.h"

namespace glassy::proto {

Result<SplitTrailer> split_trailer(std::span<const uint8_t> packet) {
  if (packet.size() < kTrailerV4Len) return Error::kBadTrailer;
  const size_t split = packet.size() - kTrailerV4Len;
  const uint8_t* t = packet.data() + split;
  if (t[7] != 0x04 || t[6] != 0) return Error::kBadTrailer;
  SplitTrailer out;
  out.payload = packet.first(split);
  out.addr.ip = {t[0], t[1], t[2], t[3]};
  out.addr.port = static_cast<uint16_t>((t[4] << 8) | t[5]);
  return out;
}

}  // namespace glassy::proto
