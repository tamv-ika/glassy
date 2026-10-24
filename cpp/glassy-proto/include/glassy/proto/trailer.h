#ifndef GLASSY_PROTO_TRAILER_H_
#define GLASSY_PROTO_TRAILER_H_

#include <array>
#include <cstdint>
#include <span>

#include "glassy/proto/result.h"

namespace glassy::proto {

inline constexpr size_t kTrailerV4Len = 8;

struct ClientAddrV4 {
  std::array<uint8_t, 4> ip{};
  uint16_t port = 0;
};

struct SplitTrailer {
  std::span<const uint8_t> payload;
  ClientAddrV4 addr;
};

// Splits the gateway's `ipv4(4) | port(u16 BE) | reserved(1)=0 | family(1)=0x04` trailer off a
// forwarded packet (spec §4.2). Anything shorter than 8 bytes, a non-zero reserved byte or a
// family other than 0x04 is kBadTrailer.
Result<SplitTrailer> split_trailer(std::span<const uint8_t> packet);

}  // namespace glassy::proto

#endif  // GLASSY_PROTO_TRAILER_H_
