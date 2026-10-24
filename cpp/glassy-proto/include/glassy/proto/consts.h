#ifndef GLASSY_PROTO_CONSTS_H_
#define GLASSY_PROTO_CONSTS_H_

#include <cstddef>

namespace glassy::proto {

// Protocol constants for ver = 1; same names and values as crates/glassy-proto/src/consts.rs.
inline constexpr size_t kMaxDatagram = 1100;
inline constexpr size_t kMaxMessage = 262144;
inline constexpr size_t kRecvWindow = 524288;
inline constexpr size_t kMaxStreamGaps = 32;
inline constexpr size_t kReplayWindow = 256;
inline constexpr size_t kMaxConnectInfoJson = 4096;
// Maximum native datagram size on the wire (the game server adds an 8-byte trailer).
inline constexpr size_t kMaxPacket = 1200;

}  // namespace glassy::proto

#endif  // GLASSY_PROTO_CONSTS_H_
