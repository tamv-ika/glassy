#ifndef GLASSY_PROTO_FRAME_H_
#define GLASSY_PROTO_FRAME_H_

#include <cstddef>
#include <cstdint>
#include <span>

#include "glassy/proto/result.h"

namespace glassy::proto {

// Frames carried inside DATA packets (spec §5): ACK, STREAM and DATAGRAM.

// `ack_delay` value meaning "no timing information" (spec §5.2).
inline constexpr uint16_t kAckDelayUnknown = 0xFFFF;

struct AckFrame {
  // Low 32 bits of the largest received packet number.
  uint32_t largest_pn_low = 0;
  // Delay in 32 microsecond units, or kAckDelayUnknown.
  uint16_t ack_delay = 0;
  // Bit n set means `largest - 1 - n` was received.
  uint64_t ack_bits = 0;
};

enum class FrameType : uint8_t { kAck = 1, kStream = 2, kDatagram = 3 };

// `data` borrows from the span given to FrameReader. `ack` is valid for kAck, `offset` for
// kStream.
struct Frame {
  FrameType type = FrameType::kAck;
  AckFrame ack;
  uint64_t offset = 0;
  std::span<const uint8_t> data;
};

// Iterates the frames of one plaintext payload without allocating. All-or-nothing (spec §5.0):
// callers make one pass to validate and a second one to apply. The first error in byte order
// is returned, and it is sticky so a caller cannot resume in the middle of a bad packet.
class FrameReader {
 public:
  explicit FrameReader(std::span<const uint8_t> plaintext) : rest_(plaintext) {}

  // true = `out` holds the next frame, false = end of payload.
  Result<bool> next(Frame& out);

 private:
  std::span<const uint8_t> rest_;
  bool seen_ack_ = false;
  Error failed_ = Error::kOk;
};

// Each encoder returns the number of bytes written, or an error with `out` content unspecified.
Result<size_t> encode_ack(const AckFrame& ack, std::span<uint8_t> out);
Result<size_t> encode_stream(uint64_t offset, std::span<const uint8_t> data,
                             std::span<uint8_t> out);
Result<size_t> encode_datagram(std::span<const uint8_t> data, std::span<uint8_t> out);

}  // namespace glassy::proto

#endif  // GLASSY_PROTO_FRAME_H_
