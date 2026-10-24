#ifndef GLASSY_PROTO_MESSAGE_H_
#define GLASSY_PROTO_MESSAGE_H_

#include <cstddef>
#include <span>

#include "glassy/proto/result.h"

namespace glassy::proto {

// Length-prefixed message framing (spec §5.3): `len varint | bytes`, `len <= kMaxMessage`.
// Shared by the native reliable stream and the WebTransport reliable stream.

struct MessageHeader {
  // True when the length varint is not complete yet; `len` and `header_len` are then 0.
  bool need_more = false;
  // Payload length announced by the header.
  size_t len = 0;
  // Number of header bytes to skip before the payload.
  size_t header_len = 0;
};

// A varint cut short by the end of `in` is not an error on a stream (need_more); every other
// failure is final.
Result<MessageHeader> decode_message_header(std::span<const uint8_t> in);

// Writes the length prefix; kTooLarge if len > kMaxMessage.
Result<size_t> encode_message_header(size_t len, std::span<uint8_t> out);

}  // namespace glassy::proto

#endif  // GLASSY_PROTO_MESSAGE_H_
