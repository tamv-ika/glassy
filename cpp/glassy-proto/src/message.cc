#include "glassy/proto/message.h"

#include "glassy/proto/consts.h"
#include "glassy/proto/varint.h"

namespace glassy::proto {

Result<MessageHeader> decode_message_header(std::span<const uint8_t> in) {
  const auto v = varint_decode(in);
  if (!v.ok()) {
    if (v.error() == Error::kTruncated) return MessageHeader{true, 0, 0};
    return v.error();
  }
  if (v.value().value > kMaxMessage) return Error::kTooLarge;
  return MessageHeader{false, static_cast<size_t>(v.value().value), v.value().len};
}

Result<size_t> encode_message_header(size_t len, std::span<uint8_t> out) {
  if (len > kMaxMessage) return Error::kTooLarge;
  return varint_encode(len, out);
}

}  // namespace glassy::proto
