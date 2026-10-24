// libFuzzer target: DATA frame payloads (spec §5) and the message length prefix (spec §5.3).
// Every payload the reader accepts must re-encode to exactly the input bytes (canonical form).
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "glassy/proto/consts.h"
#include "glassy/proto/frame.h"
#include "glassy/proto/message.h"

using namespace glassy::proto;

namespace {

void require(bool ok) {
  if (!ok) __builtin_trap();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const std::span<const uint8_t> in(data, size);

  std::vector<uint8_t> again(size + 16);
  size_t used = 0;
  FrameReader reader(in);
  Frame f;
  for (;;) {
    auto r = reader.next(f);
    if (!r.ok()) {
      // Sticky: the reader never resumes after an error.
      require(!reader.next(f).ok());
      used = SIZE_MAX;
      break;
    }
    if (!r.value()) break;
    const std::span<uint8_t> out = std::span(again).subspan(used);
    Result<size_t> n = Error::kOk;
    switch (f.type) {
      case FrameType::kAck:
        n = encode_ack(f.ack, out);
        break;
      case FrameType::kStream:
        n = encode_stream(f.offset, f.data, out);
        break;
      case FrameType::kDatagram:
        n = encode_datagram(f.data, out);
        break;
    }
    require(n.ok());
    used += n.value();
    require(used <= size);
  }
  if (used != SIZE_MAX) {
    require(used == size);
    require(std::equal(in.begin(), in.end(), again.begin()));
  }

  auto h = decode_message_header(in);
  if (h.ok() && !h.value().need_more) {
    require(h.value().len <= kMaxMessage && h.value().header_len <= size);
  }
  return 0;
}
