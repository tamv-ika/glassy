#include "glassy/proto/utf8.h"

#include <cstddef>

namespace glassy::proto {

bool is_valid_utf8(std::span<const uint8_t> b) {
  size_t i = 0;
  while (i < b.size()) {
    const uint8_t c = b[i];
    size_t extra;
    uint8_t lo = 0x80;  // allowed range of the first continuation byte
    uint8_t hi = 0xbf;
    if (c < 0x80) {
      ++i;
      continue;
    } else if (c >= 0xc2 && c <= 0xdf) {
      extra = 1;
    } else if (c >= 0xe0 && c <= 0xef) {
      extra = 2;
      if (c == 0xe0) lo = 0xa0;  // no overlong 3-byte forms
      if (c == 0xed) hi = 0x9f;  // no surrogates U+D800..U+DFFF
    } else if (c >= 0xf0 && c <= 0xf4) {
      extra = 3;
      if (c == 0xf0) lo = 0x90;  // no overlong 4-byte forms
      if (c == 0xf4) hi = 0x8f;  // nothing above U+10FFFF
    } else {
      return false;  // continuation byte as lead, 0xc0, 0xc1, 0xf5..0xff
    }
    if (b.size() - i <= extra) return false;
    if (b[i + 1] < lo || b[i + 1] > hi) return false;
    for (size_t k = 2; k <= extra; ++k) {
      if ((b[i + k] & 0xc0) != 0x80) return false;
    }
    i += extra + 1;
  }
  return true;
}

}  // namespace glassy::proto
