#ifndef GLASSY_PROTO_UTF8_H_
#define GLASSY_PROTO_UTF8_H_

#include <cstdint>
#include <span>

namespace glassy::proto {

// RFC 3629 UTF-8 validation: rejects overlong forms, surrogates and values above U+10FFFF.
bool is_valid_utf8(std::span<const uint8_t> bytes);

}  // namespace glassy::proto

#endif  // GLASSY_PROTO_UTF8_H_
