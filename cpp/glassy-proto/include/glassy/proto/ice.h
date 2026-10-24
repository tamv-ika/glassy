#ifndef GLASSY_PROTO_ICE_H_
#define GLASSY_PROTO_ICE_H_

#include <array>
#include <string_view>

#include "glassy/proto/aead.h"

namespace glassy::proto {

// ICE password for `ufrag` (spec §3.5): base64_std_nopad(HMAC-SHA256(K_ice, ufrag)) with
// K_ice = HKDF-SHA256(K_gs, salt empty, info "glassy-ice"). Always 43 characters.
std::array<char, 43> ice_pwd(const Key32& k_gs, std::string_view ufrag);

}  // namespace glassy::proto

#endif  // GLASSY_PROTO_ICE_H_
