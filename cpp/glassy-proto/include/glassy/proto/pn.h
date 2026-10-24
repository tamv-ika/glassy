#ifndef GLASSY_PROTO_PN_H_
#define GLASSY_PROTO_PN_H_

#include <array>
#include <cstdint>

#include "glassy/proto/consts.h"
#include "glassy/proto/result.h"

namespace glassy::proto {

// Reconstructs a full packet number from its low 32 bits (RFC 9000 Appendix A.3, pn_nbits = 32).
uint64_t decode_pn(uint64_t largest, uint32_t low);

// Sliding anti-replay window covering (largest - 256, largest].
class ReplayWindow {
 public:
  // Read-only; call commit() only after the AEAD verified. pn 0 is reserved for ACCEPT/REJECT
  // and gives kReplayed; pn + 256 <= largest gives kTooOld; a committed pn gives kReplayed.
  Status check(uint64_t pn) const;
  // Marks pn as seen. Ignores pn 0 and values check() rejects as too old.
  void commit(uint64_t pn);
  uint64_t largest() const { return largest_; }

 private:
  std::array<uint64_t, kReplayWindow / 64> bits_{};
  uint64_t largest_ = 0;
};

}  // namespace glassy::proto

#endif  // GLASSY_PROTO_PN_H_
