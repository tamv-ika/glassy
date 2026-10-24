#include "glassy/proto/pn.h"

#include <algorithm>

namespace glassy::proto {

uint64_t decode_pn(uint64_t largest, uint32_t low) {
  constexpr uint64_t kPnWin = uint64_t{1} << 32;
  constexpr uint64_t kPnHwin = kPnWin / 2;
  constexpr uint64_t kPnMask = kPnWin - 1;
  constexpr uint64_t kMaxPn = uint64_t{1} << 62;

  // Saturating +1 and the explicit underflow guards stand in for the signed arithmetic of the
  // RFC pseudo-code.
  const uint64_t expected = largest == UINT64_MAX ? largest : largest + 1;
  const uint64_t candidate = (expected & ~kPnMask) | low;

  if (expected >= kPnHwin && candidate <= expected - kPnHwin && candidate < kMaxPn - kPnWin) {
    return candidate + kPnWin;
  }
  const uint64_t upper = expected > UINT64_MAX - kPnHwin ? UINT64_MAX : expected + kPnHwin;
  if (candidate > upper && candidate >= kPnWin) return candidate - kPnWin;
  return candidate;
}

namespace {

struct Slot {
  size_t word;
  uint64_t mask;
};

Slot slot(uint64_t pn) {
  const size_t i = static_cast<size_t>(pn % kReplayWindow);
  return {i / 64, uint64_t{1} << (i % 64)};
}

// pn + window <= largest without overflowing.
bool too_old(uint64_t pn, uint64_t largest) {
  return pn <= UINT64_MAX - kReplayWindow ? pn + kReplayWindow <= largest : false;
}

}  // namespace

Status ReplayWindow::check(uint64_t pn) const {
  // 0 is reserved for ACCEPT/REJECT and is never a valid DATA packet number.
  if (pn == 0) return Error::kReplayed;
  if (too_old(pn, largest_)) return Error::kTooOld;
  if (pn > largest_) return Error::kOk;
  const Slot s = slot(pn);
  if (bits_[s.word] & s.mask) return Error::kReplayed;
  return Error::kOk;
}

void ReplayWindow::commit(uint64_t pn) {
  if (pn == 0 || too_old(pn, largest_)) return;
  if (pn > largest_) {
    // Slots are indexed by pn mod 256, so slots re-entering the window must be cleared.
    if (pn - largest_ >= kReplayWindow) {
      bits_.fill(0);
    } else {
      for (uint64_t n = largest_ + 1; n <= pn; ++n) {
        const Slot s = slot(n);
        bits_[s.word] &= ~s.mask;
      }
    }
    largest_ = pn;
  }
  const Slot s = slot(pn);
  bits_[s.word] |= s.mask;
}

}  // namespace glassy::proto
