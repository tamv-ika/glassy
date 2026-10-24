#include "glassy/proto/aead.h"

#include <algorithm>

#include "monocypher.h"

namespace glassy::proto {

// Monocypher 4's crypto_aead_lock/unlock is the XChaCha20-Poly1305 construction of
// draft-irtf-cfrg-xchacha-03 (checked by the A.3.1 known-answer test). It keeps the MAC
// separate, so the wrappers below lay out / split `ct | tag`.
Result<size_t> xchacha_seal(const Key32& key, const Nonce24& nonce, std::span<const uint8_t> aad,
                            std::span<const uint8_t> pt, std::span<uint8_t> out) {
  if (out.size() < pt.size() + kAeadTagLen) return Error::kBufferTooSmall;
  // Monocypher takes a non-const key; copy so the caller's key stays intact, then wipe.
  Key32 k = key;
  crypto_aead_lock(out.data(), out.data() + pt.size(), k.data(), nonce.data(), aad.data(),
                   aad.size(), pt.data(), pt.size());
  crypto_wipe(k.data(), k.size());
  return pt.size() + kAeadTagLen;
}

Result<size_t> xchacha_open(const Key32& key, const Nonce24& nonce, std::span<const uint8_t> aad,
                            std::span<const uint8_t> sealed, std::span<uint8_t> out) {
  if (sealed.size() < kAeadTagLen) return Error::kTruncated;
  const size_t ct_len = sealed.size() - kAeadTagLen;
  if (out.size() < ct_len) return Error::kBufferTooSmall;
  Key32 k = key;
  const int rc = crypto_aead_unlock(out.data(), sealed.data() + ct_len, k.data(), nonce.data(),
                                    aad.data(), aad.size(), sealed.data(), ct_len);
  crypto_wipe(k.data(), k.size());
  if (rc != 0) return Error::kAuthFailed;
  return ct_len;
}

Nonce24 packet_nonce(const std::array<uint8_t, 16>& server_nonce, uint64_t pn) {
  Nonce24 n{};
  std::copy(server_nonce.begin(), server_nonce.end(), n.begin());
  for (size_t i = 0; i < 8; ++i) n[16 + i] = static_cast<uint8_t>(pn >> ((7 - i) * 8));
  return n;
}

}  // namespace glassy::proto
