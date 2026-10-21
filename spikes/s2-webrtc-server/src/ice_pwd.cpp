#include "ice_pwd.hpp"

#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>

#include <stdexcept>

namespace glassy {
namespace {

constexpr std::string_view kIceInfo = "glassy-ice";
constexpr size_t kSha256Len = 32;

gnutls_datum_t datum(const void* data, size_t len) {
  return gnutls_datum_t{static_cast<unsigned char*>(const_cast<void*>(data)),
                        static_cast<unsigned int>(len)};
}

void check(int rc, const char* what) {
  if (rc < 0) {
    throw std::runtime_error(std::string(what) + ": " + gnutls_strerror(rc));
  }
}

}  // namespace

std::string ice_pwd(const std::array<uint8_t, 32>& k_gs, std::string_view ufrag) {
  // RFC 5869 §2.2: an absent salt is HashLen zero bytes.
  const std::array<uint8_t, kSha256Len> zero_salt{};
  const gnutls_datum_t ikm = datum(k_gs.data(), k_gs.size());
  const gnutls_datum_t salt = datum(zero_salt.data(), zero_salt.size());
  std::array<uint8_t, kSha256Len> prk{};
  check(gnutls_hkdf_extract(GNUTLS_MAC_SHA256, &ikm, &salt, prk.data()), "hkdf_extract");

  const gnutls_datum_t prk_d = datum(prk.data(), prk.size());
  const gnutls_datum_t info = datum(kIceInfo.data(), kIceInfo.size());
  std::array<uint8_t, kSha256Len> ice_key{};
  check(gnutls_hkdf_expand(GNUTLS_MAC_SHA256, &prk_d, &info, ice_key.data(), ice_key.size()),
        "hkdf_expand");

  std::array<uint8_t, kSha256Len> mac{};
  check(gnutls_hmac_fast(GNUTLS_MAC_SHA256, ice_key.data(), ice_key.size(), ufrag.data(),
                         ufrag.size(), mac.data()),
        "hmac");

  const gnutls_datum_t mac_d = datum(mac.data(), mac.size());
  gnutls_datum_t b64{};
  check(gnutls_base64_encode2(&mac_d, &b64), "base64");
  std::string out(reinterpret_cast<const char*>(b64.data), b64.size);
  gnutls_free(b64.data);
  // ICE passwords use unpadded base64, matching the broker's encoding.
  while (!out.empty() && out.back() == '=') {
    out.pop_back();
  }
  return out;
}

}  // namespace glassy
