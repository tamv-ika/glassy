#ifndef GLASSY_PROTO_ERROR_H_
#define GLASSY_PROTO_ERROR_H_

#include <cstdint>

namespace glassy::proto {

// Same order as the Rust `Error` enum (crates/glassy-proto/src/error.rs), with kOk first.
enum class Error : uint8_t {
  kOk = 0,
  kTruncated,
  kBadLength,
  kBadType,
  kBadVersion,
  kUnknownKey,
  kAuthFailed,
  kExpired,
  kReservedNonzero,
  kBadTransport,
  kSessionMismatch,
  kWrongServer,
  kBadUserId,
  kBadMetadata,
  kBadPadding,
  kBadTrailer,
  kNonCanonicalVarint,
  kValueTooLarge,
  kTooLarge,
  kDuplicateAck,
  kNonCanonicalAck,
  kBadTokenType,
  kBadOdcil,
  kBadEncoding,
  kBadJson,
  kTooOld,
  kReplayed,
  kBufferTooSmall,
};

// Stable code string, identical to Rust's `Error::code()`; kOk maps to "ok".
const char* error_code(Error e);

}  // namespace glassy::proto

#endif  // GLASSY_PROTO_ERROR_H_
