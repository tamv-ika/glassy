#include "glassy/proto/error.h"

namespace glassy::proto {

const char* error_code(Error e) {
  switch (e) {
    case Error::kOk:
      return "ok";
    case Error::kTruncated:
      return "truncated";
    case Error::kBadLength:
      return "bad_length";
    case Error::kBadType:
      return "bad_type";
    case Error::kBadVersion:
      return "bad_version";
    case Error::kUnknownKey:
      return "unknown_key";
    case Error::kAuthFailed:
      return "auth_failed";
    case Error::kExpired:
      return "expired";
    case Error::kReservedNonzero:
      return "reserved_nonzero";
    case Error::kBadTransport:
      return "bad_transport";
    case Error::kSessionMismatch:
      return "session_mismatch";
    case Error::kWrongServer:
      return "wrong_server";
    case Error::kBadUserId:
      return "bad_user_id";
    case Error::kBadMetadata:
      return "bad_metadata";
    case Error::kBadPadding:
      return "bad_padding";
    case Error::kBadTrailer:
      return "bad_trailer";
    case Error::kNonCanonicalVarint:
      return "non_canonical_varint";
    case Error::kValueTooLarge:
      return "value_too_large";
    case Error::kTooLarge:
      return "too_large";
    case Error::kDuplicateAck:
      return "duplicate_ack";
    case Error::kNonCanonicalAck:
      return "non_canonical_ack";
    case Error::kBadTokenType:
      return "bad_token_type";
    case Error::kBadOdcil:
      return "bad_odcil";
    case Error::kBadEncoding:
      return "bad_encoding";
    case Error::kBadJson:
      return "bad_json";
    case Error::kTooOld:
      return "too_old";
    case Error::kReplayed:
      return "replayed";
    case Error::kBufferTooSmall:
      return "buffer_too_small";
  }
  return "unknown";
}

}  // namespace glassy::proto
