//! Error codes shared with the C++ lib; the `code()` strings are part of the wire contract.

use std::fmt;

/// Every failure the codec can report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// `truncated`
    Truncated,
    /// `bad_length`
    BadLength,
    /// `bad_type`
    BadType,
    /// `bad_version`
    BadVersion,
    /// `unknown_key`
    UnknownKey,
    /// `auth_failed`
    AuthFailed,
    /// `expired`
    Expired,
    /// `reserved_nonzero`
    ReservedNonzero,
    /// `bad_transport`
    BadTransport,
    /// `session_mismatch`
    SessionMismatch,
    /// `wrong_server`
    WrongServer,
    /// `bad_user_id`
    BadUserId,
    /// `bad_metadata`
    BadMetadata,
    /// `bad_padding`
    BadPadding,
    /// `bad_trailer`
    BadTrailer,
    /// `non_canonical_varint`
    NonCanonicalVarint,
    /// `value_too_large`
    ValueTooLarge,
    /// `too_large`
    TooLarge,
    /// `duplicate_ack`
    DuplicateAck,
    /// `non_canonical_ack`
    NonCanonicalAck,
    /// `bad_token_type`
    BadTokenType,
    /// `bad_odcil`
    BadOdcil,
    /// `bad_encoding`
    BadEncoding,
    /// `bad_json`
    BadJson,
    /// `too_old`
    TooOld,
    /// `replayed`
    Replayed,
    /// `buffer_too_small`; returned only by encoders when the output buffer is too small.
    BufferTooSmall,
}

impl Error {
    /// Stable error code string, identical in Rust and C++.
    pub fn code(&self) -> &'static str {
        match self {
            Error::Truncated => "truncated",
            Error::BadLength => "bad_length",
            Error::BadType => "bad_type",
            Error::BadVersion => "bad_version",
            Error::UnknownKey => "unknown_key",
            Error::AuthFailed => "auth_failed",
            Error::Expired => "expired",
            Error::ReservedNonzero => "reserved_nonzero",
            Error::BadTransport => "bad_transport",
            Error::SessionMismatch => "session_mismatch",
            Error::WrongServer => "wrong_server",
            Error::BadUserId => "bad_user_id",
            Error::BadMetadata => "bad_metadata",
            Error::BadPadding => "bad_padding",
            Error::BadTrailer => "bad_trailer",
            Error::NonCanonicalVarint => "non_canonical_varint",
            Error::ValueTooLarge => "value_too_large",
            Error::TooLarge => "too_large",
            Error::DuplicateAck => "duplicate_ack",
            Error::NonCanonicalAck => "non_canonical_ack",
            Error::BadTokenType => "bad_token_type",
            Error::BadOdcil => "bad_odcil",
            Error::BadEncoding => "bad_encoding",
            Error::BadJson => "bad_json",
            Error::TooOld => "too_old",
            Error::Replayed => "replayed",
            Error::BufferTooSmall => "buffer_too_small",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for Error {}
