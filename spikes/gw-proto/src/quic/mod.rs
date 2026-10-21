//! QUIC v1 helpers for the gateway slow path (RFC 9000/9001): Initial decryption, ClientHello
//! SNI extraction and Retry offload.

pub mod initial;

/// Errors from QUIC first-flight parsing; every variant means "drop the datagram".
#[derive(Debug, PartialEq, Eq)]
pub enum QuicError {
    Short,
    NotLong,
    NotInitial,
    UnsupportedVersion,
    Decrypt,
    UnexpectedFrame,
    TooLarge,
    Malformed,
}

/// Reads a variable-length integer (RFC 9000 §16); returns the value and its encoded length.
pub fn read_varint(b: &[u8]) -> Result<(u64, usize), QuicError> {
    let first = *b.first().ok_or(QuicError::Short)?;
    let len = 1usize << (first >> 6);
    let bytes = b.get(..len).ok_or(QuicError::Short)?;
    let mut v = u64::from(first & 0x3f);
    for &x in &bytes[1..] {
        v = (v << 8) | u64::from(x);
    }
    Ok((v, len))
}
