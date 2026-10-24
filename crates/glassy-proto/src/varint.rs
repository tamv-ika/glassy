//! QUIC variable-length integers (RFC 9000 §16) with glassy's canonical-form rule:
//! the encoder always emits the shortest form and the decoder rejects anything longer.

use crate::Error;

/// Largest encodable value, 2^62 - 1.
pub const MAX: u64 = (1 << 62) - 1;

/// Returns the length of the shortest encoding of `v`.
pub fn encoded_len(v: u64) -> Result<usize, Error> {
    match v {
        0..=63 => Ok(1),
        64..=16_383 => Ok(2),
        16_384..=1_073_741_823 => Ok(4),
        1_073_741_824..=MAX => Ok(8),
        _ => Err(Error::ValueTooLarge),
    }
}

/// Appends the shortest encoding of `v` to `out`.
pub fn encode(v: u64, out: &mut Vec<u8>) -> Result<(), Error> {
    let len = encoded_len(v)?;
    // The top two bits of the first byte carry log2 of the length.
    let tag: u64 = match len {
        1 => 0,
        2 => 1,
        4 => 2,
        _ => 3,
    };
    let be = (v | (tag << (len * 8 - 2))).to_be_bytes();
    out.extend_from_slice(&be[8 - len..]);
    Ok(())
}

/// Decodes one varint from the start of `buf`, returning the value and bytes consumed.
pub fn decode(buf: &[u8]) -> Result<(u64, usize), Error> {
    let first = *buf.first().ok_or(Error::Truncated)?;
    let len = 1usize << (first >> 6);
    let bytes = buf.get(..len).ok_or(Error::Truncated)?;
    let mut v = u64::from(first & 0x3f);
    for &b in &bytes[1..] {
        v = (v << 8) | u64::from(b);
    }
    // Canonical form: the value must not fit in a shorter encoding.
    if encoded_len(v)? != len {
        return Err(Error::NonCanonicalVarint);
    }
    Ok((v, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_uses_shortest_form() {
        let cases = [
            (63, 1),
            (64, 2),
            (16_383, 2),
            (16_384, 4),
            ((1 << 30) - 1, 4),
            (1 << 30, 8),
            (MAX, 8),
        ];
        for (v, len) in cases {
            let mut out = Vec::new();
            encode(v, &mut out).unwrap();
            assert_eq!(out.len(), len, "value {v}");
            assert_eq!(encoded_len(v), Ok(len));
        }
        let mut out = Vec::new();
        assert_eq!(encode(MAX + 1, &mut out), Err(Error::ValueTooLarge));
        assert!(out.is_empty());
        assert_eq!(encoded_len(MAX + 1), Err(Error::ValueTooLarge));
    }

    #[test]
    fn decode_truncated() {
        assert_eq!(decode(&[0x40]), Err(Error::Truncated));
        assert_eq!(decode(&[]), Err(Error::Truncated));
    }
}
