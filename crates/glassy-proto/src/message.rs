//! Length-prefixed message framing (spec §5.3): `len varint | bytes`, `len <= MAX_MESSAGE`.
//! Shared by the native reliable stream and the WebTransport reliable stream.

use crate::{Error, MAX_MESSAGE, varint};

/// Result of looking at the start of a byte stream for a message header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageHeader {
    /// The length varint is not complete yet.
    NeedMore,
    /// `len` payload bytes follow the `header_len` header bytes.
    Ready {
        /// Payload length announced by the header.
        len: usize,
        /// Number of header bytes to skip before the payload.
        header_len: usize,
    },
}

/// Appends the length prefix for a message of `len` bytes.
pub fn encode_message_header(len: usize, out: &mut Vec<u8>) -> Result<(), Error> {
    if len > MAX_MESSAGE {
        return Err(Error::TooLarge);
    }
    varint::encode(len as u64, out)
}

/// Parses the length prefix at the start of `buf`.
pub fn decode_message_header(buf: &[u8]) -> Result<MessageHeader, Error> {
    // A varint cut short by the end of the buffer is not an error on a stream: more bytes may
    // still arrive. Every other failure is final.
    let (len, header_len) = match varint::decode(buf) {
        Ok(v) => v,
        Err(Error::Truncated) => return Ok(MessageHeader::NeedMore),
        Err(e) => return Err(e),
    };
    if len > MAX_MESSAGE as u64 {
        return Err(Error::TooLarge);
    }
    Ok(MessageHeader::Ready {
        len: len as usize,
        header_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_need_more_on_partial_varint() {
        assert_eq!(decode_message_header(&[]), Ok(MessageHeader::NeedMore));
        assert_eq!(decode_message_header(&[0x40]), Ok(MessageHeader::NeedMore));
        assert_eq!(
            decode_message_header(&[0x80, 0x04, 0x00]),
            Ok(MessageHeader::NeedMore)
        );
        assert_eq!(
            decode_message_header(&[0x03, b'a']),
            Ok(MessageHeader::Ready {
                len: 3,
                header_len: 1
            })
        );
    }

    #[test]
    fn max_message_accepted() {
        let mut v = Vec::new();
        encode_message_header(MAX_MESSAGE, &mut v).unwrap();
        assert_eq!(v, [0x80, 0x04, 0x00, 0x00]);
        assert_eq!(
            decode_message_header(&v),
            Ok(MessageHeader::Ready {
                len: MAX_MESSAGE,
                header_len: 4
            })
        );
    }

    #[test]
    fn max_message_plus_one_rejected() {
        let mut v = Vec::new();
        assert_eq!(
            encode_message_header(MAX_MESSAGE + 1, &mut v),
            Err(Error::TooLarge)
        );
        assert!(v.is_empty());
        assert_eq!(
            decode_message_header(&[0x80, 0x04, 0x00, 0x01]),
            Err(Error::TooLarge)
        );
    }

    #[test]
    fn noncanonical_len_rejected() {
        assert_eq!(
            decode_message_header(&[0x40, 0x05]),
            Err(Error::NonCanonicalVarint)
        );
    }
}
