//! Frames carried inside `DATA` packets (spec §5): ACK, STREAM and DATAGRAM.

use crate::Error;
use crate::consts::MAX_DATAGRAM;
use crate::varint;

const TYPE_ACK: u8 = 0x01;
const TYPE_STREAM: u8 = 0x02;
const TYPE_DATAGRAM: u8 = 0x03;

/// `ack_delay` value meaning "no timing information" (spec §5.2).
pub const ACK_DELAY_UNKNOWN: u16 = 0xFFFF;

/// Decoded ACK frame (spec §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckFrame {
    /// Low 32 bits of the largest received packet number.
    pub largest_pn_low: u32,
    /// Delay in 32 microsecond units, or [`ACK_DELAY_UNKNOWN`].
    pub ack_delay: u16,
    /// Bit `n` set means `largest - 1 - n` was received.
    pub ack_bits: u64,
}

/// One frame inside a `DATA` payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame<'a> {
    /// Acknowledgement (spec §5.2).
    Ack(AckFrame),
    /// Reliable stream bytes starting at `offset` (spec §5.3).
    Stream {
        /// Byte offset of `data` within the stream.
        offset: u64,
        /// Payload bytes.
        data: &'a [u8],
    },
    /// Unreliable datagram payload (spec §5.1).
    Datagram(&'a [u8]),
}

/// True if packet `largest - 1 - n` was received. Bits beyond the 64-bit window are unknown,
/// which callers must treat as lost (spec §5.2), so `n >= 64` yields false.
pub fn ack_bit(bits: u64, n: u32) -> bool {
    n < 64 && (bits >> n) & 1 == 1
}

/// Appends `f` to `out`. On error `out` is left unchanged.
pub fn encode_frame(f: &Frame, out: &mut Vec<u8>) -> Result<(), Error> {
    let start = out.len();
    let r = encode_into(f, out);
    if r.is_err() {
        out.truncate(start);
    }
    r
}

fn encode_into(f: &Frame, out: &mut Vec<u8>) -> Result<(), Error> {
    match f {
        Frame::Ack(a) => {
            out.push(TYPE_ACK);
            out.extend_from_slice(&a.largest_pn_low.to_be_bytes());
            out.extend_from_slice(&a.ack_delay.to_be_bytes());
            // Canonical form (spec §5.2): 0xFF bytes are never sent, so the mask is derived.
            let mut mask = 0u8;
            let mut present = [0u8; 8];
            let mut n = 0;
            for (i, b) in a.ack_bits.to_le_bytes().into_iter().enumerate() {
                if b != 0xFF {
                    mask |= 1 << i;
                    present[n] = b;
                    n += 1;
                }
            }
            out.push(mask);
            out.extend_from_slice(&present[..n]);
        }
        Frame::Stream { offset, data } => {
            check_stream_end(*offset, data.len() as u64)?;
            out.push(TYPE_STREAM);
            varint::encode(*offset, out)?;
            varint::encode(data.len() as u64, out)?;
            out.extend_from_slice(data);
        }
        Frame::Datagram(data) => {
            if data.len() > MAX_DATAGRAM {
                return Err(Error::TooLarge);
            }
            out.push(TYPE_DATAGRAM);
            varint::encode(data.len() as u64, out)?;
            out.extend_from_slice(data);
        }
    }
    Ok(())
}

fn check_stream_end(offset: u64, len: u64) -> Result<(), Error> {
    // The encoder path may pass any u64 offset, so the sum must saturate rather than wrap;
    // saturating at u64::MAX still exceeds the limit and is rejected.
    if offset.saturating_add(len) > varint::MAX {
        return Err(Error::ValueTooLarge);
    }
    Ok(())
}

/// Decodes a whole plaintext payload. All or nothing (spec §5.0): the first error in byte
/// order is returned and no partial frame list escapes.
pub fn decode_frames(plaintext: &[u8]) -> Result<Vec<Frame<'_>>, Error> {
    let mut frames = Vec::new();
    let mut seen_ack = false;
    let mut rest = plaintext;
    while let Some((&ty, body)) = rest.split_first() {
        let (frame, used) = match ty {
            TYPE_ACK => {
                if seen_ack {
                    return Err(Error::DuplicateAck);
                }
                seen_ack = true;
                decode_ack(body)?
            }
            TYPE_STREAM => decode_stream(body)?,
            TYPE_DATAGRAM => decode_datagram(body)?,
            _ => return Err(Error::BadType),
        };
        frames.push(frame);
        rest = &body[used..];
    }
    Ok(frames)
}

fn decode_ack(body: &[u8]) -> Result<(Frame<'_>, usize), Error> {
    let head = body.get(..7).ok_or(Error::Truncated)?;
    let largest_pn_low = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    let ack_delay = u16::from_be_bytes([head[4], head[5]]);
    let mask = head[6];
    let mut bits = u64::MAX;
    let mut used = 7;
    for i in 0..8 {
        if mask & (1 << i) == 0 {
            continue;
        }
        let b = *body.get(used).ok_or(Error::Truncated)?;
        // A sent 0xFF byte has a shorter canonical encoding (spec §5.2).
        if b == 0xFF {
            return Err(Error::NonCanonicalAck);
        }
        used += 1;
        bits &= !(0xFFu64 << (8 * i));
        bits |= u64::from(b) << (8 * i);
    }
    let ack = AckFrame {
        largest_pn_low,
        ack_delay,
        ack_bits: bits,
    };
    Ok((Frame::Ack(ack), used))
}

fn decode_stream(body: &[u8]) -> Result<(Frame<'_>, usize), Error> {
    let (offset, n1) = varint::decode(body)?;
    let (len, n2) = varint::decode(&body[n1..])?;
    check_stream_end(offset, len)?;
    let start = n1 + n2;
    let end = start
        .checked_add(usize::try_from(len).map_err(|_| Error::Truncated)?)
        .ok_or(Error::Truncated)?;
    let data = body.get(start..end).ok_or(Error::Truncated)?;
    Ok((Frame::Stream { offset, data }, end))
}

fn decode_datagram(body: &[u8]) -> Result<(Frame<'_>, usize), Error> {
    let (len, n) = varint::decode(body)?;
    if len > MAX_DATAGRAM as u64 {
        return Err(Error::TooLarge);
    }
    let end = n + len as usize;
    let data = body.get(n..end).ok_or(Error::Truncated)?;
    Ok((Frame::Datagram(data), end))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn ack(bits: u64) -> Frame<'static> {
        Frame::Ack(AckFrame {
            largest_pn_low: 0x0102_0304,
            ack_delay: 0x0506,
            ack_bits: bits,
        })
    }

    fn enc(f: &Frame) -> Vec<u8> {
        let mut v = Vec::new();
        encode_frame(f, &mut v).unwrap();
        v
    }

    #[test]
    fn ack_no_loss_is_8_bytes() {
        let b = enc(&ack(u64::MAX));
        assert_eq!(b, [0x01, 1, 2, 3, 4, 5, 6, 0x00]);
        assert_eq!(b.len(), 8);
        assert_eq!(decode_frames(&b), Ok(vec![ack(u64::MAX)]));
    }

    #[test]
    fn ack_omits_ff_bytes() {
        let b = enc(&ack(0xFFFF_FFFF_FFFF_FF00));
        assert_eq!(b, [0x01, 1, 2, 3, 4, 5, 6, 0x01, 0x00]);
        assert_eq!(b.len(), 9);
        assert_eq!(decode_frames(&b), Ok(vec![ack(0xFFFF_FFFF_FFFF_FF00)]));
        // A middle byte only: mask bit 3, ascending byte order for several bytes.
        let b = enc(&ack(0xFFFF_FFFF_12FF_34FF));
        assert_eq!(b, [0x01, 1, 2, 3, 4, 5, 6, 0b0000_1010, 0x34, 0x12]);
    }

    #[test]
    fn ack_bit_semantics() {
        // Bit n means largest - 1 - n was received.
        assert!(ack_bit(0b1, 0));
        assert!(!ack_bit(0b1, 1));
        assert!(ack_bit(1 << 63, 63));
        assert!(!ack_bit(u64::MAX, 64));
        assert!(!ack_bit(u64::MAX, u32::MAX));
        assert!(!ack_bit(0, 5));
    }

    #[test]
    fn empty_payload_has_no_frames() {
        assert_eq!(decode_frames(&[]), Ok(vec![]));
    }

    #[test]
    fn unknown_type_is_bad_type() {
        assert_eq!(decode_frames(&[0x04]), Err(Error::BadType));
        assert_eq!(decode_frames(&[0x00]), Err(Error::BadType));
        // All or nothing: a good frame before the bad one yields nothing.
        assert_eq!(decode_frames(&[0x03, 0x00, 0x04]), Err(Error::BadType));
    }

    #[test]
    fn second_ack_is_duplicate() {
        let mut p = enc(&ack(u64::MAX));
        p.extend(enc(&ack(u64::MAX)));
        assert_eq!(decode_frames(&p), Err(Error::DuplicateAck));
    }

    #[test]
    fn present_ff_byte_is_non_canonical_ack() {
        let p = [0x01, 0, 0, 0, 1, 0, 0, 0x01, 0xFF];
        assert_eq!(decode_frames(&p), Err(Error::NonCanonicalAck));
    }

    #[test]
    fn truncated_frames() {
        assert_eq!(decode_frames(&[0x01, 0, 0, 0]), Err(Error::Truncated));
        // Mask promises two bytes, one given.
        assert_eq!(
            decode_frames(&[0x01, 0, 0, 0, 1, 0, 0, 0x03, 0x00]),
            Err(Error::Truncated)
        );
        assert_eq!(decode_frames(&[0x02]), Err(Error::Truncated));
        assert_eq!(decode_frames(&[0x02, 0x00]), Err(Error::Truncated));
        assert_eq!(
            decode_frames(&[0x02, 0x00, 0x03, 0xaa]),
            Err(Error::Truncated)
        );
        assert_eq!(decode_frames(&[0x03]), Err(Error::Truncated));
        assert_eq!(decode_frames(&[0x03, 0x02, 0xaa]), Err(Error::Truncated));
    }

    #[test]
    fn non_canonical_varint_rejected() {
        assert_eq!(
            decode_frames(&[0x02, 0x40, 0x01, 0x00]),
            Err(Error::NonCanonicalVarint)
        );
        assert_eq!(
            decode_frames(&[0x03, 0x40, 0x00]),
            Err(Error::NonCanonicalVarint)
        );
    }

    #[test]
    fn stream_end_past_2_62_is_value_too_large() {
        let mut p = vec![0x02];
        varint::encode(varint::MAX, &mut p).unwrap();
        p.push(0x01); // len = 1
        p.push(0xaa);
        assert_eq!(decode_frames(&p), Err(Error::ValueTooLarge));
        let f = Frame::Stream {
            offset: varint::MAX,
            data: &[0],
        };
        let mut out = vec![9];
        assert_eq!(encode_frame(&f, &mut out), Err(Error::ValueTooLarge));
        assert_eq!(out, [9]);
        // Exactly at the limit is fine.
        let f = Frame::Stream {
            offset: varint::MAX,
            data: &[],
        };
        assert_eq!(decode_frames(&enc(&f)), Ok(vec![f]));
    }

    #[test]
    fn datagram_limit_is_1100() {
        let big = vec![7u8; 1101];
        let mut out = Vec::new();
        assert_eq!(
            encode_frame(&Frame::Datagram(&big), &mut out),
            Err(Error::TooLarge)
        );
        assert!(out.is_empty());
        let ok = Frame::Datagram(&big[..1100]);
        assert_eq!(decode_frames(&enc(&ok)), Ok(vec![ok]));
        let mut p = vec![0x03];
        varint::encode(1101, &mut p).unwrap();
        p.extend(&big);
        assert_eq!(decode_frames(&p), Err(Error::TooLarge));
    }

    #[test]
    fn zero_length_frames_are_valid() {
        let p = [0x02, 0x05, 0x00, 0x03, 0x00];
        assert_eq!(
            decode_frames(&p),
            Ok(vec![
                Frame::Stream {
                    offset: 5,
                    data: &[]
                },
                Frame::Datagram(&[])
            ])
        );
    }

    fn frame_strategy() -> impl Strategy<Value = (u8, u64, u32, u16, u64, Vec<u8>)> {
        (
            0u8..3,
            prop_oneof![0u64..100, 0u64..(1 << 20), 0u64..=(varint::MAX - 2048)],
            any::<u32>(),
            any::<u16>(),
            prop_oneof![any::<u64>(), Just(u64::MAX), Just(0u64)],
            proptest::collection::vec(any::<u8>(), 0..=300),
        )
    }

    proptest! {
        #[test]
        fn frames_roundtrip(specs in proptest::collection::vec(frame_strategy(), 0..8)) {
            let mut frames = Vec::new();
            let mut ack_used = false;
            for (kind, offset, pn, delay, bits, data) in &specs {
                match kind {
                    0 if !ack_used => {
                        ack_used = true;
                        frames.push(Frame::Ack(AckFrame {
                            largest_pn_low: *pn,
                            ack_delay: *delay,
                            ack_bits: *bits,
                        }));
                    }
                    1 => frames.push(Frame::Stream { offset: *offset, data }),
                    _ => frames.push(Frame::Datagram(data)),
                }
            }
            let mut bytes = Vec::new();
            for f in &frames {
                encode_frame(f, &mut bytes).unwrap();
            }
            // Keep to what seal_data accepts.
            prop_assume!(bytes.len() <= 1171);
            let decoded = decode_frames(&bytes).unwrap();
            prop_assert_eq!(&decoded, &frames);
            let mut again = Vec::new();
            for f in &decoded {
                encode_frame(f, &mut again).unwrap();
            }
            prop_assert_eq!(again, bytes);
        }
    }
}
