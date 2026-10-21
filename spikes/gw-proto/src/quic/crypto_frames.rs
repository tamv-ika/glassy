//! Reassembly of CRYPTO frames from Initial payloads (RFC 9000 §19.6).
//!
//! Browsers send ClientHellos that span several Initial packets and may reorder the CRYPTO
//! frames inside them (Chrome's "chaos protection"), so the gateway reassembles by offset.

pub use super::QuicError;
use super::read_varint;

const FRAME_PADDING: u8 = 0x00;
const FRAME_PING: u8 = 0x01;
const FRAME_ACK: u8 = 0x02;
const FRAME_ACK_ECN: u8 = 0x03;
const FRAME_CRYPTO: u8 = 0x06;

/// Collects CRYPTO stream bytes by offset, bounded by `max_bytes` so a hostile client cannot make
/// the gateway buffer arbitrary amounts before routing.
pub struct CryptoAssembler {
    buf: Vec<u8>,
    filled: Vec<bool>,
    max_bytes: usize,
}

struct Cursor<'a> {
    b: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn varint(&mut self) -> Result<u64, QuicError> {
        let (v, n) = read_varint(self.b.get(self.at..).ok_or(QuicError::Malformed)?)
            .map_err(|_| QuicError::Malformed)?;
        self.at += n;
        Ok(v)
    }

    fn usize_varint(&mut self) -> Result<usize, QuicError> {
        usize::try_from(self.varint()?).map_err(|_| QuicError::TooLarge)
    }
}

impl CryptoAssembler {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            buf: Vec::new(),
            filled: Vec::new(),
            max_bytes,
        }
    }

    /// Consumes every frame in a decrypted Initial payload; only frames legal in Initial packets
    /// are accepted (RFC 9000 §12.4).
    pub fn ingest_payload(&mut self, payload: &[u8]) -> Result<(), QuicError> {
        let mut c = Cursor { b: payload, at: 0 };
        while c.at < payload.len() {
            let frame_type = payload[c.at];
            c.at += 1;
            match frame_type {
                FRAME_PADDING | FRAME_PING => {}
                FRAME_ACK | FRAME_ACK_ECN => {
                    let _largest = c.varint()?;
                    let _delay = c.varint()?;
                    let ranges = c.varint()?;
                    let _first_range = c.varint()?;
                    for _ in 0..ranges {
                        let _gap = c.varint()?;
                        let _len = c.varint()?;
                    }
                    if frame_type == FRAME_ACK_ECN {
                        for _ in 0..3 {
                            c.varint()?;
                        }
                    }
                }
                FRAME_CRYPTO => {
                    let offset = c.usize_varint()?;
                    let len = c.usize_varint()?;
                    let end = offset.checked_add(len).ok_or(QuicError::TooLarge)?;
                    if end > self.max_bytes {
                        return Err(QuicError::TooLarge);
                    }
                    let data = payload.get(c.at..c.at + len).ok_or(QuicError::Malformed)?;
                    c.at += len;
                    self.store(offset, data);
                }
                _ => return Err(QuicError::UnexpectedFrame),
            }
        }
        Ok(())
    }

    fn store(&mut self, offset: usize, data: &[u8]) {
        let end = offset + data.len();
        if self.buf.len() < end {
            self.buf.resize(end, 0);
            self.filled.resize(end, false);
        }
        self.buf[offset..end].copy_from_slice(data);
        self.filled[offset..end].fill(true);
    }

    /// The reassembled bytes from offset 0 up to the first gap.
    pub fn contiguous(&self) -> &[u8] {
        let len = self
            .filled
            .iter()
            .position(|&f| !f)
            .unwrap_or(self.filled.len());
        &self.buf[..len]
    }
}

/// Encodes one CRYPTO frame with 4-byte varints; used by tests to build Initial payloads.
pub fn crypto_frame(offset: u64, data: &[u8]) -> Vec<u8> {
    let mut f = vec![0x06];
    let offset = u32::try_from(offset).expect("test offsets fit 30 bits");
    let len = u32::try_from(data.len()).expect("test frames fit 30 bits");
    f.extend_from_slice(&(offset | 0x8000_0000).to_be_bytes());
    f.extend_from_slice(&(len | 0x8000_0000).to_be_bytes());
    f.extend_from_slice(data);
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_frame_rejected() {
        assert_eq!(
            CryptoAssembler::new(4096).ingest_payload(&[0x08, 0, 0]),
            Err(QuicError::UnexpectedFrame)
        );
    }

    #[test]
    fn too_large_rejected() {
        assert_eq!(
            CryptoAssembler::new(4096).ingest_payload(&crypto_frame(5000, &[0; 10])),
            Err(QuicError::TooLarge)
        );
    }

    #[test]
    fn gap_stops_contiguous_prefix() {
        let mut a = CryptoAssembler::new(4096);
        a.ingest_payload(&crypto_frame(10, b"world")).unwrap();
        assert_eq!(a.contiguous(), b"");
        a.ingest_payload(&crypto_frame(0, b"hello-----")).unwrap();
        assert_eq!(a.contiguous(), b"hello-----world");
    }
}
