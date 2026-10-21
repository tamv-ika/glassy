//! ClientHello parsing: the gateway only needs the server_name extension (RFC 6066 §3).

pub use super::QuicError;

const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_PADDING: u16 = 0x0015;
const NAME_TYPE_HOST: u8 = 0x00;

#[derive(Debug, PartialEq, Eq)]
pub enum HelloParse {
    /// More CRYPTO bytes are needed before the SNI can be found.
    Incomplete,
    Sni(String),
    NoSni,
}

/// Reads fields from a possibly truncated ClientHello: running out of available bytes is
/// `Incomplete`, running past the declared message length is `Malformed`.
struct Reader<'a> {
    b: &'a [u8],
    at: usize,
    end: usize,
}

enum Need {
    More,
    Bad,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], Need> {
        let next = self.at.checked_add(n).ok_or(Need::Bad)?;
        if next > self.end {
            return Err(Need::Bad);
        }
        let s = self.b.get(self.at..next).ok_or(Need::More)?;
        self.at = next;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, Need> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Need> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }

    fn skip_vec8(&mut self) -> Result<(), Need> {
        let n = usize::from(self.u8()?);
        self.take(n).map(|_| ())
    }

    fn skip_vec16(&mut self) -> Result<(), Need> {
        let n = usize::from(self.u16()?);
        self.take(n).map(|_| ())
    }
}

fn find_sni(r: &mut Reader<'_>) -> Result<Option<String>, Need> {
    r.take(2)?; // legacy_version
    r.take(32)?; // random
    r.skip_vec8()?; // legacy_session_id
    r.skip_vec16()?; // cipher_suites
    r.skip_vec8()?; // legacy_compression_methods
    let ext_total = usize::from(r.u16()?);
    let ext_end = r.at + ext_total;
    while r.at < ext_end {
        let ext_type = r.u16()?;
        let ext_len = usize::from(r.u16()?);
        if ext_type != EXT_SERVER_NAME {
            r.take(ext_len)?;
            continue;
        }
        let list_end = r.at + ext_len;
        r.u16()?; // server_name_list length
        while r.at < list_end {
            let name_type = r.u8()?;
            let name_len = usize::from(r.u16()?);
            let name = r.take(name_len)?;
            if name_type == NAME_TYPE_HOST {
                let host = std::str::from_utf8(name).map_err(|_| Need::Bad)?;
                return Ok(Some(host.to_owned()));
            }
        }
    }
    Ok(None)
}

/// Extracts the SNI host name from the (possibly partial) TLS handshake stream.
pub fn parse_sni(handshake: &[u8]) -> Result<HelloParse, QuicError> {
    if handshake.len() < 4 {
        return Ok(HelloParse::Incomplete);
    }
    if handshake[0] != HANDSHAKE_CLIENT_HELLO {
        return Err(QuicError::Malformed);
    }
    let msg_len = usize::from(handshake[1]) << 16
        | usize::from(handshake[2]) << 8
        | usize::from(handshake[3]);
    let mut r = Reader {
        b: handshake,
        at: 4,
        end: 4 + msg_len,
    };
    match find_sni(&mut r) {
        Ok(Some(host)) => Ok(HelloParse::Sni(host)),
        Ok(None) => Ok(HelloParse::NoSni),
        Err(Need::More) => Ok(HelloParse::Incomplete),
        Err(Need::Bad) => Err(QuicError::Malformed),
    }
}

/// Builds a minimal TLS 1.3 ClientHello handshake message carrying `sni`, padded with the
/// padding extension until the message is at least `pad_to` bytes; used by tests.
pub fn build_client_hello(sni: &str, pad_to: usize) -> Vec<u8> {
    let name = sni.as_bytes();
    let name_len = u16::try_from(name.len()).expect("short host name");
    let mut ext = Vec::new();
    ext.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
    ext.extend_from_slice(&(name_len + 5).to_be_bytes());
    ext.extend_from_slice(&(name_len + 3).to_be_bytes());
    ext.push(NAME_TYPE_HOST);
    ext.extend_from_slice(&name_len.to_be_bytes());
    ext.extend_from_slice(name);

    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0x5a; 32]); // random
    body.push(0); // empty legacy_session_id
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    body.extend_from_slice(&[0x01, 0x00]); // null compression

    // Message = 4-byte handshake header + body + 2-byte extensions length + extensions.
    let unpadded = 4 + body.len() + 2 + ext.len();
    if pad_to > unpadded {
        let pad = (pad_to - unpadded).saturating_sub(4);
        ext.extend_from_slice(&EXT_PADDING.to_be_bytes());
        ext.extend_from_slice(&u16::try_from(pad).expect("padding fits").to_be_bytes());
        ext.resize(ext.len() + pad, 0);
    }
    body.extend_from_slice(
        &u16::try_from(ext.len())
            .expect("extensions fit")
            .to_be_bytes(),
    );
    body.extend_from_slice(&ext);

    let len = u32::try_from(body.len()).expect("fits u24");
    let mut msg = vec![HANDSHAKE_CLIENT_HELLO];
    msg.extend_from_slice(&len.to_be_bytes()[1..]);
    msg.extend_from_slice(&body);
    msg
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::crypto_frames::{CryptoAssembler, crypto_frame};
    use crate::quic::initial::{client_initial_keys, decrypt_initial, parse_initial_header};

    fn sni(host: &str) -> Result<HelloParse, QuicError> {
        Ok(HelloParse::Sni(host.into()))
    }

    #[test]
    fn rfc9001_a2_sni_example_com() {
        let path = format!(
            "{}/tests/fixtures/rfc9001_a2_client_initial.hex",
            env!("CARGO_MANIFEST_DIR")
        );
        let d = hex::decode(
            std::fs::read_to_string(path)
                .unwrap()
                .split_whitespace()
                .collect::<String>(),
        )
        .unwrap();
        let p = decrypt_initial(
            &d,
            &client_initial_keys(parse_initial_header(&d).unwrap().dcid),
        )
        .unwrap();
        let mut a = CryptoAssembler::new(4096);
        a.ingest_payload(&p.payload).unwrap();
        assert_eq!(parse_sni(a.contiguous()), sni("example.com"));
    }

    #[test]
    fn out_of_order_frames_reassemble() {
        let ch = build_client_hello("a.wt.test", 1500);
        assert!(ch.len() >= 1500);
        let mut first = crypto_frame(1000, &ch[1000..]);
        first.extend_from_slice(&crypto_frame(0, &ch[..500]));
        let second = crypto_frame(500, &ch[500..1000]);
        let mut a = CryptoAssembler::new(4096);
        a.ingest_payload(&first).unwrap();
        // server_name sits in the first 500 bytes, so it is readable before the rest arrives.
        assert_eq!(parse_sni(a.contiguous()), sni("a.wt.test"));
        a.ingest_payload(&second).unwrap();
        assert_eq!(parse_sni(a.contiguous()), sni("a.wt.test"));
    }

    #[test]
    fn gap_before_sni_is_incomplete_until_filled() {
        let ch = build_client_hello("a.wt.test", 1500);
        let mut a = CryptoAssembler::new(4096);
        let mut later = crypto_frame(1000, &ch[1000..]);
        later.extend_from_slice(&crypto_frame(40, &ch[40..1000]));
        a.ingest_payload(&later).unwrap();
        assert_eq!(parse_sni(a.contiguous()), Ok(HelloParse::Incomplete));
        a.ingest_payload(&crypto_frame(0, &ch[..40])).unwrap();
        assert_eq!(parse_sni(a.contiguous()), sni("a.wt.test"));
    }

    #[test]
    fn partial_is_incomplete() {
        let ch = build_client_hello("a.wt.test", 1500);
        let mut a = CryptoAssembler::new(4096);
        a.ingest_payload(&crypto_frame(0, &ch[..30])).unwrap();
        assert_eq!(parse_sni(a.contiguous()), Ok(HelloParse::Incomplete));
    }

    #[test]
    fn padding_ping_ack_ignored() {
        let ch = build_client_hello("b.wt.test", 600);
        // PADDING, PADDING, PING, then a minimal ACK: largest 0, delay 0, 0 ranges, first range 0.
        let mut payload = vec![0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00];
        payload.extend_from_slice(&crypto_frame(0, &ch));
        let mut a = CryptoAssembler::new(4096);
        a.ingest_payload(&payload).unwrap();
        assert_eq!(parse_sni(a.contiguous()), sni("b.wt.test"));
    }

    #[test]
    fn client_hello_without_sni() {
        let mut ch = build_client_hello("c.wt.test", 0);
        // Rename the server_name extension (type 0x0000) to an unknown type.
        let at = ch
            .windows(4)
            .position(|w| w == [0x00, 0x00, 0x00, 0x0e])
            .unwrap();
        ch[at + 1] = 0x99;
        assert_eq!(parse_sni(&ch), Ok(HelloParse::NoSni));
    }
}
