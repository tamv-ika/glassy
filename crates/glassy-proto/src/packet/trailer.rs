//! `client_addr` trailer the gateway appends when forwarding `CONNECT` (spec §4.2).

use super::TRAILER_V4_LEN;
use crate::Error;

const FAMILY_V4: u8 = 0x04;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Client address the gateway appends to a forwarded `CONNECT`.
pub struct ClientAddrV4 {
    /// IPv4 address octets.
    pub ip: [u8; 4],
    /// UDP source port, host order.
    pub port: u16,
}

/// Appends `ipv4(4) | port(u16 BE) | reserved(1)=0 | family(1)=0x04`.
pub fn append_trailer(b: &mut Vec<u8>, a: ClientAddrV4) {
    b.extend_from_slice(&a.ip);
    b.extend_from_slice(&a.port.to_be_bytes());
    b.push(0);
    b.push(FAMILY_V4);
}

/// Splits a forwarded packet into the original datagram and the client address.
/// Only the game server calls this; it knows the gateway always appended a trailer.
pub fn split_trailer(b: &[u8]) -> Result<(&[u8], ClientAddrV4), Error> {
    let split = b
        .len()
        .checked_sub(TRAILER_V4_LEN)
        .ok_or(Error::BadTrailer)?;
    let (body, t) = b.split_at(split);
    if t[7] != FAMILY_V4 || t[6] != 0 {
        return Err(Error::BadTrailer);
    }
    let addr = ClientAddrV4 {
        ip: [t[0], t[1], t[2], t[3]],
        port: u16::from_be_bytes([t[4], t[5]]),
    };
    Ok((body, addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailer_roundtrip() {
        let a = ClientAddrV4 {
            ip: [203, 0, 113, 7],
            port: 4433,
        };
        let mut b = vec![1, 2, 3];
        append_trailer(&mut b, a);
        assert_eq!(b.len(), 3 + TRAILER_V4_LEN);
        assert_eq!(&b[3..], &[203, 0, 113, 7, 0x11, 0x51, 0, 4]);
        assert_eq!(split_trailer(&b), Ok((&[1u8, 2, 3][..], a)));
    }

    #[test]
    fn trailer_alone_leaves_empty_body() {
        let a = ClientAddrV4 {
            ip: [1; 4],
            port: 1,
        };
        let mut b = Vec::new();
        append_trailer(&mut b, a);
        assert_eq!(split_trailer(&b), Ok((&[][..], a)));
    }

    #[test]
    fn short_input_is_bad_trailer() {
        assert_eq!(
            split_trailer(&[0, 0, 0, 0, 0, 0, 4]),
            Err(Error::BadTrailer)
        );
        assert_eq!(split_trailer(&[]), Err(Error::BadTrailer));
    }

    #[test]
    fn family_must_be_v4() {
        for fam in [0x06u8, 0x00, 0x05] {
            let b = [1, 2, 3, 4, 0, 80, 0, fam];
            assert_eq!(split_trailer(&b), Err(Error::BadTrailer), "{fam}");
        }
    }

    #[test]
    fn reserved_must_be_zero() {
        let b = [1, 2, 3, 4, 0, 80, 1, 4];
        assert_eq!(split_trailer(&b), Err(Error::BadTrailer));
    }
}
