mod common;

use glassy_proto::{Error, varint};
use proptest::prelude::*;

// RFC 9000 Appendix A.1: sample variable-length integer encodings.
#[test]
fn varint_rfc9000_examples() {
    let expected: [(&str, u64); 4] = [
        ("eight_byte_151288809941952652", 151_288_809_941_952_652),
        ("four_byte_494878333", 494_878_333),
        ("two_byte_15293", 15_293),
        ("one_byte_37", 37),
    ];
    let fixture = common::read_fixture("varint.hex");
    for (label, value) in expected {
        let bytes = &fixture.iter().find(|(l, _)| l == label).expect("label").1;
        assert_eq!(varint::decode(bytes), Ok((value, bytes.len())), "{label}");
        let mut out = Vec::new();
        varint::encode(value, &mut out).unwrap();
        assert_eq!(&out, bytes, "{label}");
    }
    // Valid in the RFC, but glassy requires the shortest form.
    let bytes = &fixture
        .iter()
        .find(|(l, _)| l == "two_byte_37_non_canonical")
        .expect("label")
        .1;
    assert_eq!(varint::decode(bytes), Err(Error::NonCanonicalVarint));
}

#[test]
fn varint_decode_truncated() {
    assert_eq!(varint::decode(&[0x40]), Err(Error::Truncated));
    assert_eq!(varint::decode(&[]), Err(Error::Truncated));
}

proptest! {
    #[test]
    fn varint_roundtrip(v in 0..=varint::MAX) {
        let mut out = Vec::new();
        varint::encode(v, &mut out).unwrap();
        prop_assert_eq!(varint::decode(&out), Ok((v, varint::encoded_len(v).unwrap())));
    }
}
