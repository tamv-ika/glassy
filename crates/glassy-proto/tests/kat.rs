mod common;

use glassy_proto::{Error, crypto, varint};
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

fn fx(fixture: &[(String, Vec<u8>)], label: &str) -> Vec<u8> {
    fixture
        .iter()
        .find(|(l, _)| l == label)
        .unwrap_or_else(|| panic!("missing label {label}"))
        .1
        .clone()
}

fn arr<const N: usize>(v: Vec<u8>) -> [u8; N] {
    v.try_into().unwrap_or_else(|_| panic!("wrong length"))
}

// draft-irtf-cfrg-xchacha-03 Appendix A.3.1: AEAD_XCHACHA20_POLY1305.
#[test]
fn xchacha_draft_a31() {
    let f = common::read_fixture("xchacha20poly1305.hex");
    let key: [u8; 32] = arr(fx(&f, "key"));
    let nonce: [u8; 24] = arr(fx(&f, "nonce"));
    let aad = fx(&f, "aad");
    let pt = fx(&f, "plaintext");
    let mut expected = fx(&f, "ciphertext");
    expected.extend_from_slice(&fx(&f, "tag"));

    let sealed = crypto::xchacha_seal(&key, &nonce, &aad, &pt);
    assert_eq!(sealed, expected);
    assert_eq!(crypto::xchacha_open(&key, &nonce, &aad, &sealed), Ok(pt));

    let mut bad = sealed.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    assert_eq!(
        crypto::xchacha_open(&key, &nonce, &aad, &bad),
        Err(Error::AuthFailed)
    );
    assert_eq!(
        crypto::xchacha_open(&key, &nonce, &aad, &sealed[..15]),
        Err(Error::Truncated)
    );
}

// McGrew-Viega, "The Galois/Counter Mode of Operation (GCM)", Test Case 4 (AES-128).
// Exercises the aes-gcm dependency that Task 3 builds on.
#[test]
fn aes128gcm_test_case_4() {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes128Gcm, Nonce};
    let f = common::read_fixture("aes128gcm.hex");
    let cipher = Aes128Gcm::new_from_slice(&fx(&f, "key")).unwrap();
    let iv = fx(&f, "iv");
    let mut expected = fx(&f, "ciphertext");
    expected.extend_from_slice(&fx(&f, "tag"));
    let sealed = cipher
        .encrypt(
            &Nonce::try_from(&iv[..]).unwrap(),
            Payload {
                msg: &fx(&f, "plaintext"),
                aad: &fx(&f, "aad"),
            },
        )
        .unwrap();
    assert_eq!(sealed, expected);
}

// RFC 5869 Appendix A.1, Test Case 1.
#[test]
fn hkdf_rfc5869_case1() {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let f = common::read_fixture("hkdf_sha256.hex");
    let want = fx(&f, "okm");
    let hk = Hkdf::<Sha256>::new(Some(&fx(&f, "salt")), &fx(&f, "ikm"));
    let mut okm = vec![0u8; want.len()];
    hk.expand(&fx(&f, "info"), &mut okm).unwrap();
    assert_eq!(okm, want);
}

// RFC 4231 Section 4.3, Test Case 2.
#[test]
fn hmac_rfc4231_case2() {
    let f = common::read_fixture("hmac_sha256.hex");
    let got = crypto::hmac_sha256(&fx(&f, "key"), &[&fx(&f, "data")]);
    assert_eq!(got.to_vec(), fx(&f, "hmac"));
    // Splitting the message across parts must not change the tag.
    let data = fx(&f, "data");
    let (a, b) = data.split_at(7);
    assert_eq!(
        crypto::hmac_sha256(&fx(&f, "key"), &[a, b]).to_vec(),
        fx(&f, "hmac")
    );
}

#[test]
fn k_ticket_differs_from_k_ice() {
    let k_gs = [0x22u8; 32];
    let t = crypto::k_ticket(&k_gs);
    let i = crypto::k_ice(&k_gs);
    assert_ne!(t, i);
    assert_ne!(t, k_gs);
    assert_ne!(i, k_gs);
}

#[test]
fn packet_nonce_layout() {
    let n = crypto::packet_nonce(&[0x77; 16], 0x0102030405060708);
    assert_eq!(&n[..16], &[0x77; 16]);
    assert_eq!(&n[16..], &[1, 2, 3, 4, 5, 6, 7, 8]);
}
