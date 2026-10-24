//! ConnectInfo (spec §3.5), the client-side document decoder. Input: the base64url text.
#![no_main]

use glassy_proto::{decode_connect_info, encode_connect_info};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The Rust API takes `&str`; raw non-UTF-8 input is covered by the C++ fuzz_connect_info
    // target and by the differential (scripts/differential.sh).
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(ci) = decode_connect_info(text) else {
        return;
    };
    // Whatever the decoder accepts, the encoder can write back, and it decodes to the same value.
    let again = encode_connect_info(&ci).expect("decoded ConnectInfo must re-encode");
    assert_eq!(decode_connect_info(&again), Ok(ci));
});
