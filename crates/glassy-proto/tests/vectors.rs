//! Golden-vector generators and checkers. Each file's `write_*` (ignored; regenerates the
//! file) sits next to its `check_*` (re-reads the file and compares every case).
//! Format: see the vector file format in the SP1 plan.

mod common;

use aes_gcm::aead::AeadInOut;
use aes_gcm::{Aes128Gcm, KeyInit};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use glassy_proto::connect_info::{
    ConnectInfo, NativeInfo, WebRtcInfo, WtInfo, decode_connect_info, encode_connect_info,
};
use glassy_proto::crypto::{k_ticket, packet_nonce, xchacha_seal};
use glassy_proto::frame::{Frame, decode_frames, encode_frame};
use glassy_proto::ice::ice_pwd;
use glassy_proto::message::{MessageHeader, decode_message_header, encode_message_header};
use glassy_proto::packet::pn::{ReplayWindow, decode_pn};
use glassy_proto::packet::{
    Accept, ClientAddrV4, Reject, append_trailer, build_accept, build_connect, build_reject,
    open_accept, open_data, open_disconnect, open_reject, parse_connect, parse_header, peek_reply,
    reject_reason, seal_data, seal_disconnect, split_trailer, verify_connect,
};
use glassy_proto::retry::{mint_retry_token, retry_token_odcid, validate_retry_token};
use glassy_proto::routing_ticket::{
    RoutingKeyRing, RoutingTicket, from_sni, from_ufrag, open_routing, seal_routing, to_sni_labels,
    to_ufrag,
};
use glassy_proto::server_ticket::{
    NativeKeys, ServerKeyRing, ServerTicket, open_server, seal_server,
};
use glassy_proto::wt::{WT_PATH_PREFIX, parse_wt_path, wt_path};
use glassy_proto::{Error, transport, varint};
use serde_json::{Value, json};

// ---------------------------------------------------------------- routing_ticket.json

const RT_FILE: &str = "routing_ticket.json";
const RT_SNI_SUFFIX: &str = "wt.example.test";
const RT_NOW: u32 = 1_900_000_000;
const RT_EXPIRY: u32 = 2_000_000_000;

fn rt_ring() -> RoutingKeyRing {
    RoutingKeyRing::new(1, [0x11; 16])
}

fn rt_ticket(transports: u8, expiry: u32) -> RoutingTicket {
    RoutingTicket {
        server_id: [0xab; 16],
        session_id: [1, 2, 3, 4, 5, 6, 7, 8],
        expiry,
        transports,
    }
}

/// Seals a hand-built body (possibly with reserved bits set) under `K_gw`.
fn rt_seal_raw(t: &RoutingTicket, flags: u8) -> [u8; 60] {
    let mut body = [0u8; 30];
    body[..16].copy_from_slice(&t.server_id);
    body[16..24].copy_from_slice(&t.session_id);
    body[24..28].copy_from_slice(&t.expiry.to_be_bytes());
    body[28] = t.transports;
    body[29] = flags;
    let header = [1u8, 1];
    let nonce = [0x88u8; 12];
    let tag = Aes128Gcm::new(&[0x11u8; 16].into())
        .encrypt_inout_detached(&nonce.into(), &header, (&mut body[..]).into())
        .unwrap();
    let mut out = [0u8; 60];
    out[..2].copy_from_slice(&header);
    out[2..14].copy_from_slice(&nonce);
    out[14..44].copy_from_slice(&body);
    out[44..].copy_from_slice(&tag);
    out
}

struct RtCase {
    name: &'static str,
    ticket: Vec<u8>,
    via: u8,
    now: u32,
    connect_session_id: Option<[u8; 8]>,
    /// True for cases that also pin the ufrag and SNI encodings.
    encodings: bool,
    expect: Result<RoutingTicket, Error>,
}

fn rt_cases() -> Vec<RtCase> {
    let ring = rt_ring();
    let nonce = [0x88u8; 12];
    let native = rt_ticket(transport::NATIVE, RT_EXPIRY);
    let browser = rt_ticket(transport::WEBRTC | transport::WEBTRANSPORT, RT_EXPIRY);
    let sealed_native = seal_routing(&native, &ring, nonce);
    let sealed_browser = seal_routing(&browser, &ring, nonce);
    let case = |name, ticket: &[u8], via, expect| RtCase {
        name,
        ticket: ticket.to_vec(),
        via,
        now: RT_NOW,
        connect_session_id: None,
        encodings: false,
        expect,
    };

    let mut v = vec![RtCase {
        connect_session_id: Some(native.session_id),
        ..case(
            "valid_native",
            &sealed_native,
            transport::NATIVE,
            Ok(native.clone()),
        )
    }];
    v.push(RtCase {
        encodings: true,
        ..case(
            "valid_webrtc_ufrag",
            &sealed_browser,
            transport::WEBRTC,
            Ok(browser.clone()),
        )
    });
    v.push(RtCase {
        encodings: true,
        ..case(
            "valid_wt_sni",
            &sealed_browser,
            transport::WEBTRANSPORT,
            Ok(browser.clone()),
        )
    });
    v.push(RtCase {
        now: RT_EXPIRY,
        ..case(
            "expiry_equals_now",
            &sealed_native,
            transport::NATIVE,
            Ok(native.clone()),
        )
    });
    v.push(RtCase {
        now: RT_EXPIRY + 1,
        ..case(
            "expired_by_one",
            &sealed_native,
            transport::NATIVE,
            Err(Error::Expired),
        )
    });
    v.push(case(
        "bad_length_59",
        &sealed_native[..59],
        transport::NATIVE,
        Err(Error::BadLength),
    ));
    let mut t = sealed_native;
    t[0] = 2;
    v.push(case(
        "bad_version",
        &t,
        transport::NATIVE,
        Err(Error::BadVersion),
    ));
    let mut t = sealed_native;
    t[1] = 2;
    v.push(case(
        "unknown_key",
        &t,
        transport::NATIVE,
        Err(Error::UnknownKey),
    ));
    let mut t = sealed_native;
    t[59] ^= 1;
    v.push(case(
        "tampered_tag",
        &t,
        transport::NATIVE,
        Err(Error::AuthFailed),
    ));
    v.push(case(
        "flags_nonzero",
        &rt_seal_raw(&native, 1),
        transport::NATIVE,
        Err(Error::ReservedNonzero),
    ));
    let reserved = rt_ticket(transport::NATIVE | 0x08, RT_EXPIRY);
    v.push(case(
        "reserved_transport_bit",
        &rt_seal_raw(&reserved, 0),
        transport::NATIVE,
        Err(Error::ReservedNonzero),
    ));
    v.push(case(
        "transport_not_allowed",
        &sealed_native,
        transport::WEBRTC,
        Err(Error::BadTransport),
    ));
    v.push(RtCase {
        connect_session_id: Some([9; 8]),
        ..case(
            "session_mismatch",
            &sealed_native,
            transport::NATIVE,
            Err(Error::SessionMismatch),
        )
    });
    v
}

#[test]
#[ignore = "regenerates vectors/routing_ticket.json"]
fn write_routing_ticket_vectors() {
    let cases: Vec<Value> = rt_cases()
        .iter()
        .map(|c| {
            let mut m = serde_json::Map::new();
            m.insert("name".into(), json!(c.name));
            m.insert("ticket_hex".into(), json!(hex::encode(&c.ticket)));
            m.insert("via".into(), json!(c.via));
            m.insert("now".into(), json!(c.now));
            if let Some(s) = c.connect_session_id {
                m.insert("connect_session_id_hex".into(), json!(hex::encode(s)));
            }
            if c.encodings {
                let raw: [u8; 60] = c.ticket.as_slice().try_into().unwrap();
                m.insert("ufrag".into(), json!(to_ufrag(&raw)));
                m.insert(
                    "sni".into(),
                    json!(format!("{}.{RT_SNI_SUFFIX}", to_sni_labels(&raw))),
                );
            }
            match &c.expect {
                Ok(t) => m.insert(
                    "expect".into(),
                    json!({
                        "server_id_hex": hex::encode(t.server_id),
                        "session_id_hex": hex::encode(t.session_id),
                        "expiry": t.expiry,
                        "transports": t.transports,
                    }),
                ),
                Err(e) => m.insert("error".into(), json!(e.code())),
            };
            Value::Object(m)
        })
        .collect();
    common::write_vectors(RT_FILE, &json!({ "cases": cases }));
}

#[test]
fn check_routing_ticket_vectors() {
    let file = common::read_vectors(RT_FILE);
    let cases = file["cases"].as_array().unwrap();
    assert_eq!(cases.len(), rt_cases().len());
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let ticket = hex::decode(c["ticket_hex"].as_str().unwrap()).unwrap();
        let via = c["via"].as_u64().unwrap() as u8;
        let now = c["now"].as_u64().unwrap() as u32;
        let sid: Option<[u8; 8]> = c.get("connect_session_id_hex").map(|h| {
            hex::decode(h.as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        });
        let got = open_routing(&ticket, &rt_ring(), now, via, sid.as_ref());
        match c.get("error") {
            Some(code) => assert_eq!(
                got.map_err(|e| e.code()),
                Err(code.as_str().unwrap()),
                "{name}"
            ),
            None => {
                let t = got.unwrap_or_else(|e| panic!("{name}: {e}"));
                let e = &c["expect"];
                assert_eq!(
                    hex::encode(t.server_id),
                    e["server_id_hex"].as_str().unwrap(),
                    "{name}"
                );
                assert_eq!(
                    hex::encode(t.session_id),
                    e["session_id_hex"].as_str().unwrap(),
                    "{name}"
                );
                assert_eq!(u64::from(t.expiry), e["expiry"].as_u64().unwrap(), "{name}");
                assert_eq!(
                    u64::from(t.transports),
                    e["transports"].as_u64().unwrap(),
                    "{name}"
                );
            }
        }
        if let Some(u) = c.get("ufrag") {
            assert_eq!(
                from_ufrag(u.as_str().unwrap()).unwrap().as_slice(),
                ticket,
                "{name}"
            );
            assert_eq!(
                to_ufrag(&ticket.as_slice().try_into().unwrap()),
                u.as_str().unwrap()
            );
        }
        if let Some(s) = c.get("sni") {
            let host = s.as_str().unwrap();
            assert_eq!(
                from_sni(host, RT_SNI_SUFFIX).unwrap().as_slice(),
                ticket,
                "{name}"
            );
            assert_eq!(
                from_sni(&host.to_uppercase(), RT_SNI_SUFFIX)
                    .unwrap()
                    .as_slice(),
                ticket,
                "{name}"
            );
        }
    }
}

// ---------------------------------------------------------------- server_ticket.json

const ST_FILE: &str = "server_ticket.json";
const ST_NOW: u32 = 1_900_000_000;
const ST_EXPIRY: u32 = 2_000_000_000;
const ST_SERVER_ID: [u8; 16] = [0xab; 16];
const ST_NONCE: [u8; 24] = [0x99; 24];

fn st_ring() -> ServerKeyRing {
    ServerKeyRing::new(1, [0x22; 32])
}

fn st_ticket(tr: u8, user_id: &str, metadata: Vec<u8>) -> ServerTicket {
    ServerTicket {
        user_id: user_id.into(),
        server_id: ST_SERVER_ID,
        session_id: [1, 2, 3, 4, 5, 6, 7, 8],
        expiry: ST_EXPIRY,
        transport: tr,
        native_keys: (tr == transport::NATIVE).then_some(NativeKeys {
            c2s: [0x44; 32],
            s2c: [0x55; 32],
        }),
        metadata,
    }
}

/// Seals a hand-built body under `K_ticket` with the fixed nonce and `ver | key_id` AAD.
fn st_seal_raw(body: &[u8]) -> Vec<u8> {
    let mut out = vec![1u8, 1];
    out.extend_from_slice(&ST_NONCE);
    out.extend(xchacha_seal(
        &k_ticket(&[0x22; 32]),
        &ST_NONCE,
        &[1, 1],
        body,
    ));
    out
}

/// Body after `user_id`: server_id | session_id | expiry | transport, then `rest`.
fn st_body(user_id_len: u8, user_id: &[u8], transport: u8, rest: &[u8]) -> Vec<u8> {
    let mut b = vec![user_id_len];
    b.extend_from_slice(user_id);
    b.extend_from_slice(&ST_SERVER_ID);
    b.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    b.extend_from_slice(&ST_EXPIRY.to_be_bytes());
    b.push(transport);
    b.extend_from_slice(rest);
    b
}

struct StCase {
    name: &'static str,
    ticket: Vec<u8>,
    now: u32,
    self_server_id: [u8; 16],
    via: u8,
    expect: Result<ServerTicket, Error>,
}

fn st_cases() -> Vec<StCase> {
    let ring = st_ring();
    let seal = |t: &ServerTicket| seal_server(t, &ring, ST_NONCE).unwrap();
    let native = st_ticket(transport::NATIVE, "user-1", b"meta".to_vec());
    let webrtc = st_ticket(transport::WEBRTC, "user-1", Vec::new());
    let wt_max = st_ticket(
        transport::WEBTRANSPORT,
        &"u".repeat(64),
        (0..=255u8).collect(),
    );
    let native_max = st_ticket(transport::NATIVE, &"u".repeat(64), vec![0xee; 256]);
    let sealed_native = seal(&native);
    let sealed_webrtc = seal(&webrtc);
    let case = |name, ticket: &[u8], expect: Result<ServerTicket, Error>| StCase {
        name,
        ticket: ticket.to_vec(),
        now: ST_NOW,
        self_server_id: ST_SERVER_ID,
        via: match &expect {
            Ok(t) => t.transport,
            Err(_) => transport::NATIVE,
        },
        expect,
    };
    let err = |name, ticket: &[u8], via, e| StCase {
        via,
        ..case(name, ticket, Err(e))
    };
    let meta0 = [0u8, 0];

    let mut v = vec![
        case("valid_native", &sealed_native, Ok(native.clone())),
        case("valid_webrtc", &sealed_webrtc, Ok(webrtc.clone())),
        case("valid_wt_max_size", &seal(&wt_max), Ok(wt_max.clone())),
    ];
    v.push(StCase {
        now: ST_EXPIRY,
        ..case("expiry_equals_now", &sealed_native, Ok(native.clone()))
    });
    v.push(StCase {
        now: ST_EXPIRY + 1,
        ..case("expired_by_one", &sealed_native, Err(Error::Expired))
    });
    v.push(case(
        "too_short_74",
        &sealed_webrtc[..74],
        Err(Error::BadLength),
    ));
    let mut long = seal(&native_max);
    long.push(0);
    v.push(case("too_long_459", &long, Err(Error::BadLength)));
    let mut t = sealed_native.clone();
    t[0] = 2;
    v.push(case("bad_version", &t, Err(Error::BadVersion)));
    let mut t = sealed_native.clone();
    t[1] = 2;
    v.push(case("unknown_key", &t, Err(Error::UnknownKey)));
    let mut t = sealed_native.clone();
    let last = t.len() - 1;
    t[last] ^= 1;
    v.push(case("tampered", &t, Err(Error::AuthFailed)));

    // Post-AEAD malformed bodies. Trailing padding keeps the ticket above the 75-byte floor.
    let mut b = st_body(0, &[], 2, &meta0);
    b.extend_from_slice(&[0; 4]);
    v.push(case(
        "user_id_len_zero",
        &st_seal_raw(&b),
        Err(Error::BadUserId),
    ));
    let b = st_body(65, &[b'a'; 65], 2, &meta0);
    v.push(case(
        "user_id_len_65",
        &st_seal_raw(&b),
        Err(Error::BadUserId),
    ));
    let b = st_body(2, &[0xff, 0xfe], 2, &meta0);
    v.push(case(
        "user_id_not_utf8",
        &st_seal_raw(&b),
        Err(Error::BadUserId),
    ));
    let b = st_body(1, b"a", 3, &meta0);
    v.push(case(
        "transport_three",
        &st_seal_raw(&b),
        Err(Error::BadTransport),
    ));
    let b = st_body(1, b"a", 1, &meta0);
    v.push(case(
        "native_without_keys",
        &st_seal_raw(&b),
        Err(Error::BadLength),
    ));
    let mut rest = 257u16.to_be_bytes().to_vec();
    rest.extend_from_slice(&[0; 257]);
    let b = st_body(1, b"a", 2, &rest);
    v.push(case(
        "metadata_257",
        &st_seal_raw(&b),
        Err(Error::BadMetadata),
    ));
    let mut rest = meta0.to_vec();
    rest.push(0);
    let b = st_body(1, b"a", 2, &rest);
    v.push(case(
        "trailing_byte",
        &st_seal_raw(&b),
        Err(Error::BadLength),
    ));

    // Checks 7-9 after AEAD.
    v.push(StCase {
        self_server_id: [0xcd; 16],
        ..err(
            "wrong_server",
            &sealed_webrtc,
            transport::WEBRTC,
            Error::WrongServer,
        )
    });
    v.push(err(
        "via_mismatch",
        &sealed_webrtc,
        transport::NATIVE,
        Error::BadTransport,
    ));
    // Multi-violation cases pin the check order (server_id, then expiry, then transport);
    // single-violation cases cannot detect a swapped order.
    v.push(StCase {
        now: ST_EXPIRY + 1,
        self_server_id: [0xcd; 16],
        ..err(
            "wrong_server_and_expired",
            &sealed_webrtc,
            transport::WEBRTC,
            Error::WrongServer,
        )
    });
    v.push(StCase {
        now: ST_EXPIRY + 1,
        ..err(
            "expired_and_via_mismatch",
            &sealed_webrtc,
            transport::NATIVE,
            Error::Expired,
        )
    });
    v
}

#[test]
#[ignore = "regenerates vectors/server_ticket.json"]
fn write_server_ticket_vectors() {
    let cases: Vec<Value> = st_cases()
        .iter()
        .map(|c| {
            let mut m = serde_json::Map::new();
            m.insert("name".into(), json!(c.name));
            m.insert("ticket_hex".into(), json!(hex::encode(&c.ticket)));
            m.insert("now".into(), json!(c.now));
            m.insert(
                "self_server_id_hex".into(),
                json!(hex::encode(c.self_server_id)),
            );
            m.insert("via".into(), json!(c.via));
            match &c.expect {
                Ok(t) => {
                    let mut e = serde_json::Map::new();
                    e.insert("user_id".into(), json!(t.user_id));
                    e.insert("server_id_hex".into(), json!(hex::encode(t.server_id)));
                    e.insert("session_id_hex".into(), json!(hex::encode(t.session_id)));
                    e.insert("expiry".into(), json!(t.expiry));
                    e.insert("transport".into(), json!(t.transport));
                    if let Some(k) = &t.native_keys {
                        e.insert("key_c2s_hex".into(), json!(hex::encode(k.c2s)));
                        e.insert("key_s2c_hex".into(), json!(hex::encode(k.s2c)));
                    }
                    e.insert("metadata_hex".into(), json!(hex::encode(&t.metadata)));
                    m.insert("expect".into(), Value::Object(e))
                }
                Err(e) => m.insert("error".into(), json!(e.code())),
            };
            Value::Object(m)
        })
        .collect();
    common::write_vectors(ST_FILE, &json!({ "cases": cases }));
}

#[test]
fn check_server_ticket_vectors() {
    let file = common::read_vectors(ST_FILE);
    let cases = file["cases"].as_array().unwrap();
    assert_eq!(cases.len(), st_cases().len());
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let ticket = hex::decode(c["ticket_hex"].as_str().unwrap()).unwrap();
        let now = c["now"].as_u64().unwrap() as u32;
        let sid: [u8; 16] = hex::decode(c["self_server_id_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let via = c["via"].as_u64().unwrap() as u8;
        let got = open_server(&ticket, &st_ring(), now, &sid, via);
        match c.get("error") {
            Some(code) => assert_eq!(
                got.map_err(|e| e.code()),
                Err(code.as_str().unwrap()),
                "{name}"
            ),
            None => {
                let t = got.unwrap_or_else(|e| panic!("{name}: {e}"));
                let e = &c["expect"];
                assert_eq!(t.user_id, e["user_id"].as_str().unwrap(), "{name}");
                assert_eq!(
                    hex::encode(t.server_id),
                    e["server_id_hex"].as_str().unwrap(),
                    "{name}"
                );
                assert_eq!(
                    hex::encode(t.session_id),
                    e["session_id_hex"].as_str().unwrap(),
                    "{name}"
                );
                assert_eq!(u64::from(t.expiry), e["expiry"].as_u64().unwrap(), "{name}");
                assert_eq!(
                    u64::from(t.transport),
                    e["transport"].as_u64().unwrap(),
                    "{name}"
                );
                assert_eq!(
                    t.native_keys
                        .as_ref()
                        .map(|k| hex::encode(k.c2s))
                        .as_deref(),
                    e.get("key_c2s_hex").and_then(Value::as_str),
                    "{name}"
                );
                assert_eq!(
                    t.native_keys
                        .as_ref()
                        .map(|k| hex::encode(k.s2c))
                        .as_deref(),
                    e.get("key_s2c_hex").and_then(Value::as_str),
                    "{name}"
                );
                assert_eq!(
                    hex::encode(&t.metadata),
                    e["metadata_hex"].as_str().unwrap(),
                    "{name}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------- ice_pwd.json

const ICE_FILE: &str = "ice_pwd.json";

/// `spike_evtj` and `spike_evtk` are Python-verified values carried over from the spike.
const ICE_CASES: [(&str, &str); 4] = [
    ("spike_evtj", "evtj"),
    ("spike_evtk", "evtk"),
    ("single_char", "a"),
    ("long_ufrag", "abcdefghijklmnopqrstuvwxyz012345"),
];

#[test]
#[ignore = "regenerates vectors/ice_pwd.json"]
fn write_ice_pwd_vectors() {
    let cases: Vec<Value> = ICE_CASES
        .iter()
        .map(|(name, ufrag)| {
            json!({
                "name": name,
                "k_gs_hex": hex::encode([0x22u8; 32]),
                "ufrag": ufrag,
                "pwd": ice_pwd(&[0x22; 32], ufrag),
            })
        })
        .collect();
    common::write_vectors(ICE_FILE, &json!({ "cases": cases }));
}

#[test]
fn check_ice_pwd_vectors() {
    let file = common::read_vectors(ICE_FILE);
    let cases = file["cases"].as_array().unwrap();
    assert_eq!(cases.len(), ICE_CASES.len());
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let k: [u8; 32] = hex::decode(c["k_gs_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let pwd = ice_pwd(&k, c["ufrag"].as_str().unwrap());
        assert_eq!(pwd, c["pwd"].as_str().unwrap(), "{name}");
        assert_eq!(pwd.len(), 43, "{name}");
    }
    let by_name = |n: &str| {
        cases
            .iter()
            .find(|c| c["name"] == n)
            .map(|c| c["pwd"].as_str().unwrap().to_string())
    };
    assert_eq!(
        by_name("spike_evtj").as_deref(),
        Some("80zK66GjJqCxXOeI6qiO7Tyrn/sory+Ra/31l+h0e60")
    );
    assert_eq!(
        by_name("spike_evtk").as_deref(),
        Some("A1/6J7XGHgokNUcZqm7BhqrgquS1iyt13K4ph1Ian4o")
    );
}

// ---------------------------------------------------------------- retry_token.json

const RETRY_FILE: &str = "retry_token.json";
const RETRY_KEY: [u8; 32] = [0x33; 32];
const RETRY_NOW: u64 = 1_900_000_000;
const RETRY_EXPIRY: u64 = 2_000_000_000;
const RETRY_CLIENT4: &str = "203.0.113.7:4433";
const RETRY_CLIENT6: &str = "[2001:db8::7]:4433";
const RETRY_ODCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
const RETRY_RSCID: [u8; 8] = [0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5];

struct RetryCase {
    name: &'static str,
    token: Vec<u8>,
    client: &'static str,
    dcid: Vec<u8>,
    now: u64,
    /// True for "parse" mode (no tag or expiry check).
    parse: bool,
    expect: Result<Vec<u8>, Error>,
}

fn retry_mint(odcid: &[u8], client: &str, expiry: u64) -> Vec<u8> {
    mint_retry_token(
        &RETRY_KEY,
        odcid,
        client.parse().unwrap(),
        &RETRY_RSCID,
        expiry,
    )
    .unwrap()
}

fn retry_cases() -> Vec<RetryCase> {
    let v4 = retry_mint(&RETRY_ODCID, RETRY_CLIENT4, RETRY_EXPIRY);
    let v6 = retry_mint(&RETRY_ODCID, RETRY_CLIENT6, RETRY_EXPIRY);
    let case = |name, token: &[u8], client, now, expect: Result<Vec<u8>, Error>| RetryCase {
        name,
        token: token.to_vec(),
        client,
        dcid: RETRY_RSCID.to_vec(),
        now,
        parse: false,
        expect,
    };
    let ok = Ok(RETRY_ODCID.to_vec());
    let mut v = vec![
        case("valid_ipv4", &v4, RETRY_CLIENT4, RETRY_NOW, ok.clone()),
        case("valid_ipv6", &v6, RETRY_CLIENT6, RETRY_NOW, ok.clone()),
        case("expiry_equals_now", &v4, RETRY_CLIENT4, RETRY_EXPIRY, ok),
        case(
            "expired_by_one",
            &v4,
            RETRY_CLIENT4,
            RETRY_EXPIRY + 1,
            Err(Error::Expired),
        ),
        case(
            "empty",
            &[],
            RETRY_CLIENT4,
            RETRY_NOW,
            Err(Error::BadLength),
        ),
    ];
    let mut type_bit = v4.clone();
    type_bit[0] |= 0x80;
    v.push(case(
        "type_bit_set",
        &type_bit,
        RETRY_CLIENT4,
        RETRY_NOW,
        Err(Error::BadTokenType),
    ));
    // ODCIL out of range: byte0 is rewritten, the rest keeps the 8-byte token's shape.
    for (name, odcil) in [("odcil_7", 7u8), ("odcil_21", 21u8)] {
        let mut t = v4.clone();
        t[0] = odcil;
        v.push(case(
            name,
            &t,
            RETRY_CLIENT4,
            RETRY_NOW,
            Err(Error::BadOdcil),
        ));
    }
    v.push(case(
        "length_mismatch",
        &v4[..v4.len() - 1],
        RETRY_CLIENT4,
        RETRY_NOW,
        Err(Error::BadLength),
    ));
    v.push(case(
        "wrong_client_port",
        &v4,
        "203.0.113.7:4434",
        RETRY_NOW,
        Err(Error::AuthFailed),
    ));
    v.push(RetryCase {
        dcid: RETRY_ODCID.to_vec(),
        ..case(
            "wrong_dcid",
            &v4,
            RETRY_CLIENT4,
            RETRY_NOW,
            Err(Error::AuthFailed),
        )
    });
    let mut bad_tag = v4.clone();
    let last = bad_tag.len() - 1;
    bad_tag[last] ^= 1;
    v.push(RetryCase {
        parse: true,
        ..case(
            "parse_only_bad_tag",
            &bad_tag,
            RETRY_CLIENT4,
            RETRY_NOW,
            Ok(RETRY_ODCID.to_vec()),
        )
    });
    // Pins check order: a bad tag and an expired expiry together must report auth_failed.
    v.push(case(
        "bad_tag_and_expired",
        &bad_tag,
        RETRY_CLIENT4,
        RETRY_EXPIRY + 1,
        Err(Error::AuthFailed),
    ));
    v
}

fn retry_run(c: &RetryCase) -> Result<Vec<u8>, Error> {
    if c.parse {
        retry_token_odcid(&c.token).map(<[u8]>::to_vec)
    } else {
        validate_retry_token(
            &RETRY_KEY,
            &c.token,
            c.client.parse().unwrap(),
            &c.dcid,
            c.now,
        )
        .map(<[u8]>::to_vec)
    }
}

#[test]
fn retry_cases_match_their_expectations() {
    for c in retry_cases() {
        assert_eq!(retry_run(&c), c.expect, "{}", c.name);
    }
}

#[test]
#[ignore = "regenerates vectors/retry_token.json"]
fn write_retry_token_vectors() {
    let cases: Vec<Value> = retry_cases()
        .iter()
        .map(|c| {
            let mut m = serde_json::Map::new();
            m.insert("name".into(), json!(c.name));
            m.insert(
                "mode".into(),
                json!(if c.parse { "parse" } else { "validate" }),
            );
            m.insert("token_hex".into(), json!(hex::encode(&c.token)));
            m.insert("client".into(), json!(c.client));
            m.insert("dcid_hex".into(), json!(hex::encode(&c.dcid)));
            m.insert("now".into(), json!(c.now));
            match &c.expect {
                Ok(odcid) => m.insert("expect".into(), json!({ "odcid_hex": hex::encode(odcid) })),
                Err(e) => m.insert("error".into(), json!(e.code())),
            };
            Value::Object(m)
        })
        .collect();
    common::write_vectors(RETRY_FILE, &json!({ "cases": cases }));
}

#[test]
fn check_retry_token_vectors() {
    let file = common::read_vectors(RETRY_FILE);
    let cases = file["cases"].as_array().unwrap();
    assert_eq!(cases.len(), retry_cases().len());
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let token = hex::decode(c["token_hex"].as_str().unwrap()).unwrap();
        let client: std::net::SocketAddr = c["client"].as_str().unwrap().parse().unwrap();
        let dcid = hex::decode(c["dcid_hex"].as_str().unwrap()).unwrap();
        let now = c["now"].as_u64().unwrap();
        let got = match c["mode"].as_str().unwrap() {
            "validate" => validate_retry_token(&RETRY_KEY, &token, client, &dcid, now),
            "parse" => retry_token_odcid(&token),
            m => panic!("{name}: unknown mode {m}"),
        };
        match c.get("error") {
            Some(code) => assert_eq!(
                got.map_err(|e| e.code()),
                Err(code.as_str().unwrap()),
                "{name}"
            ),
            None => assert_eq!(
                hex::encode(got.unwrap_or_else(|e| panic!("{name}: {e}"))),
                c["expect"]["odcid_hex"].as_str().unwrap(),
                "{name}"
            ),
        }
    }
}

// ---------------------------------------------------------------- connect_info.json

const CI_FILE: &str = "connect_info.json";

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn ci_native() -> NativeInfo {
    let rt = RoutingTicket {
        server_id: [0xab; 16],
        session_id: [1, 2, 3, 4, 5, 6, 7, 8],
        expiry: RT_EXPIRY,
        transports: transport::NATIVE | transport::WEBRTC | transport::WEBTRANSPORT,
    };
    NativeInfo {
        gateways: vec!["203.0.113.10:443".into(), "203.0.113.11:443".into()],
        routing_ticket: seal_routing(&rt, &rt_ring(), [0x88; 12]),
        server_ticket: ci_server_ticket(transport::NATIVE),
        key_c2s: [0x44; 32],
        key_s2c: [0x55; 32],
    }
}

fn ci_server_ticket(tr: u8) -> Vec<u8> {
    let t = ServerTicket {
        native_keys: (tr == transport::NATIVE).then_some(NativeKeys {
            c2s: [0x44; 32],
            s2c: [0x55; 32],
        }),
        ..st_ticket(tr, "user-1", Vec::new())
    };
    seal_server(&t, &st_ring(), [0x99; 24]).unwrap()
}

fn ci_webrtc() -> WebRtcInfo {
    let ufrag = to_ufrag(&ci_native().routing_ticket);
    let fp: Vec<String> = (0..32u8).map(|i| format!("{:02X}", i * 7)).collect();
    WebRtcInfo {
        candidates: vec!["203.0.113.10:443".into()],
        ice_pwd: ice_pwd(&[0x22; 32], &ufrag),
        ice_ufrag: ufrag,
        dtls_fingerprint: format!("sha-256 {}", fp.join(":")),
        server_ticket: ci_server_ticket(transport::WEBRTC),
    }
}

fn ci_wt() -> WtInfo {
    let host = to_sni_labels(&ci_native().routing_ticket);
    let t = b64(&ci_server_ticket(transport::WEBTRANSPORT));
    WtInfo {
        url: format!("https://{host}.wt.example.test:443/glassy?t={t}"),
        cert_sha256: [0xcd; 32],
    }
}

fn ci_all() -> ConnectInfo {
    ConnectInfo {
        session_id: [1, 2, 3, 4, 5, 6, 7, 8],
        expiry: RT_EXPIRY,
        native: Some(ci_native()),
        webrtc: Some(ci_webrtc()),
        webtransport: Some(ci_wt()),
    }
}

fn ci_json(ci: &ConnectInfo) -> String {
    String::from_utf8(
        URL_SAFE_NO_PAD
            .decode(encode_connect_info(ci).unwrap())
            .unwrap(),
    )
    .unwrap()
}

/// Replaces the single occurrence of `from`; a miss would silently weaken a case.
fn mutate(json: &str, from: &str, to: &str) -> String {
    assert_eq!(json.matches(from).count(), 1, "mutation anchor {from}");
    json.replacen(from, to, 1)
}

enum CiInput {
    Json(String),
    B64(String),
}

struct CiCase {
    name: &'static str,
    input: CiInput,
    expect: Result<ConnectInfo, Error>,
}

fn ci_input_str(i: &CiInput) -> String {
    match i {
        CiInput::Json(j) => b64(j.as_bytes()),
        CiInput::B64(s) => s.clone(),
    }
}

fn ci_cases() -> Vec<CiCase> {
    let all = ci_all();
    let base = ci_json(&all);
    let native_only = ConnectInfo {
        webrtc: None,
        webtransport: None,
        ..all.clone()
    };
    let webrtc_only = ConnectInfo {
        native: None,
        webtransport: None,
        ..all.clone()
    };
    let wt_only = ConnectInfo {
        native: None,
        webrtc: None,
        ..all.clone()
    };
    let ok = |name, json: String, expect: &ConnectInfo| CiCase {
        name,
        input: CiInput::Json(json),
        expect: Ok(expect.clone()),
    };
    let bad = |name, json: String, e: Error| CiCase {
        name,
        input: CiInput::Json(json),
        expect: Err(e),
    };
    let nat = ci_native();
    let wr = ci_webrtc();
    let sid = "\"session_id\":\"0102030405060708\"";
    let head = "{\"v\":1,\"session_id\":\"0102030405060708\",\"expiry\":2000000000";

    let mut v = vec![
        ok("native_only", ci_json(&native_only), &native_only),
        ok("webrtc_only", ci_json(&webrtc_only), &webrtc_only),
        ok("wt_only", ci_json(&wt_only), &wt_only),
        ok("all_blocks", base.clone(), &all),
    ];
    // serde_json's Value sorts keys, which puts `v` last and the blocks in alphabetical order.
    let value: Value = serde_json::from_str(&base).unwrap();
    v.push(ok("shuffled_keys", value.to_string(), &all));
    v.push(ok(
        "whitespace_everywhere",
        format!(
            " \r\n\t{}\n ",
            serde_json::to_string_pretty(&value).unwrap()
        ),
        &all,
    ));
    v.push(ok(
        "unknown_top_field",
        mutate(
            &base,
            "\"v\":1,",
            "\"v\":1,\"future\":{\"a\":[1,2.5e3,null,true]},",
        ),
        &all,
    ));
    v.push(ok(
        "unknown_nested_field",
        mutate(&base, "\"key_c2s\"", "\"extra\":{\"x\":[{}]},\"key_c2s\""),
        &all,
    ));
    v.push(ok(
        "escape_in_unknown_field",
        mutate(
            &base,
            "\"v\":1,",
            "\"v\":1,\"note\":\"a\\n\\\"b\\\\ \\u00e9\\ud83d\\ude00\",",
        ),
        &all,
    ));
    v.push(ok(
        "unicode_in_unknown_field",
        mutate(
            &base,
            "\"v\":1,",
            "\"v\":1,\"note\":\"h\u{e9}llo \u{4e16}\u{754c} \u{1f600}\",",
        ),
        &all,
    ));
    // Unknown values only have to match the JSON grammar; lone surrogate escapes and numbers
    // outside any machine range are accepted (pinned because the C++ scanner must agree).
    v.push(ok(
        "lone_surrogate_in_unknown_field",
        mutate(
            &base,
            "\"v\":1,",
            "\"v\":1,\"x\":\"\\ud800\\udc00\\udc00\",",
        ),
        &all,
    ));
    v.push(ok(
        "huge_number_in_unknown_field",
        mutate(
            &base,
            "\"v\":1,",
            "\"v\":1,\"x\":[1e999,-123456789012345678901234567890],",
        ),
        &all,
    ));
    v.push(bad(
        "bad_escape_in_unknown_field",
        mutate(&base, "\"v\":1,", "\"v\":1,\"x\":\"\\q\","),
        Error::BadJson,
    ));
    v.push(ok(
        "duplicate_unknown_key",
        mutate(&base, "\"v\":1,", "\"v\":1,\"x\":1,\"x\":2,"),
        &all,
    ));
    v.push(ok(
        "depth_8_unknown_field",
        mutate(&base, "\"v\":1,", "\"v\":1,\"x\":[[[[[[[0]]]]]]],"),
        &all,
    ));
    v.push(ok(
        "expiry_zero",
        mutate(&base, "\"expiry\":2000000000", "\"expiry\":0"),
        &ConnectInfo {
            expiry: 0,
            ..all.clone()
        },
    ));
    v.push(ok(
        "expiry_max",
        mutate(&base, "\"expiry\":2000000000", "\"expiry\":4294967295"),
        &ConnectInfo {
            expiry: u32::MAX,
            ..all.clone()
        },
    ));
    let mut padded = base.clone();
    padded.push_str(&" ".repeat(4096 - padded.len()));
    v.push(ok("json_4096_bytes", padded, &all));

    // Invalid.
    v.push(bad(
        "v_2",
        mutate(&base, "\"v\":1", "\"v\":2"),
        Error::BadVersion,
    ));
    v.push(bad(
        "v_string",
        mutate(&base, "\"v\":1", "\"v\":\"1\""),
        Error::BadJson,
    ));
    v.push(bad(
        "v_missing",
        mutate(&base, "\"v\":1,", ""),
        Error::BadJson,
    ));
    v.push(bad(
        "v_float",
        mutate(&base, "\"v\":1", "\"v\":1.0"),
        Error::BadJson,
    ));
    v.push(bad(
        "v_huge_integer",
        mutate(&base, "\"v\":1", "\"v\":123456789012345678901234567890"),
        Error::BadVersion,
    ));
    v.push(bad(
        "v_2_other_schema",
        "{\"v\":2,\"session_id\":5,\"native\":[]}".into(),
        Error::BadVersion,
    ));
    v.push(bad(
        "depth_9",
        mutate(&base, "\"v\":1,", "\"v\":1,\"x\":[[[[[[[[0]]]]]]]],"),
        Error::BadJson,
    ));
    v.push(bad(
        "duplicate_key",
        mutate(
            &base,
            "\"expiry\":2000000000",
            "\"expiry\":2000000000,\"expiry\":2000000000",
        ),
        Error::BadJson,
    ));
    v.push(bad(
        "duplicate_key_in_block",
        mutate(
            &base,
            "\"cert_sha256\"",
            "\"url\":\"https://x\",\"cert_sha256\"",
        ),
        Error::BadJson,
    ));
    v.push(bad(
        "escape_in_known_field",
        mutate(&base, sid, "\"session_id\":\"010203040506070\\u0038\""),
        Error::BadJson,
    ));
    v.push(bad(
        "escaped_key_not_matched",
        mutate(&base, "\"expiry\"", "\"expir\\u0079\""),
        Error::BadJson,
    ));
    v.push(bad(
        "uppercase_session_id",
        mutate(&base, sid, "\"session_id\":\"0A0B0C0D0E0F0102\""),
        Error::BadEncoding,
    ));
    v.push(bad(
        "session_id_short",
        mutate(&base, sid, "\"session_id\":\"01\""),
        Error::BadEncoding,
    ));
    v.push(bad(
        "no_transport_block",
        format!("{head}}}"),
        Error::BadJson,
    ));
    v.push(bad("top_level_array", "[1]".into(), Error::BadJson));
    v.push(bad(
        "null_block",
        format!("{head},\"native\":null}}"),
        Error::BadJson,
    ));
    v.push(bad(
        "missing_key_c2s",
        mutate(
            &base,
            &format!("\"key_c2s\":\"{}\",", b64(&nat.key_c2s)),
            "",
        ),
        Error::BadJson,
    ));
    v.push(bad(
        "key_c2s_wrong_type",
        mutate(
            &base,
            &format!("\"key_c2s\":\"{}\"", b64(&nat.key_c2s)),
            "\"key_c2s\":7",
        ),
        Error::BadJson,
    ));
    v.push(bad(
        "key_c2s_31_bytes",
        mutate(&base, &b64(&nat.key_c2s), &b64(&[0x44; 31])),
        Error::BadLength,
    ));
    v.push(bad(
        "key_c2s_bad_char",
        mutate(
            &base,
            &b64(&nat.key_c2s),
            &format!("!{}", &b64(&nat.key_c2s)[1..]),
        ),
        Error::BadEncoding,
    ));
    let gw = "[\"203.0.113.10:443\",\"203.0.113.11:443\"]";
    v.push(bad(
        "gateways_empty",
        mutate(&base, gw, "[]"),
        Error::BadJson,
    ));
    v.push(bad(
        "gateways_5",
        mutate(&base, gw, "[\"a:1\",\"b:1\",\"c:1\",\"d:1\",\"e:1\"]"),
        Error::TooLarge,
    ));
    v.push(bad(
        "gateway_empty_string",
        mutate(&base, gw, "[\"\"]"),
        Error::BadJson,
    ));
    v.push(bad(
        "gateway_65_bytes",
        mutate(&base, gw, &format!("[\"{}\"]", "a".repeat(65))),
        Error::TooLarge,
    ));
    v.push(bad(
        "routing_ticket_59_bytes",
        mutate(
            &base,
            &b64(&nat.routing_ticket),
            &b64(&nat.routing_ticket[..59]),
        ),
        Error::BadLength,
    ));
    v.push(bad(
        "ticket_too_short",
        mutate(
            &base,
            &b64(&nat.server_ticket),
            &b64(&nat.server_ticket[..138]),
        ),
        Error::BadLength,
    ));
    v.push(bad(
        "native_ticket_459",
        mutate(&base, &b64(&nat.server_ticket), &b64(&[0u8; 459])),
        Error::BadLength,
    ));
    v.push(ok(
        "native_ticket_458",
        mutate(&base, &b64(&nat.server_ticket), &b64(&[0u8; 458])),
        &ConnectInfo {
            native: Some(NativeInfo {
                server_ticket: vec![0; 458],
                ..nat.clone()
            }),
            ..all.clone()
        },
    ));
    v.push(bad(
        "webrtc_ticket_395",
        mutate(&base, &b64(&wr.server_ticket), &b64(&[0u8; 395])),
        Error::BadLength,
    ));
    v.push(bad(
        "webrtc_ticket_74",
        mutate(&base, &b64(&wr.server_ticket), &b64(&[0u8; 74])),
        Error::BadLength,
    ));
    v.push(bad(
        "ufrag_79_chars",
        mutate(&base, &wr.ice_ufrag, &wr.ice_ufrag[1..]),
        Error::BadLength,
    ));
    v.push(bad(
        "ufrag_bad_char",
        mutate(&base, &wr.ice_ufrag, &format!("-{}", &wr.ice_ufrag[1..])),
        Error::BadEncoding,
    ));
    v.push(bad(
        "pwd_bad_char",
        mutate(&base, &wr.ice_pwd, &format!("{}-", &wr.ice_pwd[1..])),
        Error::BadEncoding,
    ));
    v.push(bad(
        "pwd_42_chars",
        mutate(&base, &wr.ice_pwd, &wr.ice_pwd[1..]),
        Error::BadLength,
    ));
    v.push(bad(
        "candidates_empty",
        mutate(
            &base,
            "\"candidates\":[\"203.0.113.10:443\"]",
            "\"candidates\":[]",
        ),
        Error::BadJson,
    ));
    v.push(bad(
        "dtls_fingerprint_empty",
        mutate(&base, &wr.dtls_fingerprint, ""),
        Error::BadLength,
    ));
    v.push(bad(
        "dtls_fingerprint_129",
        mutate(&base, &wr.dtls_fingerprint, &"A".repeat(129)),
        Error::BadLength,
    ));
    v.push(bad(
        "dtls_fingerprint_non_ascii",
        mutate(&base, &wr.dtls_fingerprint, "sha-256 \u{e9}"),
        Error::BadEncoding,
    ));
    v.push(bad(
        "url_not_https",
        mutate(&base, "\"url\":\"https://", "\"url\":\"http://"),
        Error::BadEncoding,
    ));
    v.push(bad(
        "url_1025_bytes",
        mutate(
            &base,
            "/glassy?t=",
            &format!("/glassy?t={}", "a".repeat(1025 - (ci_wt().url.len() - 10))),
        ),
        Error::BadLength,
    ));
    v.push(bad(
        "cert_sha256_31_bytes",
        mutate(&base, &b64(&[0xcd; 32]), &b64(&[0xcd; 31])),
        Error::BadLength,
    ));

    // Encoding-level failures.
    let mut pad = base.clone();
    while pad.len() % 3 != 1 {
        pad.push(' ');
    }
    let padded = STANDARD.encode(pad.as_bytes());
    assert!(padded.ends_with('='));
    v.push(CiCase {
        name: "base64_padding",
        input: CiInput::B64(URL_SAFE_NO_PAD.encode(pad.as_bytes()) + "=="),
        expect: Err(Error::BadEncoding),
    });
    let mut unpadded = URL_SAFE_NO_PAD.encode(pad.as_bytes());
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let last = unpadded.pop().unwrap();
    let idx = alphabet.find(last).unwrap();
    assert_eq!(
        idx & 0x0f,
        0,
        "premise: trailing bits of a valid encoding are zero"
    );
    unpadded.push(alphabet.as_bytes()[idx | 1] as char);
    v.push(CiCase {
        name: "base64_nonzero_trailing_bits",
        input: CiInput::B64(unpadded),
        expect: Err(Error::BadEncoding),
    });
    v.push(CiCase {
        name: "base64_standard_alphabet",
        input: CiInput::B64(STANDARD.encode([0xfbu8, 0xff, 0xfe, 0xfb])),
        expect: Err(Error::BadEncoding),
    });
    let mut too_big = base.clone();
    too_big.push_str(&" ".repeat(4097 - too_big.len()));
    v.push(bad("json_4097_bytes", too_big, Error::TooLarge));
    v.push(bad("trailing_garbage", format!("{base}x"), Error::BadJson));
    v.push(bad(
        "trailing_second_object",
        format!("{base}{{}}"),
        Error::BadJson,
    ));
    v.push(bad(
        "truncated_json",
        base[..base.len() - 1].to_string(),
        Error::BadJson,
    ));
    v.push(CiCase {
        name: "invalid_utf8",
        input: CiInput::B64(b64(&[
            &base.as_bytes()[..base.len() - 1],
            b",\"x\":\"\xff\"}",
        ]
        .concat())),
        expect: Err(Error::BadJson),
    });
    v.push(bad(
        "expiry_float",
        mutate(&base, "\"expiry\":2000000000", "\"expiry\":2000000000.0"),
        Error::BadJson,
    ));
    v.push(bad(
        "expiry_exponent",
        mutate(&base, "\"expiry\":2000000000", "\"expiry\":2e9"),
        Error::BadJson,
    ));
    v.push(bad(
        "expiry_negative",
        mutate(&base, "\"expiry\":2000000000", "\"expiry\":-1"),
        Error::BadJson,
    ));
    v.push(bad(
        "expiry_overflow",
        mutate(&base, "\"expiry\":2000000000", "\"expiry\":4294967296"),
        Error::BadJson,
    ));
    v.push(bad(
        "expiry_string",
        mutate(&base, "\"expiry\":2000000000", "\"expiry\":\"2000000000\""),
        Error::BadJson,
    ));
    v
}

fn ci_hex_block(ci: &ConnectInfo) -> Value {
    let mut m = serde_json::Map::new();
    m.insert("session_id".into(), json!(hex::encode(ci.session_id)));
    m.insert("expiry".into(), json!(ci.expiry));
    if let Some(n) = &ci.native {
        m.insert(
            "native".into(),
            json!({
                "gateways": n.gateways,
                "routing_ticket_hex": hex::encode(n.routing_ticket),
                "server_ticket_hex": hex::encode(&n.server_ticket),
                "key_c2s_hex": hex::encode(n.key_c2s),
                "key_s2c_hex": hex::encode(n.key_s2c),
            }),
        );
    }
    if let Some(w) = &ci.webrtc {
        m.insert(
            "webrtc".into(),
            json!({
                "candidates": w.candidates,
                "ice_ufrag": w.ice_ufrag,
                "ice_pwd": w.ice_pwd,
                "dtls_fingerprint": w.dtls_fingerprint,
                "server_ticket_hex": hex::encode(&w.server_ticket),
            }),
        );
    }
    if let Some(t) = &ci.webtransport {
        m.insert(
            "webtransport".into(),
            json!({ "url": t.url, "cert_sha256_hex": hex::encode(t.cert_sha256) }),
        );
    }
    Value::Object(m)
}

#[test]
fn connect_info_cases_match_their_expectations() {
    for c in ci_cases() {
        assert_eq!(
            decode_connect_info(&ci_input_str(&c.input)),
            c.expect,
            "{}",
            c.name
        );
    }
}

#[test]
#[ignore = "regenerates vectors/connect_info.json"]
fn write_connect_info_vectors() {
    let cases: Vec<Value> = ci_cases()
        .iter()
        .map(|c| {
            let mut m = serde_json::Map::new();
            m.insert("name".into(), json!(c.name));
            match &c.input {
                CiInput::Json(j) => m.insert("json".into(), json!(j)),
                CiInput::B64(s) => m.insert("input".into(), json!(s)),
            };
            match &c.expect {
                Ok(ci) => m.insert("expect".into(), ci_hex_block(ci)),
                Err(e) => m.insert("error".into(), json!(e.code())),
            };
            Value::Object(m)
        })
        .collect();
    common::write_vectors(CI_FILE, &json!({ "cases": cases }));
}

#[test]
fn check_connect_info_vectors() {
    let file = common::read_vectors(CI_FILE);
    let cases = file["cases"].as_array().unwrap();
    assert_eq!(cases.len(), ci_cases().len());
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let input = match (c.get("json"), c.get("input")) {
            (Some(j), None) => b64(j.as_str().unwrap().as_bytes()),
            (None, Some(i)) => i.as_str().unwrap().to_string(),
            _ => panic!("{name}: need exactly one of json/input"),
        };
        let got = decode_connect_info(&input);
        match c.get("error") {
            Some(code) => assert_eq!(
                got.map_err(|e| e.code()),
                Err(code.as_str().unwrap()),
                "{name}"
            ),
            None => assert_eq!(
                ci_hex_block(&got.unwrap_or_else(|e| panic!("{name}: {e}"))),
                c["expect"],
                "{name}"
            ),
        }
    }
}

#[test]
fn connect_info_encode_is_canonical_and_roundtrips() {
    let ci = ci_all();
    let s = encode_connect_info(&ci).unwrap();
    assert_eq!(decode_connect_info(&s), Ok(ci));
    let json = ci_json(&ci_all());
    assert!(json.starts_with(
        "{\"v\":1,\"session_id\":\"0102030405060708\",\"expiry\":2000000000,\"native\":{\"gateways\":"
    ));
    let keys: Vec<usize> = ["\"native\"", "\"webrtc\"", "\"webtransport\""]
        .iter()
        .map(|k| json.find(k).unwrap())
        .collect();
    assert!(keys.windows(2).all(|w| w[0] < w[1]));
}

// ---------------------------------------------------------------- native_packets.json
//
// One file for every native packet kind. Each case names its `packet` kind and the `op`
// applied to it; the generator concatenates one helper per packet kind, so later packet
// kinds append a helper and a checker arm without touching existing cases.

const NP_FILE: &str = "native_packets.json";
const NP_NOW: u32 = 1_900_000_000;
const NP_SEQ: u64 = 1_700_000_000_000;
const NP_CONN: [u8; 16] = [0x66; 16];
const NP_SESSION: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const NP_KEY_C2S: [u8; 32] = [0x44; 32];
const NP_KEY_S2C: [u8; 32] = [0x55; 32];
const NP_SERVER_NONCE: [u8; 16] = [0x77; 16];

struct NpCase {
    name: &'static str,
    packet: &'static str,
    op: &'static str,
    /// Input fields. The file lists keys alphabetically (serde_json sorts object keys).
    inputs: Vec<(&'static str, Value)>,
    expect: Result<Value, Error>,
}

fn np_routing() -> [u8; 60] {
    let t = RoutingTicket {
        server_id: [0xab; 16],
        session_id: NP_SESSION,
        expiry: RT_EXPIRY,
        transports: transport::NATIVE,
    };
    seal_routing(&t, &RoutingKeyRing::new(1, [0x11; 16]), [0x88; 12])
}

/// Native ticket for `session`, user `"u"`, no metadata: the 139-byte minimum.
fn np_native_ticket(session: [u8; 8]) -> Vec<u8> {
    let mut t = st_ticket(transport::NATIVE, "u", Vec::new());
    t.session_id = session;
    seal_server(&t, &st_ring(), ST_NONCE).unwrap()
}

fn np_connect(st: &[u8], pad_to: usize) -> Vec<u8> {
    build_connect(
        &NP_SESSION,
        &NP_CONN,
        NP_SEQ,
        &np_routing(),
        st,
        &NP_KEY_C2S,
        pad_to,
    )
    .unwrap()
}

fn np_packet_input(b: &[u8]) -> Vec<(&'static str, Value)> {
    vec![("packet_hex", json!(hex::encode(b)))]
}

fn np_verify_input(b: &[u8]) -> Vec<(&'static str, Value)> {
    let mut v = np_packet_input(b);
    v.push(("now", json!(NP_NOW)));
    v.push(("self_server_id_hex", json!(hex::encode(ST_SERVER_ID))));
    v
}

fn np_parse_expect(b: &[u8]) -> Value {
    let v = parse_connect(b).unwrap();
    json!({
        "session_id_hex": hex::encode(v.session_id),
        "conn_id_hex": hex::encode(v.conn_id),
        "connect_seq": v.connect_seq,
        "routing_ticket_hex": hex::encode(v.routing_ticket),
        "server_ticket_hex": hex::encode(v.server_ticket),
        "proof_tag_hex": hex::encode(v.proof_tag),
        "padding_len": v.padding.len(),
    })
}

fn np_verify_expect() -> Value {
    json!({
        "session_id_hex": hex::encode(NP_SESSION),
        "conn_id_hex": hex::encode(NP_CONN),
        "connect_seq": NP_SEQ,
        "user_id": "u",
    })
}

fn np_trailer_expect(body: &[u8], a: ClientAddrV4) -> Value {
    json!({
        "body_hex": hex::encode(body),
        "ip_hex": hex::encode(a.ip),
        "port": a.port,
    })
}

fn np_connect_cases() -> Vec<NpCase> {
    let st = np_native_ticket(NP_SESSION);
    let min = np_connect(&st, 0);
    let padded = np_connect(&st, 1200);
    let addr = ClientAddrV4 {
        ip: [203, 0, 113, 7],
        port: 4433,
    };
    let with_trailer = |b: &[u8]| {
        let mut v = b.to_vec();
        append_trailer(&mut v, addr);
        v
    };
    let build_inputs = |st: &[u8], pad_to: usize| -> Vec<(&'static str, Value)> {
        vec![
            ("session_id_hex", json!(hex::encode(NP_SESSION))),
            ("conn_id_hex", json!(hex::encode(NP_CONN))),
            ("connect_seq", json!(NP_SEQ)),
            ("routing_ticket_hex", json!(hex::encode(np_routing()))),
            ("server_ticket_hex", json!(hex::encode(st))),
            ("key_c2s_hex", json!(hex::encode(NP_KEY_C2S))),
            ("pad_to", json!(pad_to)),
        ]
    };
    let ok_bytes = |b: &[u8]| Ok(json!({ "bytes_hex": hex::encode(b) }));
    let parse_err = |name, b: &[u8], e| NpCase {
        name,
        packet: "connect",
        op: "parse",
        inputs: np_packet_input(b),
        expect: Err(e),
    };
    let verify_err = |name, b: &[u8], e| NpCase {
        name,
        packet: "connect",
        op: "verify",
        inputs: np_verify_input(b),
        expect: Err(e),
    };
    let trailer_err = |name, b: &[u8]| NpCase {
        name,
        packet: "connect",
        op: "split_trailer",
        inputs: np_packet_input(b),
        expect: Err(Error::BadTrailer),
    };

    // Mutations of the minimal packet, each hitting exactly one check.
    let mut bad_type = min.clone();
    bad_type[0] = 0x81;
    let mut bad_version = min.clone();
    bad_version[1] = 2;
    let mut ticket_len_138 = padded.clone();
    ticket_len_138[94..96].copy_from_slice(&138u16.to_be_bytes());
    let mut overflow = min.clone();
    overflow[94..96].copy_from_slice(&140u16.to_be_bytes());
    let mut nonzero_padding = np_connect(&st, 400);
    nonzero_padding[399] = 1;
    // WebRTC ticket padded with metadata so it reaches 139 bytes and passes the length gate.
    let webrtc = seal_server(
        &st_ticket(transport::WEBRTC, "u", vec![0; 100]),
        &st_ring(),
        ST_NONCE,
    )
    .unwrap();
    assert!(webrtc.len() >= 139);
    let session_mismatch = np_connect(&np_native_ticket([9; 8]), 0);
    let mut bad_proof = min.clone();
    *bad_proof.last_mut().unwrap() ^= 1;
    let mut both = np_connect(&st, 400);
    both[399] = 1;
    both[250] ^= 1;
    let mut family_06 = with_trailer(&min);
    *family_06.last_mut().unwrap() = 0x06;
    let mut reserved = with_trailer(&min);
    let n = reserved.len();
    reserved[n - 2] = 1;
    let mut too_long = padded.clone();
    too_long.push(0);

    vec![
        NpCase {
            name: "connect_min_251",
            packet: "connect",
            op: "build",
            inputs: build_inputs(&st, 0),
            expect: ok_bytes(&min),
        },
        NpCase {
            name: "connect_padded_1200",
            packet: "connect",
            op: "build",
            inputs: build_inputs(&st, 1200),
            expect: ok_bytes(&padded),
        },
        NpCase {
            name: "connect_min_251_parse",
            packet: "connect",
            op: "parse",
            inputs: np_packet_input(&min),
            expect: Ok(np_parse_expect(&min)),
        },
        NpCase {
            name: "connect_padded_1200_parse",
            packet: "connect",
            op: "parse",
            inputs: np_packet_input(&padded),
            expect: Ok(np_parse_expect(&padded)),
        },
        NpCase {
            name: "connect_min_251_verify",
            packet: "connect",
            op: "verify",
            inputs: np_verify_input(&min),
            expect: Ok(np_verify_expect()),
        },
        NpCase {
            name: "connect_padded_1200_verify",
            packet: "connect",
            op: "verify",
            inputs: np_verify_input(&padded),
            expect: Ok(np_verify_expect()),
        },
        NpCase {
            name: "connect_with_trailer",
            packet: "connect",
            op: "split_trailer",
            inputs: np_packet_input(&with_trailer(&min)),
            expect: Ok(np_trailer_expect(&min, addr)),
        },
        parse_err("len_250", &min[..250], Error::BadLength),
        parse_err("len_1201", &too_long, Error::BadLength),
        parse_err("bad_type", &bad_type, Error::BadType),
        parse_err("bad_version", &bad_version, Error::BadVersion),
        parse_err("ticket_len_138", &ticket_len_138, Error::BadLength),
        parse_err("ticket_len_overflows_packet", &overflow, Error::BadLength),
        verify_err("nonzero_padding", &nonzero_padding, Error::BadPadding),
        verify_err(
            "ticket_webrtc_in_connect",
            &np_connect(&webrtc, 0),
            Error::BadTransport,
        ),
        verify_err(
            "session_mismatch",
            &session_mismatch,
            Error::SessionMismatch,
        ),
        verify_err("bad_proof", &bad_proof, Error::AuthFailed),
        // Padding is checked before the ticket and the proof.
        verify_err("nonzero_padding_and_bad_proof", &both, Error::BadPadding),
        // The gateway's trailer left on the packet reads as nonzero padding.
        verify_err(
            "fake_trailer_without_split",
            &with_trailer(&min),
            Error::BadPadding,
        ),
        trailer_err("trailer_family_06", &family_06),
        trailer_err("trailer_reserved_nonzero", &reserved),
        // Shorter than the 8-byte trailer itself.
        trailer_err("trailer_input_7_bytes", &[0, 0, 0, 0, 0, 0, 4]),
    ]
}

fn np_accept() -> Accept {
    Accept {
        session_id: NP_SESSION,
        connect_seq: NP_SEQ,
        server_nonce: NP_SERVER_NONCE,
        resumed: false,
        server_time_ms: 1_900_000_000_123,
    }
}

fn np_reject(reason: u8) -> Reject {
    Reject {
        session_id: NP_SESSION,
        connect_seq: NP_SEQ,
        server_nonce: NP_SERVER_NONCE,
        reason,
        last_connect_seq: NP_SEQ + 1,
    }
}

fn np_accept_json(a: &Accept) -> Value {
    json!({
        "session_id_hex": hex::encode(a.session_id),
        "connect_seq": a.connect_seq,
        "server_nonce_hex": hex::encode(a.server_nonce),
        "resumed": a.resumed,
        "server_time_ms": a.server_time_ms,
    })
}

fn np_reject_json(r: &Reject) -> Value {
    json!({
        "session_id_hex": hex::encode(r.session_id),
        "connect_seq": r.connect_seq,
        "server_nonce_hex": hex::encode(r.server_nonce),
        "reason": r.reason,
        "last_connect_seq": r.last_connect_seq,
    })
}

/// Inputs for opening an `ACCEPT`/`REJECT`: the packet plus the `conn_id` and key.
fn np_reply_inputs(b: &[u8], conn_id: [u8; 16]) -> Vec<(&'static str, Value)> {
    vec![
        ("packet_hex", json!(hex::encode(b))),
        ("conn_id_hex", json!(hex::encode(conn_id))),
        ("key_s2c_hex", json!(hex::encode(NP_KEY_S2C))),
    ]
}

fn np_reply_cases() -> Vec<NpCase> {
    let fresh = np_accept();
    let resumed = Accept {
        resumed: true,
        ..np_accept()
    };
    let stale = np_reject(reject_reason::STALE_CONNECT_SEQ);
    let unknown = np_reject(9);
    let accept_inputs = |a: &Accept| -> Vec<(&'static str, Value)> {
        let mut v = vec![
            ("session_id_hex", json!(hex::encode(a.session_id))),
            ("connect_seq", json!(a.connect_seq)),
            ("server_nonce_hex", json!(hex::encode(a.server_nonce))),
            ("resumed", json!(a.resumed)),
            ("server_time_ms", json!(a.server_time_ms)),
        ];
        v.push(("conn_id_hex", json!(hex::encode(NP_CONN))));
        v.push(("key_s2c_hex", json!(hex::encode(NP_KEY_S2C))));
        v
    };
    let reject_inputs = |r: &Reject| -> Vec<(&'static str, Value)> {
        vec![
            ("session_id_hex", json!(hex::encode(r.session_id))),
            ("connect_seq", json!(r.connect_seq)),
            ("server_nonce_hex", json!(hex::encode(r.server_nonce))),
            ("reason", json!(r.reason)),
            ("last_connect_seq", json!(r.last_connect_seq)),
            ("conn_id_hex", json!(hex::encode(NP_CONN))),
            ("key_s2c_hex", json!(hex::encode(NP_KEY_S2C))),
        ]
    };
    let ok_bytes = |b: &[u8]| Ok(json!({ "bytes_hex": hex::encode(b) }));
    let accept_bytes = |a: &Accept| build_accept(a, &NP_CONN, &NP_KEY_S2C);
    let reject_bytes = |r: &Reject| build_reject(r, &NP_CONN, &NP_KEY_S2C);
    let a_fresh = accept_bytes(&fresh);
    let a_resumed = accept_bytes(&resumed);
    let r_stale = reject_bytes(&stale);
    let r_unknown = reject_bytes(&unknown);
    // A correctly sealed ACCEPT whose flags byte sets a reserved bit (0x02).
    let reserved_flag = {
        let mut body = [0u8; 10];
        body[0] = 0x02;
        let mut b = a_fresh[..33].to_vec();
        let mut aad = b.clone();
        aad.extend_from_slice(&NP_CONN);
        let sealed = xchacha_seal(&NP_KEY_S2C, &packet_nonce(&NP_SERVER_NONCE, 0), &aad, &body);
        b.extend_from_slice(&sealed);
        b
    };
    vec![
        NpCase {
            name: "accept_fresh",
            packet: "accept",
            op: "build",
            inputs: accept_inputs(&fresh),
            expect: ok_bytes(&a_fresh),
        },
        NpCase {
            name: "accept_fresh_open",
            packet: "accept",
            op: "open",
            inputs: np_reply_inputs(&a_fresh, NP_CONN),
            expect: Ok(np_accept_json(&fresh)),
        },
        NpCase {
            name: "accept_resumed",
            packet: "accept",
            op: "build",
            inputs: accept_inputs(&resumed),
            expect: ok_bytes(&a_resumed),
        },
        NpCase {
            name: "accept_resumed_open",
            packet: "accept",
            op: "open",
            inputs: np_reply_inputs(&a_resumed, NP_CONN),
            expect: Ok(np_accept_json(&resumed)),
        },
        NpCase {
            name: "accept_wrong_conn_id",
            packet: "accept",
            op: "open",
            inputs: np_reply_inputs(&a_fresh, [0x67; 16]),
            expect: Err(Error::AuthFailed),
        },
        NpCase {
            name: "accept_reserved_flag",
            packet: "accept",
            op: "open",
            inputs: np_reply_inputs(&reserved_flag, NP_CONN),
            expect: Err(Error::ReservedNonzero),
        },
        NpCase {
            name: "accept_len_58",
            packet: "accept",
            op: "open",
            inputs: np_reply_inputs(&a_fresh[..58], NP_CONN),
            expect: Err(Error::BadLength),
        },
        NpCase {
            name: "accept_type_84",
            packet: "accept",
            op: "open",
            inputs: np_reply_inputs(
                &{
                    let mut b = a_fresh;
                    b[0] = 0x84;
                    b
                },
                NP_CONN,
            ),
            expect: Err(Error::BadType),
        },
        NpCase {
            name: "accept_peek",
            packet: "accept",
            op: "peek",
            inputs: np_packet_input(&a_fresh),
            expect: Ok(json!({
                "type": 0x81,
                "session_id_hex": hex::encode(NP_SESSION),
                "connect_seq": NP_SEQ,
            })),
        },
        NpCase {
            name: "reject_stale",
            packet: "reject",
            op: "build",
            inputs: reject_inputs(&stale),
            expect: ok_bytes(&r_stale),
        },
        NpCase {
            name: "reject_stale_open",
            packet: "reject",
            op: "open",
            inputs: np_reply_inputs(&r_stale, NP_CONN),
            expect: Ok(np_reject_json(&stale)),
        },
        NpCase {
            name: "reject_unknown_reason_9",
            packet: "reject",
            op: "build",
            inputs: reject_inputs(&unknown),
            expect: ok_bytes(&r_unknown),
        },
        NpCase {
            name: "reject_unknown_reason_9_open",
            packet: "reject",
            op: "open",
            inputs: np_reply_inputs(&r_unknown, NP_CONN),
            expect: Ok(np_reject_json(&unknown)),
        },
        NpCase {
            name: "reject_peek",
            packet: "reject",
            op: "peek",
            inputs: np_packet_input(&r_stale),
            expect: Ok(json!({
                "type": 0x84,
                "session_id_hex": hex::encode(NP_SESSION),
                "connect_seq": NP_SEQ,
            })),
        },
        NpCase {
            name: "reply_peek_type_82_len_59",
            packet: "accept",
            op: "peek",
            inputs: np_packet_input(&{
                let mut b = a_fresh;
                b[0] = 0x82;
                b
            }),
            expect: Err(Error::BadType),
        },
        NpCase {
            name: "reply_peek_type_90_len_20",
            packet: "accept",
            op: "peek",
            inputs: np_packet_input(&[0x90; 20]),
            expect: Err(Error::BadLength),
        },
        NpCase {
            name: "reply_peek_accept_len_58",
            packet: "accept",
            op: "peek",
            inputs: np_packet_input(&a_fresh[..58]),
            expect: Err(Error::BadType),
        },
        NpCase {
            name: "reply_peek_empty",
            packet: "accept",
            op: "peek",
            inputs: np_packet_input(&[]),
            expect: Err(Error::BadLength),
        },
        NpCase {
            name: "reject_len_57",
            packet: "reject",
            op: "open",
            inputs: np_reply_inputs(&r_stale[..57], NP_CONN),
            expect: Err(Error::BadLength),
        },
        NpCase {
            name: "reject_type_81",
            packet: "reject",
            op: "open",
            inputs: np_reply_inputs(
                &{
                    let mut b = r_stale;
                    b[0] = 0x81;
                    b
                },
                NP_CONN,
            ),
            expect: Err(Error::BadType),
        },
    ]
}

fn np_data_inputs(pn: u64, frames: &[u8]) -> Vec<(&'static str, Value)> {
    vec![
        ("key_hex", json!(hex::encode(NP_KEY_S2C))),
        ("server_nonce_hex", json!(hex::encode(NP_SERVER_NONCE))),
        ("session_id_hex", json!(hex::encode(NP_SESSION))),
        ("pn", json!(pn)),
        ("frames_hex", json!(hex::encode(frames))),
    ]
}

fn np_open_inputs(b: &[u8], pn: u64) -> Vec<(&'static str, Value)> {
    vec![
        ("key_hex", json!(hex::encode(NP_KEY_S2C))),
        ("server_nonce_hex", json!(hex::encode(NP_SERVER_NONCE))),
        ("packet_hex", json!(hex::encode(b))),
        ("pn", json!(pn)),
    ]
}

fn np_header_expect(b: &[u8]) -> Value {
    np_header_expect_checked(b).unwrap()
}

fn np_header_expect_checked(b: &[u8]) -> Result<Value, Error> {
    let h = parse_header(b)?;
    Ok(json!({
        "type": h.ty,
        "session_id_hex": hex::encode(h.session_id),
        "pn_low": h.pn_low,
    }))
}

fn np_data_cases() -> Vec<NpCase> {
    let frames = (0u8..=99).collect::<Vec<_>>();
    let wrap_pn = 0x1_0000_0005u64;
    let keepalive = seal_data(&NP_KEY_S2C, &NP_SERVER_NONCE, &NP_SESSION, 1, &[]).unwrap();
    let with_frames = seal_data(&NP_KEY_S2C, &NP_SERVER_NONCE, &NP_SESSION, 42, &frames).unwrap();
    let wrap = seal_data(&NP_KEY_S2C, &NP_SERVER_NONCE, &NP_SESSION, wrap_pn, &frames).unwrap();
    let disc = seal_disconnect(&NP_KEY_S2C, &NP_SERVER_NONCE, &NP_SESSION, 43, 2).unwrap();
    let bytes = |b: &[u8]| Ok(json!({ "bytes_hex": hex::encode(b) }));
    let frames_out = |f: &[u8]| Ok(json!({ "frames_hex": hex::encode(f) }));
    // A 30-byte DATA packet (one frame byte) looks like a DISCONNECT by length only.
    let disc_len_data = seal_data(&NP_KEY_S2C, &NP_SERVER_NONCE, &NP_SESSION, 43, &[2]).unwrap();
    assert_eq!(disc_len_data.len(), 30);
    let mut type_85 = keepalive.clone();
    type_85[0] = 0x85;
    vec![
        NpCase {
            name: "data_keepalive",
            packet: "data",
            op: "seal",
            inputs: np_data_inputs(1, &[]),
            expect: bytes(&keepalive),
        },
        NpCase {
            name: "data_keepalive_open",
            packet: "data",
            op: "open",
            inputs: np_open_inputs(&keepalive, 1),
            expect: frames_out(&[]),
        },
        NpCase {
            name: "data_with_frames",
            packet: "data",
            op: "seal",
            inputs: np_data_inputs(42, &frames),
            expect: bytes(&with_frames),
        },
        NpCase {
            name: "data_with_frames_open",
            packet: "data",
            op: "open",
            inputs: np_open_inputs(&with_frames, 42),
            expect: frames_out(&frames),
        },
        NpCase {
            name: "data_pn_low_wrap",
            packet: "data",
            op: "seal",
            inputs: np_data_inputs(wrap_pn, &frames),
            expect: bytes(&wrap),
        },
        NpCase {
            name: "data_pn_low_wrap_open",
            packet: "data",
            op: "open",
            inputs: np_open_inputs(&wrap, wrap_pn),
            expect: frames_out(&frames),
        },
        NpCase {
            name: "data_pn_low_wrap_header",
            packet: "data",
            op: "parse_header",
            inputs: np_packet_input(&wrap),
            expect: Ok(np_header_expect(&wrap)),
        },
        NpCase {
            name: "data_wrong_pn",
            packet: "data",
            op: "open",
            inputs: np_open_inputs(&with_frames, 43),
            expect: Err(Error::AuthFailed),
        },
        NpCase {
            name: "data_pn_zero",
            packet: "data",
            op: "seal",
            inputs: np_data_inputs(0, &[]),
            expect: Err(Error::Replayed),
        },
        NpCase {
            name: "data_frames_1172",
            packet: "data",
            op: "seal",
            inputs: np_data_inputs(1, &vec![0; 1172]),
            expect: Err(Error::TooLarge),
        },
        NpCase {
            name: "data_len_28",
            packet: "data",
            op: "parse_header",
            inputs: np_packet_input(&keepalive[..28]),
            expect: Err(Error::BadLength),
        },
        NpCase {
            name: "data_type_85",
            packet: "data",
            op: "parse_header",
            inputs: np_packet_input(&type_85),
            expect: Err(Error::BadType),
        },
        NpCase {
            name: "disconnect_normal",
            packet: "disconnect",
            op: "seal",
            inputs: {
                let mut v = np_data_inputs(43, &[]);
                v.pop();
                v.push(("reason", json!(2)));
                v
            },
            expect: bytes(&disc),
        },
        NpCase {
            name: "disconnect_normal_open",
            packet: "disconnect",
            op: "open",
            inputs: np_open_inputs(&disc, 43),
            expect: Ok(json!({ "reason": 2 })),
        },
        NpCase {
            name: "disconnect_len_29",
            packet: "disconnect",
            op: "open",
            inputs: np_open_inputs(&disc[..29], 43),
            expect: Err(Error::BadLength),
        },
        NpCase {
            name: "disconnect_pn_zero",
            packet: "disconnect",
            op: "seal",
            inputs: {
                let mut v = np_data_inputs(0, &[]);
                v.pop();
                v.push(("reason", json!(2)));
                v
            },
            expect: Err(Error::Replayed),
        },
        NpCase {
            name: "data_pn_zero_frames_1172",
            packet: "data",
            op: "seal",
            inputs: np_data_inputs(0, &vec![0; 1172]),
            expect: Err(Error::TooLarge),
        },
        NpCase {
            name: "data_open_len_1201",
            packet: "data",
            op: "open",
            inputs: np_open_inputs(&vec![0x82; 1201], 1),
            expect: Err(Error::BadLength),
        },
        NpCase {
            name: "data_open_disconnect_type",
            packet: "data",
            op: "open",
            inputs: np_open_inputs(&disc, 43),
            expect: Err(Error::BadType),
        },
        NpCase {
            name: "disconnect_open_data_type",
            packet: "disconnect",
            op: "open",
            inputs: np_open_inputs(&disc_len_data, 43),
            expect: Err(Error::BadType),
        },
    ]
}

/// `op: decode_pn` expects `{pn}`; `op: window` replays `commits`, then checks `check`.
fn np_pn_cases() -> Vec<NpCase> {
    let decode = |name, largest: u64, low: u32, pn: u64| NpCase {
        name,
        packet: "pn",
        op: "decode_pn",
        inputs: vec![("largest", json!(largest)), ("low", json!(low))],
        expect: Ok(json!({ "pn": pn })),
    };
    let window = |name, commits: &[u64], check: u64, e: Option<Error>| NpCase {
        name,
        packet: "replay",
        op: "window",
        inputs: vec![("commits", json!(commits)), ("check", json!(check))],
        expect: match e {
            None => Ok(json!({ "status": "ok" })),
            Some(e) => Err(e),
        },
    };
    vec![
        decode("pn_first_packet", 0, 1, 1),
        decode("pn_next", 1000, 1001, 1001),
        decode("pn_reordered_back", 1000, 990, 990),
        decode("pn_boundary_forward", 0xFFFF_FFF0, 2, 0x1_0000_0002),
        decode(
            "pn_boundary_stays_low",
            0x1_0000_0005,
            0xFFFF_FFFF,
            0xFFFF_FFFF,
        ),
        decode("pn_boundary_stays_high", 0x1_0000_0005, 3, 0x1_0000_0003),
        window("window_fresh_ok", &[], 1, None),
        window("window_pn_zero", &[], 0, Some(Error::Replayed)),
        window("window_pn_zero_after_500", &[500], 0, Some(Error::Replayed)),
        window("window_duplicate", &[5, 6, 7], 6, Some(Error::Replayed)),
        window("window_gap_ok", &[5, 7], 6, None),
        window("window_edge_ok", &[1000], 745, None),
        window("window_edge_too_old", &[1000], 744, Some(Error::TooOld)),
        window(
            "window_jump_clears_old",
            &[1, 2, 3, 600],
            3,
            Some(Error::TooOld),
        ),
        window(
            "window_jump_reuses_slot",
            &[3, 259],
            259,
            Some(Error::Replayed),
        ),
        window(
            "window_old_still_in_window",
            &[3, 258],
            3,
            Some(Error::Replayed),
        ),
    ]
}

fn np_cases() -> Vec<NpCase> {
    let mut v = Vec::new();
    v.extend(np_connect_cases());
    v.extend(np_reply_cases());
    v.extend(np_data_cases());
    v.extend(np_pn_cases());
    v
}

#[test]
#[ignore = "regenerates vectors/native_packets.json"]
fn write_native_packets_vectors() {
    let cases: Vec<Value> = np_cases()
        .into_iter()
        .map(|c| {
            let mut m = serde_json::Map::new();
            m.insert("name".into(), json!(c.name));
            m.insert("packet".into(), json!(c.packet));
            m.insert("op".into(), json!(c.op));
            for (k, v) in c.inputs {
                m.insert(k.into(), v);
            }
            match c.expect {
                Ok(e) => m.insert("expect".into(), e),
                Err(e) => m.insert("error".into(), json!(e.code())),
            };
            Value::Object(m)
        })
        .collect();
    common::write_vectors(NP_FILE, &json!({ "cases": cases }));
}

fn np_hex(c: &Value, key: &str) -> Vec<u8> {
    hex::decode(c[key].as_str().unwrap_or_else(|| panic!("missing {key}"))).unwrap()
}

fn np_arr<const N: usize>(c: &Value, key: &str) -> [u8; N] {
    np_hex(c, key).try_into().unwrap()
}

/// Runs one case and returns the result in the file's `expect` shape.
fn np_run(c: &Value) -> Result<Value, Error> {
    let name = c["name"].as_str().unwrap();
    match (c["packet"].as_str().unwrap(), c["op"].as_str().unwrap()) {
        ("connect", "build") => {
            let b = build_connect(
                &np_arr(c, "session_id_hex"),
                &np_arr(c, "conn_id_hex"),
                c["connect_seq"].as_u64().unwrap(),
                &np_arr(c, "routing_ticket_hex"),
                &np_hex(c, "server_ticket_hex"),
                &np_arr(c, "key_c2s_hex"),
                c["pad_to"].as_u64().unwrap() as usize,
            )?;
            Ok(json!({ "bytes_hex": hex::encode(b) }))
        }
        ("connect", "parse") => {
            let b = np_hex(c, "packet_hex");
            parse_connect(&b)?;
            Ok(np_parse_expect(&b))
        }
        ("connect", "verify") => {
            let b = np_hex(c, "packet_hex");
            let v = verify_connect(
                &b,
                &st_ring(),
                &np_arr(c, "self_server_id_hex"),
                c["now"].as_u64().unwrap() as u32,
            )?;
            Ok(json!({
                "session_id_hex": hex::encode(v.session_id),
                "conn_id_hex": hex::encode(v.conn_id),
                "connect_seq": v.connect_seq,
                "user_id": v.ticket.user_id,
            }))
        }
        ("connect", "split_trailer") => {
            let b = np_hex(c, "packet_hex");
            let (body, a) = split_trailer(&b)?;
            Ok(np_trailer_expect(body, a))
        }
        ("accept", "build") => {
            let a = Accept {
                session_id: np_arr(c, "session_id_hex"),
                connect_seq: c["connect_seq"].as_u64().unwrap(),
                server_nonce: np_arr(c, "server_nonce_hex"),
                resumed: c["resumed"].as_bool().unwrap(),
                server_time_ms: c["server_time_ms"].as_u64().unwrap(),
            };
            let b = build_accept(&a, &np_arr(c, "conn_id_hex"), &np_arr(c, "key_s2c_hex"));
            Ok(json!({ "bytes_hex": hex::encode(b) }))
        }
        ("accept", "open") => {
            let a = open_accept(
                &np_hex(c, "packet_hex"),
                &np_arr(c, "conn_id_hex"),
                &np_arr(c, "key_s2c_hex"),
            )?;
            Ok(np_accept_json(&a))
        }
        ("accept" | "reject", "peek") => {
            let (ty, session_id, seq) = peek_reply(&np_hex(c, "packet_hex"))?;
            Ok(json!({
                "type": ty,
                "session_id_hex": hex::encode(session_id),
                "connect_seq": seq,
            }))
        }
        ("reject", "build") => {
            let r = Reject {
                session_id: np_arr(c, "session_id_hex"),
                connect_seq: c["connect_seq"].as_u64().unwrap(),
                server_nonce: np_arr(c, "server_nonce_hex"),
                reason: c["reason"].as_u64().unwrap() as u8,
                last_connect_seq: c["last_connect_seq"].as_u64().unwrap(),
            };
            let b = build_reject(&r, &np_arr(c, "conn_id_hex"), &np_arr(c, "key_s2c_hex"));
            Ok(json!({ "bytes_hex": hex::encode(b) }))
        }
        ("reject", "open") => {
            let r = open_reject(
                &np_hex(c, "packet_hex"),
                &np_arr(c, "conn_id_hex"),
                &np_arr(c, "key_s2c_hex"),
            )?;
            Ok(np_reject_json(&r))
        }
        ("data", "seal") => {
            let b = seal_data(
                &np_arr(c, "key_hex"),
                &np_arr(c, "server_nonce_hex"),
                &np_arr(c, "session_id_hex"),
                c["pn"].as_u64().unwrap(),
                &np_hex(c, "frames_hex"),
            )?;
            Ok(json!({ "bytes_hex": hex::encode(b) }))
        }
        ("data", "open") => {
            let f = open_data(
                &np_arr(c, "key_hex"),
                &np_arr(c, "server_nonce_hex"),
                &np_hex(c, "packet_hex"),
                c["pn"].as_u64().unwrap(),
            )?;
            Ok(json!({ "frames_hex": hex::encode(f) }))
        }
        ("data", "parse_header") => Ok(np_header_expect_checked(&np_hex(c, "packet_hex"))?),
        ("disconnect", "seal") => {
            let b = seal_disconnect(
                &np_arr(c, "key_hex"),
                &np_arr(c, "server_nonce_hex"),
                &np_arr(c, "session_id_hex"),
                c["pn"].as_u64().unwrap(),
                c["reason"].as_u64().unwrap() as u8,
            )?;
            Ok(json!({ "bytes_hex": hex::encode(b) }))
        }
        ("disconnect", "open") => {
            let r = open_disconnect(
                &np_arr(c, "key_hex"),
                &np_arr(c, "server_nonce_hex"),
                &np_hex(c, "packet_hex"),
                c["pn"].as_u64().unwrap(),
            )?;
            Ok(json!({ "reason": r }))
        }
        ("pn", "decode_pn") => Ok(json!({
            "pn": decode_pn(
                c["largest"].as_u64().unwrap(),
                c["low"].as_u64().unwrap() as u32,
            )
        })),
        ("replay", "window") => {
            let mut w = ReplayWindow::new();
            for pn in c["commits"].as_array().unwrap() {
                w.commit(pn.as_u64().unwrap());
            }
            w.check(c["check"].as_u64().unwrap())?;
            Ok(json!({ "status": "ok" }))
        }
        (p, op) => panic!("{name}: unsupported case {p}/{op}"),
    }
}

#[test]
fn check_native_packets_vectors() {
    let file = common::read_vectors(NP_FILE);
    let cases = file["cases"].as_array().unwrap();
    assert_eq!(cases.len(), np_cases().len());
    let mut names = std::collections::HashSet::new();
    for c in cases {
        let name = c["name"].as_str().unwrap();
        assert!(names.insert(name), "duplicate case name {name}");
        let got = np_run(c);
        match c.get("error") {
            Some(code) => assert_eq!(
                got.map_err(|e| e.code()),
                Err(code.as_str().unwrap()),
                "{name}"
            ),
            None => assert_eq!(
                got.unwrap_or_else(|e| panic!("{name}: {e}")),
                c["expect"],
                "{name}"
            ),
        }
    }
}

// ---------------------------------------------------------------- frames.json

const FR_FILE: &str = "frames.json";

/// Frame spelled out independently of the codec so the vector file does not simply echo it.
enum FrExpect {
    Ack(u32, u16, u64),
    Stream(u64, Vec<u8>),
    Datagram(Vec<u8>),
}

struct FrCase {
    name: &'static str,
    plaintext: Vec<u8>,
    result: Result<Vec<FrExpect>, Error>,
}

fn fr_varint(v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    varint::encode(v, &mut out).unwrap_or_else(|e| panic!("varint {v}: {e}"));
    out
}

fn fr_ack_bytes(largest: u32, delay: u16, bits: u64) -> Vec<u8> {
    let mut mask = 0u8;
    let mut tail = Vec::new();
    for i in 0..8 {
        let b = (bits >> (8 * i)) as u8;
        if b != 0xFF {
            mask |= 1 << i;
            tail.push(b);
        }
    }
    let mut v = vec![0x01];
    v.extend(largest.to_be_bytes());
    v.extend(delay.to_be_bytes());
    v.push(mask);
    v.extend(tail);
    v
}

fn fr_stream_bytes(offset: u64, data: &[u8]) -> Vec<u8> {
    let mut v = vec![0x02];
    v.extend(fr_varint(offset));
    v.extend(fr_varint(data.len() as u64));
    v.extend(data);
    v
}

fn fr_datagram_bytes(data: &[u8]) -> Vec<u8> {
    let mut v = vec![0x03];
    v.extend(fr_varint(data.len() as u64));
    v.extend(data);
    v
}

fn fr_datagram_header(len: u64) -> Vec<u8> {
    let mut v = vec![0x03];
    v.extend(fr_varint(len));
    v
}

fn fr_cases() -> Vec<FrCase> {
    let cat = |parts: &[Vec<u8>]| parts.concat();
    let sparse = 0xFFFF_FFFF_00FF_FE00u64;
    let max = varint::MAX;
    let mut dg_big_after_acks = fr_ack_bytes(7, 1, u64::MAX);
    dg_big_after_acks.extend(fr_ack_bytes(8, 1, u64::MAX));
    dg_big_after_acks.extend(fr_datagram_bytes(&[0x5a; 1101]));
    vec![
        FrCase {
            name: "empty",
            plaintext: vec![],
            result: Ok(vec![]),
        },
        FrCase {
            name: "ack_only",
            plaintext: fr_ack_bytes(0x0102_0304, 0xFFFF, u64::MAX),
            result: Ok(vec![FrExpect::Ack(0x0102_0304, 0xFFFF, u64::MAX)]),
        },
        FrCase {
            name: "ack_sparse",
            plaintext: fr_ack_bytes(0xFFFF_FFF0, 300, sparse),
            result: Ok(vec![FrExpect::Ack(0xFFFF_FFF0, 300, sparse)]),
        },
        FrCase {
            name: "stream_offset_0",
            plaintext: fr_stream_bytes(0, b"hello"),
            result: Ok(vec![FrExpect::Stream(0, b"hello".to_vec())]),
        },
        FrCase {
            name: "stream_big_offset",
            plaintext: fr_stream_bytes(1 << 40, &[1, 2, 3]),
            result: Ok(vec![FrExpect::Stream(1 << 40, vec![1, 2, 3])]),
        },
        FrCase {
            name: "datagram_1100",
            plaintext: fr_datagram_bytes(&[0xd1; 1100]),
            result: Ok(vec![FrExpect::Datagram(vec![0xd1; 1100])]),
        },
        FrCase {
            name: "datagram_1101",
            plaintext: fr_datagram_bytes(&[0xd1; 1101]),
            result: Err(Error::TooLarge),
        },
        FrCase {
            // Short data must not mask the length-limit error: the limit is checked first.
            name: "datagram_1101_short_data",
            plaintext: cat(&[fr_datagram_header(1101), vec![0xd1; 5]]),
            result: Err(Error::TooLarge),
        },
        FrCase {
            name: "mixed_three_frames",
            plaintext: cat(&[
                fr_ack_bytes(99, 5, 0xFFFF_FFFF_FFFF_FFFE),
                fr_stream_bytes(70, b"abc"),
                fr_datagram_bytes(b"xyz"),
            ]),
            result: Ok(vec![
                FrExpect::Ack(99, 5, 0xFFFF_FFFF_FFFF_FFFE),
                FrExpect::Stream(70, b"abc".to_vec()),
                FrExpect::Datagram(b"xyz".to_vec()),
            ]),
        },
        FrCase {
            name: "two_acks",
            plaintext: cat(&[fr_ack_bytes(1, 1, u64::MAX), fr_ack_bytes(2, 2, u64::MAX)]),
            result: Err(Error::DuplicateAck),
        },
        FrCase {
            name: "datagram_1101_after_two_acks",
            plaintext: dg_big_after_acks,
            result: Err(Error::DuplicateAck),
        },
        FrCase {
            name: "ack_present_ff",
            plaintext: vec![0x01, 0, 0, 0, 9, 0, 0, 0x01, 0xFF],
            result: Err(Error::NonCanonicalAck),
        },
        FrCase {
            name: "ack_truncated_bits",
            plaintext: vec![0x01, 0, 0, 0, 9, 0, 0, 0x03, 0x00],
            result: Err(Error::Truncated),
        },
        FrCase {
            name: "unknown_type_04",
            plaintext: vec![0x04],
            result: Err(Error::BadType),
        },
        FrCase {
            name: "stream_truncated_data",
            plaintext: vec![0x02, 0x00, 0x05, 0xaa, 0xbb],
            result: Err(Error::Truncated),
        },
        FrCase {
            name: "stream_noncanonical_offset",
            plaintext: vec![0x02, 0x40, 0x01, 0x00],
            result: Err(Error::NonCanonicalVarint),
        },
        FrCase {
            name: "stream_offset_overflow",
            plaintext: cat(&[vec![0x02], fr_varint(max), vec![0x01, 0xaa]]),
            result: Err(Error::ValueTooLarge),
        },
        FrCase {
            // offset + len > 2^62 - 1 is reported even though the data bytes are missing.
            name: "stream_overflow_short_data",
            plaintext: cat(&[vec![0x02], fr_varint(max), fr_varint(2), vec![0xaa]]),
            result: Err(Error::ValueTooLarge),
        },
        FrCase {
            name: "stream_end_at_limit",
            plaintext: cat(&[vec![0x02], fr_varint(max), vec![0x00]]),
            result: Ok(vec![FrExpect::Stream(max, vec![])]),
        },
    ]
}

fn fr_expect_json(f: &FrExpect) -> Value {
    match f {
        FrExpect::Ack(l, d, b) => json!({
            "type": "ack", "largest_pn_low": l, "ack_delay": d,
            "ack_bits_hex": format!("{b:016x}"),
        }),
        FrExpect::Stream(o, d) => {
            json!({"type": "stream", "offset": o, "data_hex": hex::encode(d)})
        }
        FrExpect::Datagram(d) => json!({"type": "datagram", "data_hex": hex::encode(d)}),
    }
}

fn fr_frame_json(f: &Frame) -> Value {
    match f {
        Frame::Ack(a) => fr_expect_json(&FrExpect::Ack(a.largest_pn_low, a.ack_delay, a.ack_bits)),
        Frame::Stream { offset, data } => fr_expect_json(&FrExpect::Stream(*offset, data.to_vec())),
        Frame::Datagram(d) => fr_expect_json(&FrExpect::Datagram(d.to_vec())),
    }
}

#[test]
#[ignore = "regenerates vectors/frames.json"]
fn write_frames_vectors() {
    let cases: Vec<Value> = fr_cases()
        .iter()
        .map(|c| match &c.result {
            Ok(frames) => json!({
                "name": c.name,
                "plaintext_hex": hex::encode(&c.plaintext),
                "expect": {"frames": frames.iter().map(fr_expect_json).collect::<Vec<_>>()},
            }),
            Err(e) => json!({
                "name": c.name,
                "plaintext_hex": hex::encode(&c.plaintext),
                "error": e.code(),
            }),
        })
        .collect();
    common::write_vectors(FR_FILE, &json!({ "cases": cases }));
}

#[test]
fn check_frames_vectors() {
    let file = common::read_vectors(FR_FILE);
    let cases = file["cases"].as_array().unwrap();
    assert_eq!(cases.len(), fr_cases().len());
    let mut names = std::collections::HashSet::new();
    for c in cases {
        let name = c["name"].as_str().unwrap();
        assert!(names.insert(name), "duplicate case name {name}");
        let plaintext = hex::decode(c["plaintext_hex"].as_str().unwrap()).unwrap();
        let got = decode_frames(&plaintext);
        match c.get("error") {
            Some(code) => assert_eq!(
                got.map(|_| ()).map_err(|e| e.code()),
                Err(code.as_str().unwrap()),
                "{name}"
            ),
            None => {
                let frames = got.unwrap_or_else(|e| panic!("{name}: {e}"));
                let json: Vec<Value> = frames.iter().map(fr_frame_json).collect();
                assert_eq!(Value::Array(json), c["expect"]["frames"], "{name}");
                // Canonical encoding: re-encoding reproduces the input bytes.
                let mut again = Vec::new();
                for f in &frames {
                    encode_frame(f, &mut again).unwrap();
                }
                assert_eq!(again, plaintext, "{name}");
            }
        }
    }
}

// ---------------------------------------------------------------- wt_framing.json

const WF_FILE: &str = "wt_framing.json";

/// Outcome of a `kind: "stream"` case: messages plus the unconsumed tail, or an error.
type WfStream = Result<(Vec<Vec<u8>>, Vec<u8>), Error>;

enum WfCase {
    Stream(&'static str, Vec<u8>, WfStream),
    Path(&'static str, String, Result<Vec<u8>, Error>),
}

fn wf_msg(payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    encode_message_header(payload.len(), &mut v).unwrap_or_else(|e| panic!("header: {e}"));
    v.extend_from_slice(payload);
    v
}

fn wf_ticket(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn wf_path_of(ticket: &[u8]) -> String {
    format!("{WT_PATH_PREFIX}{}", URL_SAFE_NO_PAD.encode(ticket))
}

fn wf_cases() -> Vec<WfCase> {
    use WfCase::{Path, Stream};
    let two = [wf_msg(b"abc"), wf_msg(b"de")].concat();
    let tail = [wf_msg(b"abc"), vec![0x05, 0x01, 0x02]].concat();
    let ok = |msgs: &[&[u8]], rest: &[u8]| {
        Ok((msgs.iter().map(|m| m.to_vec()).collect(), rest.to_vec()))
    };
    vec![
        Stream("stream_two_messages", two, ok(&[b"abc", b"de"], &[])),
        Stream(
            "stream_partial_tail",
            tail,
            ok(&[b"abc"], &[0x05, 0x01, 0x02]),
        ),
        Stream("stream_empty_message", vec![0x00], ok(&[b""], &[])),
        Stream(
            "stream_partial_varint",
            vec![0x01, b'x', 0x40],
            ok(&[b"x"], &[0x40]),
        ),
        Stream(
            "stream_len_262144_awaiting_body",
            vec![0x80, 0x04, 0x00, 0x00, 0xaa],
            ok(&[], &[0x80, 0x04, 0x00, 0x00, 0xaa]),
        ),
        Stream(
            "stream_len_262145",
            vec![0x80, 0x04, 0x00, 0x01],
            Err(Error::TooLarge),
        ),
        Stream(
            "stream_noncanonical_len",
            vec![0x40, 0x05, 1, 2, 3, 4, 5],
            Err(Error::NonCanonicalVarint),
        ),
        Stream(
            "stream_error_after_good_message",
            [wf_msg(b"ok"), vec![0x80, 0x04, 0x00, 0x01]].concat(),
            Err(Error::TooLarge),
        ),
        Path(
            "path_valid",
            wf_path_of(&wf_ticket(144)),
            Ok(wf_ticket(144)),
        ),
        Path("path_min", wf_path_of(&wf_ticket(75)), Ok(wf_ticket(75))),
        Path("path_max", wf_path_of(&wf_ticket(394)), Ok(wf_ticket(394))),
        Path(
            "path_537",
            format!("{WT_PATH_PREFIX}{}", "A".repeat(527)),
            Err(Error::TooLarge),
        ),
        Path(
            "path_wrong_prefix",
            format!("/other?t={}", URL_SAFE_NO_PAD.encode(wf_ticket(144))),
            Err(Error::BadEncoding),
        ),
        Path(
            "path_extra_param",
            format!("{}&x=1", wf_path_of(&wf_ticket(144))),
            Err(Error::BadEncoding),
        ),
        Path(
            "path_fragment",
            format!("{}#f", wf_path_of(&wf_ticket(144))),
            Err(Error::BadEncoding),
        ),
        Path(
            "path_padded_base64",
            format!("{WT_PATH_PREFIX}{}", STANDARD.encode(wf_ticket(76))),
            Err(Error::BadEncoding),
        ),
        Path(
            "path_ticket_too_short",
            wf_path_of(&wf_ticket(74)),
            Err(Error::BadLength),
        ),
        Path(
            // 395 bytes encode to 527 characters, so the path-length check fires first.
            "path_ticket_395",
            wf_path_of(&wf_ticket(395)),
            Err(Error::TooLarge),
        ),
    ]
}

/// Splits `stream` into messages. The C++ port mirrors this loop exactly:
/// repeat `decode_message_header(rest)`: `NeedMore` -> stop; error -> the whole case is that
/// error (messages already sliced are discarded); `Ready` -> if fewer than `header_len + len`
/// bytes remain stop, else slice out the payload and continue. `rest` at the stop is the
/// remainder.
fn wf_split(stream: &[u8]) -> WfStream {
    let mut rest = stream;
    let mut msgs = Vec::new();
    loop {
        match decode_message_header(rest)? {
            MessageHeader::NeedMore => break,
            MessageHeader::Ready { len, header_len } => {
                let Some(payload) = rest.get(header_len..header_len + len) else {
                    break;
                };
                msgs.push(payload.to_vec());
                rest = &rest[header_len + len..];
            }
        }
    }
    Ok((msgs, rest.to_vec()))
}

#[test]
#[ignore = "regenerates vectors/wt_framing.json"]
fn write_wt_framing_vectors() {
    let cases: Vec<Value> = wf_cases()
        .iter()
        .map(|c| match c {
            WfCase::Stream(name, stream, Ok((msgs, rest))) => json!({
                "name": name, "kind": "stream", "stream_hex": hex::encode(stream),
                "expect": {
                    "messages_hex": msgs.iter().map(hex::encode).collect::<Vec<_>>(),
                    "remainder_hex": hex::encode(rest),
                },
            }),
            WfCase::Stream(name, stream, Err(e)) => json!({
                "name": name, "kind": "stream", "stream_hex": hex::encode(stream),
                "error": e.code(),
            }),
            WfCase::Path(name, path, Ok(t)) => json!({
                "name": name, "kind": "path", "path": path,
                "expect": {"ticket_hex": hex::encode(t)},
            }),
            WfCase::Path(name, path, Err(e)) => json!({
                "name": name, "kind": "path", "path": path, "error": e.code(),
            }),
        })
        .collect();
    common::write_vectors(WF_FILE, &json!({ "cases": cases }));
}

#[test]
fn check_wt_framing_vectors() {
    let file = common::read_vectors(WF_FILE);
    let cases = file["cases"].as_array().unwrap();
    assert_eq!(cases.len(), wf_cases().len());
    let mut names = std::collections::HashSet::new();
    for c in cases {
        let name = c["name"].as_str().unwrap();
        assert!(names.insert(name), "duplicate case name {name}");
        let got: Result<Value, Error> = match c["kind"].as_str().unwrap() {
            "stream" => {
                let stream = hex::decode(c["stream_hex"].as_str().unwrap()).unwrap();
                wf_split(&stream).map(|(msgs, rest)| {
                    json!({
                        "messages_hex": msgs.iter().map(hex::encode).collect::<Vec<_>>(),
                        "remainder_hex": hex::encode(rest),
                    })
                })
            }
            "path" => {
                let path = c["path"].as_str().unwrap();
                parse_wt_path(path).map(|t| {
                    // Canonical: rebuilding the path reproduces the input.
                    assert_eq!(wt_path(&t).as_deref(), Ok(path), "{name}");
                    json!({"ticket_hex": hex::encode(t)})
                })
            }
            other => panic!("{name}: unknown kind {other}"),
        };
        match c.get("error") {
            Some(code) => assert_eq!(
                got.map(|_| ()).map_err(|e| e.code()),
                Err(code.as_str().unwrap()),
                "{name}"
            ),
            None => assert_eq!(
                got.unwrap_or_else(|e| panic!("{name}: {e}")),
                c["expect"],
                "{name}"
            ),
        }
    }
}
