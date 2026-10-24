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
use glassy_proto::crypto::{k_ticket, xchacha_seal};
use glassy_proto::ice::ice_pwd;
use glassy_proto::retry::{mint_retry_token, retry_token_odcid, validate_retry_token};
use glassy_proto::routing_ticket::{
    RoutingKeyRing, RoutingTicket, from_sni, from_ufrag, open_routing, seal_routing, to_sni_labels,
    to_ufrag,
};
use glassy_proto::server_ticket::{
    NativeKeys, ServerKeyRing, ServerTicket, open_server, seal_server,
};
use glassy_proto::{Error, transport};
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
