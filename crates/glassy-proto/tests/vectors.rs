//! Golden-vector generators and checkers. Each file's `write_*` (ignored; regenerates the
//! file) sits next to its `check_*` (re-reads the file and compares every case).
//! Format: see the vector file format in the SP1 plan.

mod common;

use aes_gcm::aead::AeadInOut;
use aes_gcm::{Aes128Gcm, KeyInit};
use glassy_proto::crypto::{k_ticket, xchacha_seal};
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
