//! Golden-vector generators and checkers. Each file's `write_*` (ignored; regenerates the
//! file) sits next to its `check_*` (re-reads the file and compares every case).
//! Format: see the vector file format in the SP1 plan.

mod common;

use aes_gcm::aead::AeadInOut;
use aes_gcm::{Aes128Gcm, KeyInit};
use glassy_proto::routing_ticket::{
    RoutingKeyRing, RoutingTicket, from_sni, from_ufrag, open_routing, seal_routing, to_sni_labels,
    to_ufrag,
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
