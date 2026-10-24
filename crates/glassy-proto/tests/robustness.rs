//! Robustness sweep: every proper prefix of every valid vector input must be rejected (or at
//! least must not panic, for formats whose prefixes can legitimately decode), and fixed-length
//! or self-describing formats must also reject the input extended by one byte.

mod common;

use glassy_proto::Error;
use glassy_proto::connect_info::decode_connect_info;
use glassy_proto::frame::decode_frames;
use glassy_proto::message::{MessageHeader, decode_message_header};
use glassy_proto::packet::{
    open_accept, open_data, open_disconnect, open_reject, parse_connect, parse_header, peek_reply,
    split_trailer, verify_connect,
};
use glassy_proto::retry::{retry_token_odcid, validate_retry_token};
use glassy_proto::routing_ticket::{RoutingKeyRing, open_routing};
use glassy_proto::server_ticket::{ServerKeyRing, open_server};
use glassy_proto::wt::{WT_PATH_PREFIX, parse_wt_path};
use serde_json::Value;

const RETRY_KEY: [u8; 32] = [0x33; 32];

fn rt_ring() -> RoutingKeyRing {
    RoutingKeyRing::new(1, [0x11; 16])
}

fn st_ring() -> ServerKeyRing {
    ServerKeyRing::new(1, [0x22; 32])
}

fn valid_cases(file: &str) -> Vec<Value> {
    common::read_vectors(file)["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c.get("error").is_none())
        .cloned()
        .collect()
}

fn hex_of(c: &Value, key: &str) -> Vec<u8> {
    hex::decode(c[key].as_str().unwrap_or_else(|| panic!("missing {key}"))).unwrap()
}

fn arr<const N: usize>(c: &Value, key: &str) -> [u8; N] {
    hex_of(c, key).try_into().unwrap()
}

/// Every proper prefix must be rejected; when `extend` is set, `input + [0x00]` as well.
fn sweep(name: &str, input: &[u8], extend: bool, run: impl Fn(&[u8]) -> Result<(), Error>) {
    run(input).unwrap_or_else(|e| panic!("{name}: the full input must be accepted: {e}"));
    for k in 0..input.len() {
        assert!(
            run(&input[..k]).is_err(),
            "{name}: prefix of {k} bytes was accepted"
        );
    }
    if extend {
        let mut longer = input.to_vec();
        longer.push(0x00);
        assert!(run(&longer).is_err(), "{name}: input + 0x00 was accepted");
    }
}

/// Like `sweep` for CONNECT: trailing 0x00 bytes are padding, so a prefix that keeps every
/// non-zero byte may be accepted and no extension check applies. (A real trailing zero byte
/// only makes this bound conservative.)
fn sweep_padded(name: &str, input: &[u8], run: impl Fn(&[u8]) -> Result<(), Error>) {
    let significant = input.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    run(input).unwrap_or_else(|e| panic!("{name}: the full input must be accepted: {e}"));
    for k in 0..significant {
        assert!(
            run(&input[..k]).is_err(),
            "{name}: prefix of {k} bytes was accepted"
        );
    }
}

/// For formats where a prefix can be valid: only checks that nothing panics.
fn sweep_no_panic(input: &[u8], run: impl Fn(&[u8]) -> Result<(), Error>) {
    for k in 0..=input.len() {
        let _ = run(&input[..k]);
    }
    let mut longer = input.to_vec();
    longer.push(0x00);
    let _ = run(&longer);
}

#[test]
fn every_prefix_is_rejected_routing_ticket() {
    for c in valid_cases("routing_ticket.json") {
        let name = c["name"].as_str().unwrap();
        let ticket = hex_of(&c, "ticket_hex");
        let via = c["via"].as_u64().unwrap() as u8;
        let now = c["now"].as_u64().unwrap() as u32;
        let sid: Option<[u8; 8]> = c
            .get("connect_session_id_hex")
            .map(|_| arr(&c, "connect_session_id_hex"));
        sweep(name, &ticket, true, |b| {
            open_routing(b, &rt_ring(), now, via, sid.as_ref()).map(|_| ())
        });
    }
}

#[test]
fn every_prefix_is_rejected_server_ticket() {
    for c in valid_cases("server_ticket.json") {
        let name = c["name"].as_str().unwrap();
        let ticket = hex_of(&c, "ticket_hex");
        let via = c["via"].as_u64().unwrap() as u8;
        let now = c["now"].as_u64().unwrap() as u32;
        let sid: [u8; 16] = arr(&c, "self_server_id_hex");
        sweep(name, &ticket, true, |b| {
            open_server(b, &st_ring(), now, &sid, via).map(|_| ())
        });
    }
}

#[test]
fn every_prefix_is_rejected_retry_token() {
    for c in valid_cases("retry_token.json") {
        let name = c["name"].as_str().unwrap();
        let token = hex_of(&c, "token_hex");
        let client: std::net::SocketAddr = c["client"].as_str().unwrap().parse().unwrap();
        let dcid = hex_of(&c, "dcid_hex");
        let now = c["now"].as_u64().unwrap();
        match c["mode"].as_str().unwrap() {
            "validate" => sweep(name, &token, true, |b| {
                validate_retry_token(&RETRY_KEY, b, client, &dcid, now).map(|_| ())
            }),
            "parse" => sweep(name, &token, true, |b| retry_token_odcid(b).map(|_| ())),
            m => panic!("{name}: unknown mode {m}"),
        }
    }
}

#[test]
fn every_prefix_is_rejected_connect_info() {
    use base64::Engine;
    for c in valid_cases("connect_info.json") {
        let name = c["name"].as_str().unwrap();
        let input = match (c.get("json"), c.get("input")) {
            (Some(j), None) => base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(j.as_str().unwrap().as_bytes()),
            (None, Some(i)) => i.as_str().unwrap().to_string(),
            _ => panic!("{name}: need exactly one of json/input"),
        };
        // Cutting only trailing JSON whitespace leaves a valid document, so a prefix that still
        // decodes to every non-whitespace byte may legitimately be accepted (json cases only).
        let significant = c
            .get("json")
            .and_then(Value::as_str)
            .map(|j| j.trim_end_matches([' ', '\t', '\r', '\n']).len());
        // The base64 alphabet is ASCII, so byte prefixes are valid str prefixes.
        assert!(input.is_ascii(), "{name}");
        for k in 0..input.len() {
            let allowed = significant.is_some_and(|n| k * 3 / 4 >= n);
            assert!(
                allowed || decode_connect_info(&input[..k]).is_err(),
                "{name}: prefix of {k} chars was accepted"
            );
        }
    }
}

#[test]
fn every_prefix_is_rejected_native_packets() {
    for c in valid_cases("native_packets.json") {
        let name = c["name"].as_str().unwrap();
        let packet = c["packet"].as_str().unwrap();
        let op = c["op"].as_str().unwrap();
        match (packet, op) {
            ("connect", "parse") => {
                sweep_padded(name, &hex_of(&c, "packet_hex"), |b| {
                    parse_connect(b).map(|_| ())
                });
            }
            ("connect", "verify") => {
                let sid: [u8; 16] = arr(&c, "self_server_id_hex");
                let now = c["now"].as_u64().unwrap() as u32;
                // A trailing 0x00 is valid CONNECT padding, so no extension check.
                sweep_padded(name, &hex_of(&c, "packet_hex"), |b| {
                    verify_connect(b, &st_ring(), now, &sid).map(|_| ())
                });
            }
            ("connect", "split_trailer") => {
                sweep(name, &hex_of(&c, "packet_hex"), false, |b| {
                    split_trailer(b).map(|_| ())
                });
            }
            ("accept", "open") => {
                let conn: [u8; 16] = arr(&c, "conn_id_hex");
                let key: [u8; 32] = arr(&c, "key_s2c_hex");
                sweep(name, &hex_of(&c, "packet_hex"), true, |b| {
                    open_accept(b, &conn, &key).map(|_| ())
                });
            }
            ("reject", "open") => {
                let conn: [u8; 16] = arr(&c, "conn_id_hex");
                let key: [u8; 32] = arr(&c, "key_s2c_hex");
                sweep(name, &hex_of(&c, "packet_hex"), true, |b| {
                    open_reject(b, &conn, &key).map(|_| ())
                });
            }
            ("accept" | "reject", "peek") => {
                sweep(name, &hex_of(&c, "packet_hex"), false, |b| {
                    peek_reply(b).map(|_| ())
                });
            }
            ("data", "open") => {
                let key: [u8; 32] = arr(&c, "key_hex");
                let nonce: [u8; 16] = arr(&c, "server_nonce_hex");
                let pn = c["pn"].as_u64().unwrap();
                sweep(name, &hex_of(&c, "packet_hex"), false, |b| {
                    open_data(&key, &nonce, b, pn).map(|_| ())
                });
            }
            ("disconnect", "open") => {
                let key: [u8; 32] = arr(&c, "key_hex");
                let nonce: [u8; 16] = arr(&c, "server_nonce_hex");
                let pn = c["pn"].as_u64().unwrap();
                sweep(name, &hex_of(&c, "packet_hex"), true, |b| {
                    open_disconnect(&key, &nonce, b, pn).map(|_| ())
                });
            }
            ("data", "parse_header") => {
                // A header is a prefix of the packet, so longer inputs are legitimately valid;
                // only the no-panic property holds for every length.
                sweep_no_panic(&hex_of(&c, "packet_hex"), |b| parse_header(b).map(|_| ()));
            }
            // Builders and pn/replay logic take no wire bytes as input.
            _ => {}
        }
    }
}

#[test]
fn every_prefix_is_rejected_frames() {
    // A prefix cut on a frame boundary is itself a valid frame sequence: only no-panic holds.
    for c in valid_cases("frames.json") {
        sweep_no_panic(&hex_of(&c, "plaintext_hex"), |b| {
            decode_frames(b).map(|_| ())
        });
    }
}

#[test]
fn every_prefix_is_rejected_wt_framing() {
    for c in valid_cases("wt_framing.json") {
        let name = c["name"].as_str().unwrap();
        match c["kind"].as_str().unwrap() {
            "stream" => {
                // Prefixes decode to fewer messages or NeedMore: only no-panic holds.
                let stream = hex::decode(c["stream_hex"].as_str().unwrap()).unwrap();
                sweep_no_panic(&stream, |b| {
                    decode_message_header(b).map(|h| {
                        if let MessageHeader::Ready { len, header_len } = h {
                            let _ = b.get(header_len..header_len.saturating_add(len));
                        }
                    })
                });
            }
            "path" => {
                let path = c["path"].as_str().unwrap();
                assert!(path.is_ascii(), "{name}");
                // The ticket is opaque at this layer and variable-length, so a prefix may decode to
                // a shorter ticket; it must then be a byte prefix of the original and still pass
                // the minimum-length check, otherwise it must be rejected.
                let full = hex::decode(c["expect"]["ticket_hex"].as_str().unwrap()).unwrap();
                for k in 0..path.len() {
                    if let Ok(t) = parse_wt_path(&path[..k]) {
                        assert!(
                            full.starts_with(&t),
                            "{name}: prefix of {k} chars altered the ticket"
                        );
                        assert!(
                            t.len() >= 75 && t.len() < full.len(),
                            "{name}: prefix of {k} chars"
                        );
                    }
                }
                assert!(
                    parse_wt_path(&path[..path.len().min(WT_PATH_PREFIX.len())]).is_err(),
                    "{name}"
                );
            }
            other => panic!("{name}: unknown kind {other}"),
        }
    }
}
