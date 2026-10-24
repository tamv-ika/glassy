//! Decode CLI for the Rust/C++ differential runner (spec §7, `scripts/differential.sh`).
//!
//! `glassy-proto-cli <kind>` reads one hex-encoded input per stdin line and prints one canonical
//! JSON line per input, in order: `{"err":"<code>"}` or `{"ok":<object>}`, no whitespace, keys
//! in a fixed order, bytes as lowercase hex. `cpp/glassy-proto/tools/proto_cli.cc` must print
//! exactly the same lines.
//!
//! `glassy-proto-cli seed <vectors_dir> <out_dir>` writes every input found in the vector files,
//! valid and invalid, as one raw file per input under `<out_dir>/<kind>/`.

use std::fs;
use std::io::{BufRead, BufWriter, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use glassy_proto::{
    Error, Frame, MessageHeader, ServerKeyRing, ServerTicket, decode_connect_info, decode_frames,
    decode_message_header, open_server, parse_connect, parse_wt_path, retry_token_odcid, transport,
};
use serde_json::Value;

/// Fixed server-ticket context, the same values the vectors use (constraints: `K_gs`).
const K_GS: [u8; 32] = [0x22; 32];
const K_GS_ID: u8 = 1;
const NOW: u32 = 1_900_000_000;
const SELF_SERVER_ID: [u8; 16] = [0xab; 16];

type Decoded = Result<String, Error>;

fn decoder(kind: &str) -> Option<fn(&[u8]) -> Decoded> {
    Some(match kind {
        "frames" => frames,
        "connect" => connect,
        "server_ticket" => server_ticket,
        "retry_token" => retry_token,
        "connect_info" => connect_info,
        "wt_stream" => wt_stream,
        "wt_path" => wt_path,
        _ => return None,
    })
}

fn line(r: Decoded) -> String {
    match r {
        Ok(object) => format!("{{\"ok\":{object}}}"),
        Err(e) => format!("{{\"err\":\"{}\"}}", e.code()),
    }
}

/// Field order follows `vectors/frames.json` (serde_json writes keys sorted).
fn frames(b: &[u8]) -> Decoded {
    let items: Vec<String> = decode_frames(b)?
        .iter()
        .map(|f| match f {
            Frame::Ack(a) => format!(
                "{{\"ack_bits_hex\":\"{:016x}\",\"ack_delay\":{},\"largest_pn_low\":{},\"type\":\"ack\"}}",
                a.ack_bits, a.ack_delay, a.largest_pn_low
            ),
            Frame::Stream { offset, data } => format!(
                "{{\"data_hex\":\"{}\",\"offset\":{offset},\"type\":\"stream\"}}",
                hex::encode(data)
            ),
            Frame::Datagram(data) => format!(
                "{{\"data_hex\":\"{}\",\"type\":\"datagram\"}}",
                hex::encode(data)
            ),
        })
        .collect();
    Ok(format!("{{\"frames\":[{}]}}", items.join(",")))
}

/// Gateway view (spec §4.2): structure only, nothing is authenticated.
fn connect(b: &[u8]) -> Decoded {
    let v = parse_connect(b)?;
    Ok(format!(
        "{{\"session_id\":\"{}\",\"conn_id\":\"{}\",\"connect_seq\":{},\"server_ticket_len\":{},\"padding_len\":{}}}",
        hex::encode(v.session_id),
        hex::encode(v.conn_id),
        v.connect_seq,
        v.server_ticket.len(),
        v.padding.len()
    ))
}

/// Opens with `via` = native, then WebRTC, then WebTransport; the first success wins. Every
/// check before the transport one ignores `via`, so a native failure other than
/// `bad_transport` is the answer for all three.
fn open_any_via(b: &[u8]) -> Result<ServerTicket, Error> {
    let ring = ServerKeyRing::new(K_GS_ID, K_GS);
    match open_server(b, &ring, NOW, &SELF_SERVER_ID, transport::NATIVE) {
        Err(Error::BadTransport) => {}
        other => return other,
    }
    [transport::WEBRTC, transport::WEBTRANSPORT]
        .into_iter()
        .find_map(|via| open_server(b, &ring, NOW, &SELF_SERVER_ID, via).ok())
        .ok_or(Error::BadTransport)
}

fn server_ticket(b: &[u8]) -> Decoded {
    let t = open_any_via(b)?;
    // serde_json's string escaping is the canonical form; proto_cli.cc mirrors it.
    let user_id = serde_json::to_string(&t.user_id).map_err(|_| Error::BadUserId)?;
    Ok(format!(
        "{{\"user_id\":{user_id},\"session_id\":\"{}\",\"transport\":{},\"metadata_len\":{}}}",
        hex::encode(t.session_id),
        t.transport,
        t.metadata.len()
    ))
}

/// Game-server parse mode (spec §3.6): no tag or expiry check.
fn retry_token(b: &[u8]) -> Decoded {
    let odcid = retry_token_odcid(b)?;
    Ok(format!("{{\"odcid\":\"{}\"}}", hex::encode(odcid)))
}

/// The Rust decoders take `&str`, the C++ ones raw bytes. Each byte of an invalid UTF-8
/// sequence becomes 0x7F, which (like every byte >= 0x80) is outside the base64url alphabet and
/// the path prefix, and the byte length that both decoders check first is unchanged.
fn text(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len());
    for chunk in b.utf8_chunks() {
        s.push_str(chunk.valid());
        s.extend(chunk.invalid().iter().map(|_| '\x7f'));
    }
    s
}

fn connect_info(b: &[u8]) -> Decoded {
    let ci = decode_connect_info(&text(b))?;
    Ok(format!(
        "{{\"session_id\":\"{}\",\"expiry\":{},\"native\":{},\"webrtc\":{},\"webtransport\":{}}}",
        hex::encode(ci.session_id),
        ci.expiry,
        ci.native.is_some(),
        ci.webrtc.is_some(),
        ci.webtransport.is_some()
    ))
}

/// Same split loop as the `wt_framing.json` generator: stop on an incomplete header or body,
/// and any header error fails the whole input.
fn wt_stream(b: &[u8]) -> Decoded {
    let mut rest = b;
    let mut messages = Vec::new();
    while let MessageHeader::Ready { len, header_len } = decode_message_header(rest)? {
        let Some(payload) = rest.get(header_len..header_len + len) else {
            break;
        };
        messages.push(format!("\"{}\"", hex::encode(payload)));
        rest = &rest[header_len + len..];
    }
    Ok(format!(
        "{{\"messages\":[{}],\"remainder\":\"{}\"}}",
        messages.join(","),
        hex::encode(rest)
    ))
}

fn wt_path(b: &[u8]) -> Decoded {
    let ticket = parse_wt_path(&text(b))?;
    Ok(format!("{{\"ticket\":\"{}\"}}", hex::encode(ticket)))
}

fn run(kind: &str) -> Result<()> {
    let Some(decode) = decoder(kind) else {
        bail!("unknown kind {kind:?}");
    };
    let mut out = BufWriter::new(std::io::stdout().lock());
    for (i, l) in std::io::stdin().lock().lines().enumerate() {
        let l = l.context("read stdin")?;
        let input =
            hex::decode(l.trim_end()).with_context(|| format!("line {}: bad hex", i + 1))?;
        writeln!(out, "{}", line(decode(&input)))?;
    }
    out.flush()?;
    Ok(())
}

/// One seed: raw input bytes for `kind`, named `<vector file>-<case>-<field>`.
struct Seed {
    kind: &'static str,
    name: String,
    bytes: Vec<u8>,
}

/// How a vector field becomes a seed.
enum Field {
    /// `_hex` bytes.
    Hex,
    /// A string taken as its UTF-8 bytes.
    Text,
    /// A JSON document, base64url-encoded as `ConnectInfo` travels.
    JsonB64,
}

/// (vector file, field, seed kind). Fields are looked up in each case and in its `expect`.
/// `routing_ticket` seeds only feed the Rust fuzz target; the differential has no such kind.
const SEED_FIELDS: &[(&str, &str, &str, Field)] = &[
    ("frames.json", "plaintext_hex", "frames", Field::Hex),
    ("native_packets.json", "frames_hex", "frames", Field::Hex),
    ("native_packets.json", "packet_hex", "connect", Field::Hex),
    ("native_packets.json", "bytes_hex", "connect", Field::Hex),
    (
        "native_packets.json",
        "server_ticket_hex",
        "server_ticket",
        Field::Hex,
    ),
    (
        "native_packets.json",
        "routing_ticket_hex",
        "routing_ticket",
        Field::Hex,
    ),
    (
        "server_ticket.json",
        "ticket_hex",
        "server_ticket",
        Field::Hex,
    ),
    (
        "routing_ticket.json",
        "ticket_hex",
        "routing_ticket",
        Field::Hex,
    ),
    ("routing_ticket.json", "sni", "routing_ticket", Field::Text),
    (
        "routing_ticket.json",
        "ufrag",
        "routing_ticket",
        Field::Text,
    ),
    ("retry_token.json", "token_hex", "retry_token", Field::Hex),
    ("connect_info.json", "json", "connect_info", Field::JsonB64),
    ("connect_info.json", "input", "connect_info", Field::Text),
    ("wt_framing.json", "stream_hex", "wt_stream", Field::Hex),
    ("wt_framing.json", "path", "wt_path", Field::Text),
];

fn vector_seeds(vectors: &Path) -> Result<Vec<Seed>> {
    let mut seeds = Vec::new();
    for (file, key, kind, how) in SEED_FIELDS {
        let path = vectors.join(file);
        let text = fs::read_to_string(&path).with_context(|| format!("read {path:?}"))?;
        let doc: Value = serde_json::from_str(&text).with_context(|| format!("parse {path:?}"))?;
        let cases = doc["cases"]
            .as_array()
            .with_context(|| format!("{file}: no cases"))?;
        let stem = file.trim_end_matches(".json");
        for case in cases {
            let case_name = case["name"]
                .as_str()
                .with_context(|| format!("{file}: case without name"))?;
            for (prefix, holder) in [("", case), ("expect_", &case["expect"])] {
                let Some(value) = holder.get(key).and_then(Value::as_str) else {
                    continue;
                };
                let bytes = match how {
                    Field::Hex => hex::decode(value)
                        .with_context(|| format!("{file}/{case_name}: bad {key}"))?,
                    Field::Text => value.as_bytes().to_vec(),
                    Field::JsonB64 => URL_SAFE_NO_PAD.encode(value).into_bytes(),
                };
                let field = key.trim_end_matches("_hex");
                seeds.push(Seed {
                    kind,
                    name: format!("{stem}-{case_name}-{prefix}{field}"),
                    bytes,
                });
            }
        }
    }
    Ok(seeds)
}

fn write_seeds(vectors: &Path, out: &Path) -> Result<()> {
    let seeds = vector_seeds(vectors)?;
    let mut kinds: Vec<&str> = seeds.iter().map(|s| s.kind).collect();
    kinds.sort_unstable();
    kinds.dedup();
    // Start from empty directories so seeds of renamed or removed cases disappear.
    for kind in &kinds {
        let dir = out.join(kind);
        if dir.exists() {
            fs::remove_dir_all(&dir).with_context(|| format!("remove {dir:?}"))?;
        }
        fs::create_dir_all(&dir).with_context(|| format!("create {dir:?}"))?;
    }
    for s in &seeds {
        let path = out.join(s.kind).join(&s.name);
        fs::write(&path, &s.bytes).with_context(|| format!("write {path:?}"))?;
    }
    eprintln!("wrote {} seeds to {out:?}", seeds.len());
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [cmd, vectors, out] if cmd == "seed" => write_seeds(Path::new(vectors), Path::new(out)),
        [kind] => run(kind),
        _ => bail!(
            "usage: glassy-proto-cli <kind> < hex-lines\n       glassy-proto-cli seed <vectors_dir> <out_dir>"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashSet;
    use std::path::PathBuf;

    fn vectors_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors")
    }

    fn cases(file: &str) -> Vec<Value> {
        let text = fs::read_to_string(vectors_dir().join(file)).unwrap();
        let doc: Value = serde_json::from_str(&text).unwrap();
        doc["cases"].as_array().unwrap().clone()
    }

    fn unhex(v: &Value) -> Vec<u8> {
        hex::decode(v.as_str().unwrap()).unwrap()
    }

    /// Runs `kind` on `input` and parses the printed line back.
    fn run_kind(kind: &str, input: &[u8]) -> Value {
        let out = line(decoder(kind).unwrap()(input));
        serde_json::from_str(&out).unwrap_or_else(|e| panic!("{out}: {e}"))
    }

    fn expected(c: &Value, ok: impl FnOnce(&Value) -> Value) -> Value {
        match c.get("error") {
            Some(code) => json!({ "err": code }),
            None => json!({ "ok": ok(&c["expect"]) }),
        }
    }

    fn hex_len(v: &Value) -> usize {
        v.as_str().unwrap().len() / 2
    }

    #[test]
    fn frames_match_vectors() {
        for c in cases("frames.json") {
            let got = run_kind("frames", &unhex(&c["plaintext_hex"]));
            assert_eq!(got, expected(&c, Value::clone), "{}", c["name"]);
        }
    }

    #[test]
    fn connect_matches_parse_vectors() {
        let parse = cases("native_packets.json")
            .into_iter()
            .filter(|c| c["packet"] == "connect" && c["op"] == "parse");
        for c in parse {
            let got = run_kind("connect", &unhex(&c["packet_hex"]));
            let want = expected(&c, |e| {
                json!({
                    "session_id": e["session_id_hex"],
                    "conn_id": e["conn_id_hex"],
                    "connect_seq": e["connect_seq"],
                    "server_ticket_len": hex_len(&e["server_ticket_hex"]),
                    "padding_len": e["padding_len"],
                })
            });
            assert_eq!(got, want, "{}", c["name"]);
        }
    }

    #[test]
    fn server_ticket_matches_vectors_opened_at_the_cli_context() {
        let comparable = cases("server_ticket.json").into_iter().filter(|c| {
            // The CLI picks `via` itself, so a case about the via check says nothing about it.
            c["now"] == NOW
                && c["self_server_id_hex"] == hex::encode(SELF_SERVER_ID)
                && c["error"] != "bad_transport"
        });
        let mut n = 0;
        for c in comparable {
            let got = run_kind("server_ticket", &unhex(&c["ticket_hex"]));
            let want = expected(&c, |e| {
                json!({
                    "user_id": e["user_id"],
                    "session_id": e["session_id_hex"],
                    "transport": e["transport"],
                    "metadata_len": hex_len(&e["metadata_hex"]),
                })
            });
            assert_eq!(got, want, "{}", c["name"]);
            n += 1;
        }
        assert!(n >= 10, "only {n} comparable cases");
    }

    #[test]
    fn server_ticket_via_mismatch_case_opens_on_its_own_transport() {
        let c = cases("server_ticket.json")
            .into_iter()
            .find(|c| c["name"] == "via_mismatch")
            .unwrap();
        let got = run_kind("server_ticket", &unhex(&c["ticket_hex"]));
        assert!(got.get("ok").is_some(), "{got}");
    }

    #[test]
    fn server_ticket_bad_transport_byte_reports_bad_transport() {
        let c = cases("server_ticket.json")
            .into_iter()
            .find(|c| c["name"] == "transport_three")
            .unwrap();
        let got = run_kind("server_ticket", &unhex(&c["ticket_hex"]));
        assert_eq!(got, json!({"err": "bad_transport"}));
    }

    #[test]
    fn retry_token_matches_structural_vectors() {
        for c in cases("retry_token.json") {
            // Tag and expiry failures only exist in validate mode; the CLI is parse mode.
            if matches!(c["error"].as_str(), Some("expired" | "auth_failed")) {
                continue;
            }
            let got = run_kind("retry_token", &unhex(&c["token_hex"]));
            let want = expected(&c, |e| json!({ "odcid": e["odcid_hex"] }));
            assert_eq!(got, want, "{}", c["name"]);
        }
    }

    #[test]
    fn connect_info_matches_vectors() {
        for c in cases("connect_info.json") {
            let input = match (c.get("json"), c.get("input")) {
                (Some(j), None) => URL_SAFE_NO_PAD.encode(j.as_str().unwrap()),
                (None, Some(i)) => i.as_str().unwrap().to_string(),
                _ => panic!("{}: need json or input", c["name"]),
            };
            let got = run_kind("connect_info", input.as_bytes());
            let want = expected(&c, |e| {
                json!({
                    "session_id": e["session_id"],
                    "expiry": e["expiry"],
                    "native": e.get("native").is_some(),
                    "webrtc": e.get("webrtc").is_some(),
                    "webtransport": e.get("webtransport").is_some(),
                })
            });
            assert_eq!(got, want, "{}", c["name"]);
        }
    }

    #[test]
    fn wt_matches_vectors() {
        for c in cases("wt_framing.json") {
            let got = match c["kind"].as_str().unwrap() {
                "stream" => run_kind("wt_stream", &unhex(&c["stream_hex"])),
                _ => run_kind("wt_path", c["path"].as_str().unwrap().as_bytes()),
            };
            let want = expected(&c, |e| match e.get("ticket_hex") {
                Some(t) => json!({ "ticket": t }),
                None => json!({ "messages": e["messages_hex"], "remainder": e["remainder_hex"] }),
            });
            assert_eq!(got, want, "{}", c["name"]);
        }
    }

    #[test]
    fn lines_are_compact_with_fixed_key_order() {
        let ack = hex::decode("0101020304ffff00").unwrap();
        assert_eq!(
            line(frames(&ack)),
            r#"{"ok":{"frames":[{"ack_bits_hex":"ffffffffffffffff","ack_delay":65535,"largest_pn_low":16909060,"type":"ack"}]}}"#
        );
        assert_eq!(
            line(wt_stream(&hex::decode("03616263026465").unwrap())),
            r#"{"ok":{"messages":["616263","6465"],"remainder":""}}"#
        );
        assert_eq!(
            line(wt_stream(&[0x80, 0x04, 0x00, 0x01])),
            r#"{"err":"too_large"}"#
        );
        let packet = cases("native_packets.json")
            .into_iter()
            .find(|c| c["packet"] == "connect" && c["op"] == "parse" && c.get("error").is_none())
            .unwrap();
        let got = line(connect(&unhex(&packet["packet_hex"])));
        assert!(
            got.starts_with(r#"{"ok":{"session_id":"0102030405060708","conn_id":"666"#),
            "{got}"
        );
        assert!(
            got.contains(r#","connect_seq":1700000000000,"server_ticket_len":"#),
            "{got}"
        );
    }

    #[test]
    fn user_id_escaping_matches_serde_json() {
        assert_eq!(
            serde_json::to_string("a\"\\\u{1}\u{1f}\n\t\u{7f}é").unwrap(),
            "\"a\\\"\\\\\\u0001\\u001f\\n\\t\u{7f}é\""
        );
    }

    #[test]
    fn invalid_utf8_keeps_length_and_is_never_base64() {
        assert_eq!(text(b"ab\xffc\xe2\x82"), "ab\x7fc\x7f\x7f");
        assert_eq!(
            run_kind("wt_path", b"/glassy?t=\xff"),
            json!({"err": "bad_encoding"})
        );
        let long = [b'/'; 537]
            .iter()
            .chain(b"\xff")
            .copied()
            .collect::<Vec<u8>>();
        assert_eq!(run_kind("wt_path", &long), json!({"err": "too_large"}));
    }

    #[test]
    fn seeds_cover_every_kind_with_unique_names() {
        let seeds = vector_seeds(&vectors_dir()).unwrap();
        let mut names = HashSet::new();
        for s in &seeds {
            assert!(
                names.insert((s.kind, s.name.as_str())),
                "duplicate {}",
                s.name
            );
        }
        for kind in [
            "frames",
            "connect",
            "server_ticket",
            "retry_token",
            "connect_info",
            "wt_stream",
            "wt_path",
            "routing_ticket",
        ] {
            assert!(seeds.iter().any(|s| s.kind == kind), "no seeds for {kind}");
        }
    }
}
