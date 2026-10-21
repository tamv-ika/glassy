//! Parses real Chromium Initial datagrams captured by `gw-proto capture` (spike S1).
//!
//! Regenerate the fixtures with `npx playwright test s1` in `spikes/web`; the ticket inside was
//! minted with the fixed spike key, so the test can open it.

use gw_proto::quic::client_hello::{HelloParse, parse_sni};
use gw_proto::quic::crypto_frames::CryptoAssembler;
use gw_proto::quic::initial::{client_initial_keys, decrypt_initial, parse_initial_header};
use gw_proto::quic::read_varint;
use gw_proto::ticket::{KeyRing, from_sni, open};

const SERVER_A2: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xa2];

fn captured() -> Vec<Vec<u8>> {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/chromium");
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort_by_key(|p| {
        p.file_stem()
            .unwrap()
            .to_string_lossy()
            .parse::<u32>()
            .unwrap()
    });
    files.iter().map(|p| std::fs::read(p).unwrap()).collect()
}

/// Describes the frames of a decrypted payload, e.g. "CRYPTO@0+1162 PADDING PING".
fn describe_frames(payload: &[u8]) -> String {
    let mut out = Vec::new();
    let mut at = 0;
    while at < payload.len() {
        let t = payload[at];
        at += 1;
        match t {
            0x00 => {
                while at < payload.len() && payload[at] == 0 {
                    at += 1;
                }
                out.push("PADDING".to_string());
            }
            0x01 => out.push("PING".to_string()),
            0x06 => {
                let (off, n) = read_varint(&payload[at..]).unwrap();
                at += n;
                let (len, n) = read_varint(&payload[at..]).unwrap();
                at += n + usize::try_from(len).unwrap();
                out.push(format!("CRYPTO@{off}+{len}"));
            }
            other => {
                out.push(format!("frame 0x{other:02x}"));
                break;
            }
        }
    }
    out.join(" ")
}

/// Prints how long the whole ClientHello is and how many datagrams carry it (findings only).
fn report_full_hello(datagrams: &[Vec<u8>], dcid: &[u8]) {
    let mut assembler = CryptoAssembler::new(16 * 1024);
    for (i, d) in datagrams.iter().enumerate() {
        let h = parse_initial_header(d).unwrap();
        if h.dcid != dcid {
            continue;
        }
        assembler
            .ingest_payload(
                &decrypt_initial(d, &client_initial_keys(h.dcid))
                    .unwrap()
                    .payload,
            )
            .unwrap();
        let hs = assembler.contiguous();
        if hs.len() >= 4 {
            let total =
                4 + (usize::from(hs[1]) << 16 | usize::from(hs[2]) << 8 | usize::from(hs[3]));
            if hs.len() >= total {
                println!(
                    "client_hello_total_len = {total}, datagrams_for_full_hello = {}",
                    i + 1
                );
                return;
            }
        }
    }
    println!("full ClientHello not present in the capture");
}

#[test]
fn chromium_fixture_sni() {
    let datagrams = captured();
    assert!(!datagrams.is_empty(), "run the S1 capture test first");
    let dcid = parse_initial_header(&datagrams[0]).unwrap().dcid.to_vec();
    let mut assembler = CryptoAssembler::new(16 * 1024);
    let mut found = None;
    for (i, d) in datagrams.iter().enumerate() {
        let h = parse_initial_header(d).unwrap();
        if h.dcid != dcid.as_slice() {
            continue; // a later connection attempt
        }
        let p = decrypt_initial(d, &client_initial_keys(h.dcid)).unwrap();
        println!(
            "datagram {i}: {} bytes, pn {}, {}",
            d.len(),
            p.packet_number,
            describe_frames(&p.payload)
        );
        assembler.ingest_payload(&p.payload).unwrap();
        if let Ok(HelloParse::Sni(host)) = parse_sni(assembler.contiguous()) {
            found = Some((i + 1, host));
            break;
        }
    }
    let (needed, host) = found.expect("SNI never became readable");
    println!("client_hello_datagrams = {needed}");
    report_full_hello(&datagrams, &dcid);
    assert!(host.ends_with(".wt.test"), "unexpected SNI {host}");
    // now = 0: the committed fixture outlives the ticket's one-hour expiry.
    let ticket = open(
        &from_sni(&host, "wt.test").unwrap(),
        &KeyRing::new(1, [0x11; 16]),
        0,
    )
    .unwrap();
    assert_eq!(ticket.server_id, SERVER_A2);
}
