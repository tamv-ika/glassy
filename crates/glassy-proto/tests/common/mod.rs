//! Shared helpers for integration tests.
#![allow(dead_code)]

use std::fs;
use std::path::PathBuf;

/// `<repo root>/vectors`, resolved from the crate manifest directory.
pub fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../vectors")
}

/// Reads a `tests/fixtures/*.hex` file: one `label: hex` per line; blank lines
/// and lines starting with `#` are ignored.
pub fn read_fixture(name: &str) -> Vec<(String, Vec<u8>)> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (label, hex_str) = l
                .split_once(':')
                .unwrap_or_else(|| panic!("bad fixture line: {l}"));
            let bytes =
                hex::decode(hex_str.trim()).unwrap_or_else(|e| panic!("bad hex in {l}: {e}"));
            (label.trim().to_string(), bytes)
        })
        .collect()
}

/// Writes `<vectors_dir>/<name>` as pretty JSON with a trailing newline.
pub fn write_vectors(name: &str, value: &serde_json::Value) {
    let dir = vectors_dir();
    fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("create {dir:?}: {e}"));
    let mut text = serde_json::to_string_pretty(value).unwrap_or_else(|e| panic!("json: {e}"));
    text.push('\n');
    fs::write(dir.join(name), text).unwrap_or_else(|e| panic!("write {name}: {e}"));
}

/// Reads `<vectors_dir>/<name>` as JSON.
pub fn read_vectors(name: &str) -> serde_json::Value {
    let path = vectors_dir().join(name);
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {path:?}: {e}"))
}
