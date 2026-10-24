//! `ConnectInfo` codec (spec §3.5): the broker encodes, clients decode.
//!
//! Wire form: `base64url_nopad(compact JSON)`. The C++ decoder mirrors the decode rules below
//! exactly, so each one is deterministic and needs no allocation or generic JSON model:
//!
//! 1. base64url text longer than [`MAX_B64_LEN`] -> `TooLarge`; bad base64url (padding, wrong
//!    alphabet, non-zero trailing bits) -> `BadEncoding`; decoded JSON over
//!    [`MAX_CONNECT_INFO_JSON`] -> `TooLarge`.
//! 2. Nesting depth of `{`/`[` above [`MAX_DEPTH`] -> `BadJson` (separate byte scan).
//! 3. The whole document must be valid UTF-8 and one valid JSON object with nothing after it
//!    except whitespace, else `BadJson`.
//! 4. Top-level `v` is checked before anything else: missing or not an integer token
//!    (`-?(0|[1-9][0-9]*)`) -> `BadJson`; an integer other than 1 -> `BadVersion`.
//! 5. Known fields: a duplicated known name, a wrong value type or an escape (`\`) inside a
//!    known string value -> `BadJson`. A key containing an escape never matches a known name
//!    (it is an unknown key). Unknown keys and values are ignored at every level, duplicates
//!    of unknown keys included. `expiry` is a JSON integer token in `0..=u32::MAX`.
//! 6. Presence: `session_id` and `expiry` are required, at least one transport block must be
//!    present and every block must have all its fields (`null` is a wrong type) -> `BadJson`.
//! 7. Values are then validated in document order (`session_id`, `native`, `webrtc`,
//!    `webtransport`; fields in the order of the structs below); see each `check_*` helper.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::de::{Deserialize, Deserializer, Error as _, IgnoredAny, MapAccess, Visitor};
use serde::{Serialize, Serializer};
use serde_json::value::RawValue;

use crate::Error;
use crate::MAX_CONNECT_INFO_JSON;
use crate::routing_ticket::ROUTING_TICKET_LEN;
use crate::server_ticket::{
    SERVER_TICKET_BROWSER_MAX, SERVER_TICKET_MIN, SERVER_TICKET_NATIVE_MIN,
};

/// `ceil(4096 * 4 / 3)`: the longest base64url text that can hold [`MAX_CONNECT_INFO_JSON`].
const MAX_B64_LEN: usize = 5462;
const MAX_DEPTH: usize = 8;
const MAX_ADDRS: usize = 4;
const MAX_ADDR_LEN: usize = 64;
const NATIVE_TICKET_MAX: usize = 458;
const UFRAG_LEN: usize = 80;
const PWD_LEN: usize = 43;
const FINGERPRINT_MAX: usize = 128;
const URL_MAX: usize = 1024;
const URL_PREFIX: &str = "https://";

#[derive(Clone, Debug, PartialEq, Eq)]
/// Native UDP endpoint data inside connect-info (spec §3.5).
pub struct NativeInfo {
    /// Gateway `host:port` addresses the client may send `CONNECT` to.
    pub gateways: Vec<String>,
    /// Sealed routing ticket (spec §3.1), sent in every `CONNECT`.
    pub routing_ticket: [u8; 60],
    /// Sealed server ticket (spec §3.2), opaque to the client.
    pub server_ticket: Vec<u8>,
    /// Client-to-server packet key (spec §0.3).
    pub key_c2s: [u8; 32],
    /// Server-to-client packet key (spec §0.3).
    pub key_s2c: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// WebRTC endpoint data inside connect-info (spec §3.5).
pub struct WebRtcInfo {
    /// ICE candidate lines for the game server.
    pub candidates: Vec<String>,
    /// ICE username fragment; carries the routing ticket (spec §3.1).
    pub ice_ufrag: String,
    /// ICE password derived from the server key and `ice_ufrag`.
    pub ice_pwd: String,
    /// DTLS certificate fingerprint of the game server.
    pub dtls_fingerprint: String,
    /// Sealed server ticket (spec §3.2), opaque to the client.
    pub server_ticket: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// WebTransport endpoint data inside connect-info (spec §3.5).
pub struct WtInfo {
    /// `https://` URL of the WebTransport endpoint.
    pub url: String,
    /// SHA-256 of the server certificate, for certificate pinning.
    pub cert_sha256: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Connect-info document the backend hands to the client (spec §3.5).
pub struct ConnectInfo {
    /// Session this connect-info belongs to.
    pub session_id: [u8; 8],
    /// Unix seconds after which the tickets inside are no longer valid.
    pub expiry: u32,
    /// Native transport data, if offered.
    pub native: Option<NativeInfo>,
    /// WebRTC transport data, if offered.
    pub webrtc: Option<WebRtcInfo>,
    /// WebTransport data, if offered.
    pub webtransport: Option<WtInfo>,
}

// ------------------------------------------------------------------ encode

#[derive(Serialize)]
struct WireNative<'a> {
    gateways: &'a [String],
    routing_ticket: String,
    server_ticket: String,
    key_c2s: String,
    key_s2c: String,
}

#[derive(Serialize)]
struct WireWebRtc<'a> {
    candidates: &'a [String],
    ice_ufrag: &'a str,
    ice_pwd: &'a str,
    dtls_fingerprint: &'a str,
    server_ticket: String,
}

#[derive(Serialize)]
struct WireWt<'a> {
    url: &'a str,
    cert_sha256: String,
}

/// Field order here is the wire order (spec §3.5); `v` always comes first.
#[derive(Serialize)]
struct WireInfo<'a> {
    v: u8,
    #[serde(serialize_with = "hex_lower")]
    session_id: &'a [u8; 8],
    expiry: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    native: Option<WireNative<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    webrtc: Option<WireWebRtc<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    webtransport: Option<WireWt<'a>>,
}

fn hex_lower<S: Serializer>(b: &&[u8; 8], s: S) -> Result<S::Ok, S::Error> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 16];
    for (i, byte) in b.iter().enumerate() {
        out[2 * i] = DIGITS[usize::from(byte >> 4)];
        out[2 * i + 1] = DIGITS[usize::from(byte & 15)];
    }
    // Only ASCII digits were written above.
    s.serialize_str(std::str::from_utf8(&out).map_err(serde::ser::Error::custom)?)
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Serializes `ci` and returns base64url of the compact JSON.
///
/// The result is run through [`decode_connect_info`] so the encoder can never emit a document
/// the decoder rejects (oversized tickets, empty address lists, escapes in strings, ...).
pub fn encode_connect_info(ci: &ConnectInfo) -> Result<String, Error> {
    let wire = WireInfo {
        v: 1,
        session_id: &ci.session_id,
        expiry: ci.expiry,
        native: ci.native.as_ref().map(|n| WireNative {
            gateways: &n.gateways,
            routing_ticket: b64(&n.routing_ticket),
            server_ticket: b64(&n.server_ticket),
            key_c2s: b64(&n.key_c2s),
            key_s2c: b64(&n.key_s2c),
        }),
        webrtc: ci.webrtc.as_ref().map(|w| WireWebRtc {
            candidates: &w.candidates,
            ice_ufrag: &w.ice_ufrag,
            ice_pwd: &w.ice_pwd,
            dtls_fingerprint: &w.dtls_fingerprint,
            server_ticket: b64(&w.server_ticket),
        }),
        webtransport: ci.webtransport.as_ref().map(|t| WireWt {
            url: &t.url,
            cert_sha256: b64(&t.cert_sha256),
        }),
    };
    let json = serde_json::to_vec(&wire).map_err(|_| Error::BadJson)?;
    if json.len() > MAX_CONNECT_INFO_JSON {
        return Err(Error::TooLarge);
    }
    let s = b64(&json);
    decode_connect_info(&s)?;
    Ok(s)
}

// ------------------------------------------------------------------ decode

/// A map key that only matches known names when it is a plain (escape-free) JSON string.
///
/// serde_json hands out escape-free keys as borrowed slices and unescaped ones as owned copies,
/// so "borrowed" is exactly "contains no backslash".
struct Key<'a>(Option<&'a str>);

impl<'de> Deserialize<'de> for Key<'de> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Key<'de>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a string key")
            }
            fn visit_borrowed_str<E: serde::de::Error>(self, v: &'de str) -> Result<Key<'de>, E> {
                Ok(Key(Some(v)))
            }
            fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Key<'de>, E> {
                Ok(Key(None))
            }
        }
        d.deserialize_str(V)
    }
}

/// Declares a JSON object with known fields. The generated `Deserialize` ignores unknown keys,
/// rejects a repeated known key, and the generated `require` fails with `BadJson` on a missing
/// required field.
macro_rules! object {
    ($raw:ident / $req:ident { $($f:ident : $ty:ty = $key:literal),+ $(,)? }) => {
        #[derive(Default)]
        struct $raw<'a> { $($f: Option<$ty>),+ }
        struct $req<'a> { $($f: $ty),+ }
        impl<'a> $raw<'a> {
            fn require(self) -> Result<$req<'a>, Error> {
                Ok($req { $($f: self.$f.ok_or(Error::BadJson)?),+ })
            }
        }
        impl<'a> Deserialize<'a> for $raw<'a> {
            fn deserialize<D: Deserializer<'a>>(d: D) -> Result<Self, D::Error> {
                struct V;
                impl<'a> Visitor<'a> for V {
                    type Value = $raw<'a>;
                    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        f.write_str("a JSON object")
                    }
                    fn visit_map<M: MapAccess<'a>>(self, mut m: M) -> Result<$raw<'a>, M::Error> {
                        let mut out = $raw::default();
                        while let Some(Key(k)) = m.next_key::<Key<'a>>()? {
                            match k {
                                $(Some($key) => {
                                    if out.$f.is_some() {
                                        return Err(M::Error::duplicate_field($key));
                                    }
                                    out.$f = Some(m.next_value()?);
                                })+
                                _ => {
                                    m.next_value::<IgnoredAny>()?;
                                }
                            }
                        }
                        Ok(out)
                    }
                }
                d.deserialize_map(V)
            }
        }
    };
}

object!(HeadRaw / HeadReq { v: &'a RawValue = "v" });
object!(NativeRaw / NativeReq {
    gateways: Vec<&'a str> = "gateways",
    routing_ticket: &'a str = "routing_ticket",
    server_ticket: &'a str = "server_ticket",
    key_c2s: &'a str = "key_c2s",
    key_s2c: &'a str = "key_s2c",
});
object!(WebRtcRaw / WebRtcReq {
    candidates: Vec<&'a str> = "candidates",
    ice_ufrag: &'a str = "ice_ufrag",
    ice_pwd: &'a str = "ice_pwd",
    dtls_fingerprint: &'a str = "dtls_fingerprint",
    server_ticket: &'a str = "server_ticket",
});
object!(WtRaw / WtReq {
    url: &'a str = "url",
    cert_sha256: &'a str = "cert_sha256",
});

/// Top level: `v` was already checked; transport blocks are optional.
#[derive(Default)]
struct TopRaw<'a> {
    session_id: Option<&'a str>,
    expiry: Option<u32>,
    native: Option<NativeRaw<'a>>,
    webrtc: Option<WebRtcRaw<'a>>,
    webtransport: Option<WtRaw<'a>>,
}

impl<'a> Deserialize<'a> for TopRaw<'a> {
    fn deserialize<D: Deserializer<'a>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'a> Visitor<'a> for V {
            type Value = TopRaw<'a>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<M: MapAccess<'a>>(self, mut m: M) -> Result<TopRaw<'a>, M::Error> {
                let mut out = TopRaw::default();
                macro_rules! slot {
                    ($f:ident, $key:literal) => {{
                        if out.$f.is_some() {
                            return Err(M::Error::duplicate_field($key));
                        }
                        out.$f = Some(m.next_value()?);
                    }};
                }
                while let Some(Key(k)) = m.next_key::<Key<'a>>()? {
                    match k {
                        Some("session_id") => slot!(session_id, "session_id"),
                        Some("expiry") => slot!(expiry, "expiry"),
                        Some("native") => slot!(native, "native"),
                        Some("webrtc") => slot!(webrtc, "webrtc"),
                        Some("webtransport") => slot!(webtransport, "webtransport"),
                        _ => {
                            m.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(out)
            }
        }
        d.deserialize_map(V)
    }
}

/// Rejects nesting deeper than [`MAX_DEPTH`]; string contents (including `\"`) are skipped.
fn check_depth(json: &[u8]) -> Result<(), Error> {
    let (mut depth, mut in_string, mut escaped) = (0usize, false, false);
    for &b in json {
        if in_string {
            match (escaped, b) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > MAX_DEPTH {
                    return Err(Error::BadJson);
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}

/// Parses `json` as one `T` followed only by JSON whitespace.
fn parse_whole<'a, T: Deserialize<'a>>(json: &'a str) -> Result<T, Error> {
    let mut de = serde_json::Deserializer::from_str(json);
    let value = T::deserialize(&mut de).map_err(|_| Error::BadJson)?;
    de.end().map_err(|_| Error::BadJson)?;
    Ok(value)
}

/// `v` must be the integer token `1`; other integers are a version mismatch.
fn check_version(raw: &str) -> Result<(), Error> {
    let digits = raw.strip_prefix('-').unwrap_or(raw);
    let integer = match digits.as_bytes() {
        [b'0'] => true,
        [b'1'..=b'9', rest @ ..] => rest.iter().all(u8::is_ascii_digit),
        _ => false,
    };
    if !integer {
        return Err(Error::BadJson);
    }
    if raw == "1" {
        Ok(())
    } else {
        Err(Error::BadVersion)
    }
}

fn b64_decode(s: &str) -> Result<Vec<u8>, Error> {
    URL_SAFE_NO_PAD.decode(s).map_err(|_| Error::BadEncoding)
}

fn b64_fixed<const N: usize>(s: &str) -> Result<[u8; N], Error> {
    b64_decode(s)?.try_into().map_err(|_| Error::BadLength)
}

fn b64_ticket(s: &str, min: usize, max: usize) -> Result<Vec<u8>, Error> {
    let t = b64_decode(s)?;
    if (min..=max).contains(&t.len()) {
        Ok(t)
    } else {
        Err(Error::BadLength)
    }
}

/// 1..=4 entries (empty -> `BadJson`, more -> `TooLarge`), each 1..=64 bytes (same split).
fn check_addrs(list: &[&str]) -> Result<Vec<String>, Error> {
    if list.is_empty() {
        return Err(Error::BadJson);
    }
    if list.len() > MAX_ADDRS {
        return Err(Error::TooLarge);
    }
    list.iter()
        .map(|a| match a.len() {
            0 => Err(Error::BadJson),
            1..=MAX_ADDR_LEN => Ok((*a).to_string()),
            _ => Err(Error::TooLarge),
        })
        .collect()
}

/// Exactly 16 lowercase hex digits.
fn check_session_id(s: &str) -> Result<[u8; 8], Error> {
    let b = s.as_bytes();
    if b.len() != 16 {
        return Err(Error::BadEncoding);
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(Error::BadEncoding),
    };
    let mut out = [0u8; 8];
    for (o, pair) in out.iter_mut().zip(b.chunks_exact(2)) {
        *o = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(out)
}

/// `len` characters, all in the standard base64 alphabet (no `=`).
fn check_std_b64_chars(s: &str, len: usize) -> Result<(), Error> {
    if s.len() != len {
        return Err(Error::BadLength);
    }
    if s.bytes()
        .all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
    {
        Ok(())
    } else {
        Err(Error::BadEncoding)
    }
}

fn check_native(n: NativeReq<'_>) -> Result<NativeInfo, Error> {
    Ok(NativeInfo {
        gateways: check_addrs(&n.gateways)?,
        routing_ticket: b64_fixed::<ROUTING_TICKET_LEN>(n.routing_ticket)?,
        server_ticket: b64_ticket(n.server_ticket, SERVER_TICKET_NATIVE_MIN, NATIVE_TICKET_MAX)?,
        key_c2s: b64_fixed(n.key_c2s)?,
        key_s2c: b64_fixed(n.key_s2c)?,
    })
}

fn check_webrtc(w: WebRtcReq<'_>) -> Result<WebRtcInfo, Error> {
    let candidates = check_addrs(&w.candidates)?;
    check_std_b64_chars(w.ice_ufrag, UFRAG_LEN)?;
    check_std_b64_chars(w.ice_pwd, PWD_LEN)?;
    let fp = w.dtls_fingerprint;
    if fp.is_empty() || fp.len() > FINGERPRINT_MAX {
        return Err(Error::BadLength);
    }
    if !fp.bytes().all(|c| (0x20..=0x7e).contains(&c)) {
        return Err(Error::BadEncoding);
    }
    Ok(WebRtcInfo {
        candidates,
        ice_ufrag: w.ice_ufrag.to_string(),
        ice_pwd: w.ice_pwd.to_string(),
        dtls_fingerprint: fp.to_string(),
        server_ticket: b64_ticket(
            w.server_ticket,
            SERVER_TICKET_MIN,
            SERVER_TICKET_BROWSER_MAX,
        )?,
    })
}

fn check_wt(t: WtReq<'_>) -> Result<WtInfo, Error> {
    if t.url.is_empty() || t.url.len() > URL_MAX {
        return Err(Error::BadLength);
    }
    if !t.url.starts_with(URL_PREFIX) {
        return Err(Error::BadEncoding);
    }
    Ok(WtInfo {
        url: t.url.to_string(),
        cert_sha256: b64_fixed(t.cert_sha256)?,
    })
}

/// Decodes and validates a base64url `ConnectInfo` string (see the module docs for the rules).
pub fn decode_connect_info(s: &str) -> Result<ConnectInfo, Error> {
    if s.len() > MAX_B64_LEN {
        return Err(Error::TooLarge);
    }
    let bytes = b64_decode(s)?;
    if bytes.len() > MAX_CONNECT_INFO_JSON {
        return Err(Error::TooLarge);
    }
    check_depth(&bytes)?;
    let json = std::str::from_utf8(&bytes).map_err(|_| Error::BadJson)?;

    // Pass 1: syntax of the whole document plus `v`, before any other field is looked at, so a
    // future-version document with a different schema reports `BadVersion`.
    let head: HeadRaw<'_> = parse_whole(json)?;
    check_version(head.require()?.v.get())?;

    // Pass 2: the version-1 schema.
    let top: TopRaw<'_> = parse_whole(json)?;
    let session_id = top.session_id.ok_or(Error::BadJson)?;
    let expiry = top.expiry.ok_or(Error::BadJson)?;
    if top.native.is_none() && top.webrtc.is_none() && top.webtransport.is_none() {
        return Err(Error::BadJson);
    }
    // Presence of every block field is settled before any value is validated.
    let native = top.native.map(NativeRaw::require).transpose()?;
    let webrtc = top.webrtc.map(WebRtcRaw::require).transpose()?;
    let webtransport = top.webtransport.map(WtRaw::require).transpose()?;

    Ok(ConnectInfo {
        session_id: check_session_id(session_id)?,
        expiry,
        native: native.map(check_native).transpose()?,
        webrtc: webrtc.map(check_webrtc).transpose()?,
        webtransport: webtransport.map(check_wt).transpose()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAX_CONNECT_INFO_JSON;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    fn sample() -> ConnectInfo {
        ConnectInfo {
            session_id: [1, 2, 3, 4, 5, 6, 7, 8],
            expiry: 2_000_000_000,
            native: Some(NativeInfo {
                gateways: vec!["203.0.113.10:443".into(), "203.0.113.11:443".into()],
                routing_ticket: [7; 60],
                server_ticket: vec![8; 144],
                key_c2s: [0x44; 32],
                key_s2c: [0x55; 32],
            }),
            webrtc: Some(WebRtcInfo {
                candidates: vec!["203.0.113.10:443".into()],
                ice_ufrag: "A".repeat(80),
                ice_pwd: "B".repeat(43),
                dtls_fingerprint: "sha-256 AB:CD".into(),
                server_ticket: vec![9; 100],
            }),
            webtransport: Some(WtInfo {
                url: "https://x.wt.example.com:443/glassy?t=abc".into(),
                cert_sha256: [0xcd; 32],
            }),
        }
    }

    #[test]
    fn roundtrip_all_blocks() {
        let ci = sample();
        let s = encode_connect_info(&ci).unwrap();
        assert_eq!(decode_connect_info(&s), Ok(ci));
    }

    #[test]
    fn max_size_fits() {
        let mut ci = sample();
        let long = "g".repeat(64);
        let n = ci.native.as_mut().unwrap();
        n.gateways = vec![long.clone(); 4];
        n.server_ticket = vec![1; 458];
        let w = ci.webrtc.as_mut().unwrap();
        w.candidates = vec![long; 4];
        w.server_ticket = vec![2; 394];
        w.dtls_fingerprint = "F".repeat(128);
        ci.webtransport.as_mut().unwrap().url = format!("https://{}", "u".repeat(1016));
        let s = encode_connect_info(&ci).unwrap();
        let json = URL_SAFE_NO_PAD.decode(&s).unwrap();
        assert!(
            json.len() <= MAX_CONNECT_INFO_JSON,
            "json is {}",
            json.len()
        );
        assert_eq!(decode_connect_info(&s), Ok(ci));
    }
}
