// ConnectInfo decoder (spec §3.5). The behavioural reference is
// crates/glassy-proto/src/connect_info.rs, which decodes in two serde_json passes: pass 1 checks
// the grammar of the whole document plus top-level `v`, pass 2 reads the version-1 schema.
// Here a single tokenizer pass does both: grammar and pass-1 failures return at once, while
// pass-2 (schema) failures are only recorded, so that a future version still reports
// kBadVersion whatever its schema looks like.
#include "glassy/proto/connect_info.h"

#include <algorithm>

#include "base64.h"
#include "glassy/proto/consts.h"
#include "glassy/proto/utf8.h"
#include "json_reader.h"

namespace glassy::proto {
namespace {

// ceil(4096 * 4 / 3): the longest base64url text that can hold kMaxConnectInfoJson bytes.
constexpr size_t kMaxB64Len = 5462;
constexpr size_t kNativeTicketMin = 139;  // spec §3.2: a native ticket also carries the keys
constexpr size_t kBrowserTicketMin = 75;  // spec §3.2
constexpr size_t kUfragLen = 80;
constexpr size_t kPwdLen = 43;
constexpr size_t kFingerprintMax = 128;
constexpr size_t kUrlMax = 1024;
constexpr std::string_view kUrlPrefix = "https://";

// Unvalidated views into the decoded JSON (escape-free string values only).
struct AddrList {
  std::array<std::string_view, kConnectInfoMaxAddrs> items{};
  size_t count = 0;  // may exceed items.size(); only the first entries are kept
};

struct NativeRaw {
  uint8_t seen = 0;  // bit i set once names[i] has been read
  AddrList gateways;
  std::string_view routing_ticket, server_ticket, key_c2s, key_s2c;
};
constexpr std::array<std::string_view, 5> kNativeNames = {"gateways", "routing_ticket",
                                                          "server_ticket", "key_c2s", "key_s2c"};

struct WebRtcRaw {
  uint8_t seen = 0;
  AddrList candidates;
  std::string_view ice_ufrag, ice_pwd, dtls_fingerprint, server_ticket;
};
constexpr std::array<std::string_view, 5> kWebRtcNames = {"candidates", "ice_ufrag", "ice_pwd",
                                                          "dtls_fingerprint", "server_ticket"};

struct WtRaw {
  uint8_t seen = 0;
  std::string_view url, cert_sha256;
};
constexpr std::array<std::string_view, 2> kWtNames = {"url", "cert_sha256"};

enum TopField : uint8_t { kV, kSessionId, kExpiry, kNative, kWebRtc, kWebTransport };
constexpr std::array<std::string_view, 6> kTopNames = {"v",      "session_id", "expiry",
                                                       "native", "webrtc",     "webtransport"};

template <size_t N>
int find_name(const std::array<std::string_view, N>& names, std::string_view key) {
  for (size_t i = 0; i < N; ++i) {
    if (names[i] == key) return static_cast<int>(i);
  }
  return -1;
}

template <size_t N>
constexpr uint8_t all_bits(const std::array<std::string_view, N>&) {
  return static_cast<uint8_t>((1u << N) - 1);
}

// Same byte scan as the Rust check_depth: brackets inside strings (including `\"`) do not count.
bool depth_ok(std::string_view json) {
  size_t depth = 0;
  bool in_string = false;
  bool escaped = false;
  for (const char b : json) {
    if (in_string) {
      if (escaped) {
        escaped = false;
      } else if (b == '\\') {
        escaped = true;
      } else if (b == '"') {
        in_string = false;
      }
      continue;
    }
    if (b == '"') {
      in_string = true;
    } else if (b == '{' || b == '[') {
      if (++depth > JsonReader::kMaxDepth) return false;
    } else if ((b == '}' || b == ']') && depth > 0) {
      --depth;
    }
  }
  return true;
}

// The parse helpers return false only on a grammar error; a wrong type or an escape in a known
// value sets `schema_error` (pass 2 of the Rust reference) and the value is skipped.
bool read_string(JsonReader& r, std::string_view& out, bool& schema_error) {
  const JsonToken t = r.next();
  if (t == JsonToken::kString && !r.escaped()) {
    out = r.text();
    return true;
  }
  schema_error = true;
  return r.skip_value(t);
}

bool read_addrs(JsonReader& r, AddrList& out, bool& schema_error) {
  JsonToken t = r.next();
  if (t != JsonToken::kArrayBegin) {
    schema_error = true;
    return r.skip_value(t);
  }
  for (;;) {
    t = r.next();
    if (t == JsonToken::kArrayEnd) return true;
    if (t == JsonToken::kString && !r.escaped()) {
      if (out.count < out.items.size()) out.items[out.count] = r.text();
      ++out.count;
      continue;
    }
    schema_error = true;
    if (!r.skip_value(t)) return false;
  }
}

// `expiry` is an integer token in 0..=u32::MAX; serde_json rejects `-0`, fractions and
// exponents for a u32.
bool parse_u32(std::string_view s, uint32_t& out) {
  if (s.empty() || s.size() > 10) return false;
  uint64_t v = 0;
  for (const char c : s) {
    if (c < '0' || c > '9') return false;
    v = v * 10 + static_cast<uint64_t>(c - '0');
  }
  if (v > UINT32_MAX) return false;
  out = static_cast<uint32_t>(v);
  return true;
}

// Reads one known object. Duplicated known names are tracked with the `seen` bitmask.
template <size_t N, class OnField>
bool read_block(JsonReader& r, const std::array<std::string_view, N>& names, uint8_t& seen,
                bool& schema_error, OnField on_field) {
  JsonToken t = r.next();
  if (t != JsonToken::kObjectBegin) {
    schema_error = true;
    return r.skip_value(t);
  }
  for (;;) {
    t = r.next();
    if (t == JsonToken::kObjectEnd) return true;
    if (t != JsonToken::kKey) return false;
    // serde_json unescapes keys of the objects it interprets and rejects lone surrogates there.
    if (!r.strict_utf16()) schema_error = true;
    const int idx = r.escaped() ? -1 : find_name(names, r.text());
    const uint8_t bit = idx < 0 ? 0 : static_cast<uint8_t>(1u << idx);
    if (idx < 0 || (seen & bit) != 0) {
      if (idx >= 0) schema_error = true;
      if (!r.skip_value(r.next())) return false;
      continue;
    }
    seen |= bit;
    if (!on_field(static_cast<size_t>(idx))) return false;
  }
}

template <size_t N>
void copy_to(std::string_view s, FixedString<N>& out) {
  std::copy(s.begin(), s.end(), out.data.begin());
  out.len = static_cast<uint16_t>(s.size());
}

// 1..=4 entries (empty -> kBadJson, more -> kTooLarge), each 1..=64 bytes (same split).
Status check_addrs(const AddrList& list,
                   std::array<FixedString<kConnectInfoMaxAddrLen>, kConnectInfoMaxAddrs>& out,
                   uint8_t& count) {
  if (list.count == 0) return Error::kBadJson;
  if (list.count > kConnectInfoMaxAddrs) return Error::kTooLarge;
  for (size_t i = 0; i < list.count; ++i) {
    const std::string_view a = list.items[i];
    if (a.empty()) return Error::kBadJson;
    if (a.size() > kConnectInfoMaxAddrLen) return Error::kTooLarge;
    copy_to(a, out[i]);
  }
  count = static_cast<uint8_t>(list.count);
  return std::monostate{};
}

// base64url errors first, then the length: a too-long value is kBadLength, as in Rust.
Result<size_t> b64_decode(std::string_view s, std::span<uint8_t> out) {
  const Result<size_t> r = base64_decode(Base64Alphabet::kUrl, s, out);
  if (!r.ok() && r.error() == Error::kBufferTooSmall) return Error::kBadLength;
  return r;
}

Status b64_fixed(std::string_view s, std::span<uint8_t> out) {
  const Result<size_t> r = b64_decode(s, out);
  if (!r.ok()) return r.error();
  if (r.value() != out.size()) return Error::kBadLength;
  return std::monostate{};
}

// `out` holds exactly the maximum ticket size.
Status b64_ticket(std::string_view s, size_t min, std::span<uint8_t> out, uint16_t& len) {
  const Result<size_t> r = b64_decode(s, out);
  if (!r.ok()) return r.error();
  if (r.value() < min) return Error::kBadLength;
  len = static_cast<uint16_t>(r.value());
  return std::monostate{};
}

int lower_hex(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

Status check_session_id(std::string_view s, std::array<uint8_t, 8>& out) {
  if (s.size() != 16) return Error::kBadEncoding;
  for (size_t i = 0; i < 8; ++i) {
    const int hi = lower_hex(s[2 * i]);
    const int lo = lower_hex(s[2 * i + 1]);
    if (hi < 0 || lo < 0) return Error::kBadEncoding;
    out[i] = static_cast<uint8_t>(hi << 4 | lo);
  }
  return std::monostate{};
}

// `len` characters of the standard base64 alphabet without '='. Trailing bits are not checked,
// matching the Rust reference.
Status check_std_b64_chars(std::string_view s, size_t len) {
  if (s.size() != len) return Error::kBadLength;
  for (const char c : s) {
    const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                    c == '+' || c == '/';
    if (!ok) return Error::kBadEncoding;
  }
  return std::monostate{};
}

Status check_native(const NativeRaw& n, NativeInfo& out) {
  if (Status s = check_addrs(n.gateways, out.gateways, out.gateway_count); !s.ok()) return s;
  if (Status s = b64_fixed(n.routing_ticket, out.routing_ticket); !s.ok()) return s;
  if (Status s =
          b64_ticket(n.server_ticket, kNativeTicketMin, out.server_ticket, out.server_ticket_len);
      !s.ok()) {
    return s;
  }
  if (Status s = b64_fixed(n.key_c2s, out.key_c2s); !s.ok()) return s;
  return b64_fixed(n.key_s2c, out.key_s2c);
}

Status check_webrtc(const WebRtcRaw& w, WebRtcInfo& out) {
  if (Status s = check_addrs(w.candidates, out.candidates, out.candidate_count); !s.ok()) {
    return s;
  }
  if (Status s = check_std_b64_chars(w.ice_ufrag, kUfragLen); !s.ok()) return s;
  if (Status s = check_std_b64_chars(w.ice_pwd, kPwdLen); !s.ok()) return s;
  const std::string_view fp = w.dtls_fingerprint;
  if (fp.empty() || fp.size() > kFingerprintMax) return Error::kBadLength;
  for (const char c : fp) {
    if (c < 0x20 || c > 0x7e) return Error::kBadEncoding;
  }
  copy_to(w.ice_ufrag, out.ice_ufrag);
  copy_to(w.ice_pwd, out.ice_pwd);
  copy_to(fp, out.dtls_fingerprint);
  return b64_ticket(w.server_ticket, kBrowserTicketMin, out.server_ticket, out.server_ticket_len);
}

Status check_wt(const WtRaw& t, WtInfo& out) {
  if (t.url.empty() || t.url.size() > kUrlMax) return Error::kBadLength;
  if (!t.url.starts_with(kUrlPrefix)) return Error::kBadEncoding;
  copy_to(t.url, out.url);
  return b64_fixed(t.cert_sha256, out.cert_sha256);
}

// Everything the parse pass collects before validation.
struct Parsed {
  uint8_t seen = 0;  // kTopNames bits
  std::string_view v;
  bool v_is_number = false;
  std::string_view session_id;
  uint32_t expiry = 0;
  NativeRaw native;
  WebRtcRaw webrtc;
  WtRaw wt;
  bool schema_error = false;
};

// Rules 3-5: grammar and pass-1 failures return kBadJson; schema failures set schema_error.
Status parse(std::string_view json, Parsed& p) {
  JsonReader r(json);
  if (r.next() != JsonToken::kObjectBegin) return Error::kBadJson;
  bool& se = p.schema_error;
  for (;;) {
    JsonToken t = r.next();
    if (t == JsonToken::kObjectEnd) break;
    if (t != JsonToken::kKey) return Error::kBadJson;
    // Both passes unescape top-level keys, so a lone surrogate there fails pass 1.
    if (!r.strict_utf16()) return Error::kBadJson;
    const int idx = r.escaped() ? -1 : find_name(kTopNames, r.text());
    if (idx < 0) {
      if (!r.skip_value(r.next())) return Error::kBadJson;
      continue;
    }
    const uint8_t bit = static_cast<uint8_t>(1u << idx);
    if ((p.seen & bit) != 0) {
      if (idx == kV) return Error::kBadJson;  // pass 1 rejects a second `v`
      se = true;
      if (!r.skip_value(r.next())) return Error::kBadJson;
      continue;
    }
    p.seen |= bit;
    bool ok = true;
    switch (idx) {
      case kV:
        t = r.next();
        p.v_is_number = t == JsonToken::kNumber;
        if (p.v_is_number) p.v = r.text();
        ok = r.skip_value(t);
        break;
      case kSessionId:
        ok = read_string(r, p.session_id, se);
        break;
      case kExpiry:
        t = r.next();
        if (t != JsonToken::kNumber || !parse_u32(r.text(), p.expiry)) {
          se = true;
          ok = r.skip_value(t);
        }
        break;
      case kNative:
        ok = read_block(r, kNativeNames, p.native.seen, se, [&](size_t f) {
          NativeRaw& n = p.native;
          switch (f) {
            case 0:
              return read_addrs(r, n.gateways, se);
            case 1:
              return read_string(r, n.routing_ticket, se);
            case 2:
              return read_string(r, n.server_ticket, se);
            case 3:
              return read_string(r, n.key_c2s, se);
            default:
              return read_string(r, n.key_s2c, se);
          }
        });
        break;
      case kWebRtc:
        ok = read_block(r, kWebRtcNames, p.webrtc.seen, se, [&](size_t f) {
          WebRtcRaw& w = p.webrtc;
          switch (f) {
            case 0:
              return read_addrs(r, w.candidates, se);
            case 1:
              return read_string(r, w.ice_ufrag, se);
            case 2:
              return read_string(r, w.ice_pwd, se);
            case 3:
              return read_string(r, w.dtls_fingerprint, se);
            default:
              return read_string(r, w.server_ticket, se);
          }
        });
        break;
      default:
        ok = read_block(r, kWtNames, p.wt.seen, se, [&](size_t f) {
          return read_string(r, f == 0 ? p.wt.url : p.wt.cert_sha256, se);
        });
        break;
    }
    if (!ok) return Error::kBadJson;
  }
  if (r.next() != JsonToken::kEnd) return Error::kBadJson;
  return std::monostate{};
}

// `v` must be the integer token `1`; any other integer token, however long, is a version
// mismatch, while fractions, exponents and non-numbers are kBadJson.
Status check_version(const Parsed& p) {
  if ((p.seen & (1u << kV)) == 0 || !p.v_is_number) return Error::kBadJson;
  if (p.v.find_first_of(".eE") != std::string_view::npos) return Error::kBadJson;
  return p.v == "1" ? Status(std::monostate{}) : Status(Error::kBadVersion);
}

}  // namespace

Status decode_connect_info(std::string_view b64, ConnectInfo& out, std::span<uint8_t> scratch) {
  out.has_native = out.has_webrtc = out.has_webtransport = false;
  if (scratch.size() < kConnectInfoScratchMin) return Error::kBufferTooSmall;

  // Rule 1.
  if (b64.size() > kMaxB64Len) return Error::kTooLarge;
  const Result<size_t> n =
      base64_decode(Base64Alphabet::kUrl, b64, scratch.first(kMaxConnectInfoJson));
  if (!n.ok()) return n.error() == Error::kBufferTooSmall ? Error::kTooLarge : n.error();
  const std::span<const uint8_t> bytes = scratch.first(n.value());
  const std::string_view json(reinterpret_cast<const char*>(bytes.data()), bytes.size());

  // Rules 2-4.
  if (!depth_ok(json)) return Error::kBadJson;
  if (!is_valid_utf8(bytes)) return Error::kBadJson;
  Parsed p;
  if (Status s = parse(json, p); !s.ok()) return s;
  if (Status s = check_version(p); !s.ok()) return s;

  // Rules 5-6.
  if (p.schema_error) return Error::kBadJson;
  if ((p.seen & (1u << kSessionId)) == 0 || (p.seen & (1u << kExpiry)) == 0) {
    return Error::kBadJson;
  }
  const bool has_native = (p.seen & (1u << kNative)) != 0;
  const bool has_webrtc = (p.seen & (1u << kWebRtc)) != 0;
  const bool has_wt = (p.seen & (1u << kWebTransport)) != 0;
  if (!has_native && !has_webrtc && !has_wt) return Error::kBadJson;
  if ((has_native && p.native.seen != all_bits(kNativeNames)) ||
      (has_webrtc && p.webrtc.seen != all_bits(kWebRtcNames)) ||
      (has_wt && p.wt.seen != all_bits(kWtNames))) {
    return Error::kBadJson;
  }

  // Rule 7.
  if (Status s = check_session_id(p.session_id, out.session_id); !s.ok()) return s;
  out.expiry = p.expiry;
  if (has_native) {
    if (Status s = check_native(p.native, out.native); !s.ok()) return s;
  }
  if (has_webrtc) {
    if (Status s = check_webrtc(p.webrtc, out.webrtc); !s.ok()) return s;
  }
  if (has_wt) {
    if (Status s = check_wt(p.wt, out.webtransport); !s.ok()) return s;
  }
  out.has_native = has_native;
  out.has_webrtc = has_webrtc;
  out.has_webtransport = has_wt;
  return std::monostate{};
}

}  // namespace glassy::proto
