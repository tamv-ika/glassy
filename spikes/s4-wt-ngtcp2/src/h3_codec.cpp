#include "h3_codec.hpp"

#include <nghttp3/nghttp3.h>

#include <memory>
#include <string_view>

namespace glassy {
namespace {

constexpr uint64_t kFrameSettings = 0x04;
constexpr size_t kMaxVarintLen = 8;

void append_varint(std::vector<uint8_t>& out, uint64_t v) {
  uint8_t buf[kMaxVarintLen];
  const size_t n = varint_encode(v, buf);
  out.insert(out.end(), buf, buf + n);
}

// Literal field line with a literal name, no Huffman (RFC 9204 §4.5.6).
void append_literal(std::vector<uint8_t>& out, std::string_view name, std::string_view value) {
  // '001' pattern, N=0, H=0, then a 3-bit-prefix length; continuation bytes follow RFC 7541 §5.1.
  size_t len = name.size();
  if (len < 7) {
    out.push_back(static_cast<uint8_t>(0x20 | len));
  } else {
    out.push_back(0x27);
    len -= 7;
    while (len >= 0x80) {
      out.push_back(static_cast<uint8_t>(0x80 | (len & 0x7f)));
      len >>= 7;
    }
    out.push_back(static_cast<uint8_t>(len));
  }
  out.insert(out.end(), name.begin(), name.end());
  out.push_back(static_cast<uint8_t>(value.size()));  // values here are < 127 bytes
  out.insert(out.end(), value.begin(), value.end());
}

std::string_view rcbuf_view(nghttp3_rcbuf* buf) {
  const nghttp3_vec v = nghttp3_rcbuf_get_buf(buf);
  return {reinterpret_cast<const char*>(v.base), v.len};
}

}  // namespace

size_t varint_encode(uint64_t v, uint8_t* out) {
  size_t len = 0;
  uint8_t prefix = 0;
  if (v < (1ull << 6)) {
    len = 1;
  } else if (v < (1ull << 14)) {
    len = 2;
    prefix = 0x40;
  } else if (v < (1ull << 30)) {
    len = 4;
    prefix = 0x80;
  } else {
    len = 8;
    prefix = 0xc0;
  }
  for (size_t i = 0; i < len; ++i) {
    out[len - 1 - i] = static_cast<uint8_t>(v >> (8 * i));
  }
  out[0] |= prefix;
  return len;
}

std::optional<std::pair<uint64_t, size_t>> varint_decode(std::span<const uint8_t> in) {
  if (in.empty()) {
    return std::nullopt;
  }
  const size_t len = size_t{1} << (in[0] >> 6);
  if (in.size() < len) {
    return std::nullopt;
  }
  uint64_t v = in[0] & 0x3f;
  for (size_t i = 1; i < len; ++i) {
    v = (v << 8) | in[i];
  }
  return std::make_pair(v, len);
}

std::vector<uint8_t> encode_settings_frame(const Settings& settings) {
  std::vector<uint8_t> payload;
  for (const auto& [id, value] : settings) {
    append_varint(payload, id);
    append_varint(payload, value);
  }
  std::vector<uint8_t> frame;
  append_varint(frame, kFrameSettings);
  append_varint(frame, payload.size());
  frame.insert(frame.end(), payload.begin(), payload.end());
  return frame;
}

std::optional<Settings> decode_settings_payload(std::span<const uint8_t> payload) {
  Settings out;
  while (!payload.empty()) {
    const auto id = varint_decode(payload);
    if (!id) {
      return std::nullopt;
    }
    payload = payload.subspan(id->second);
    const auto value = varint_decode(payload);
    if (!value) {
      return std::nullopt;
    }
    payload = payload.subspan(value->second);
    out.emplace_back(id->first, value->first);
  }
  return out;
}

std::optional<std::map<std::string, std::string>> qpack_decode_request(
    std::span<const uint8_t> block) {
  nghttp3_qpack_decoder* raw_decoder = nullptr;
  // Dynamic table capacity 0: we advertise QPACK_MAX_TABLE_CAPACITY = 0, so peers may not use it.
  if (nghttp3_qpack_decoder_new(&raw_decoder, 0, 0, nghttp3_mem_default()) != 0) {
    return std::nullopt;
  }
  std::unique_ptr<nghttp3_qpack_decoder, decltype(&nghttp3_qpack_decoder_del)> decoder(
      raw_decoder, &nghttp3_qpack_decoder_del);
  nghttp3_qpack_stream_context* raw_ctx = nullptr;
  if (nghttp3_qpack_stream_context_new(&raw_ctx, 0, nghttp3_mem_default()) != 0) {
    return std::nullopt;
  }
  std::unique_ptr<nghttp3_qpack_stream_context, decltype(&nghttp3_qpack_stream_context_del)> ctx(
      raw_ctx, &nghttp3_qpack_stream_context_del);

  std::map<std::string, std::string> headers;
  const uint8_t* src = block.data();
  size_t left = block.size();
  for (;;) {
    nghttp3_qpack_nv nv{};
    uint8_t flags = 0;
    const nghttp3_ssize n = nghttp3_qpack_decoder_read_request(decoder.get(), ctx.get(), &nv,
                                                               &flags, src, left, /*fin=*/1);
    if (n < 0 || (flags & NGHTTP3_QPACK_DECODE_FLAG_BLOCKED)) {
      return std::nullopt;
    }
    src += n;
    left -= static_cast<size_t>(n);
    if (flags & NGHTTP3_QPACK_DECODE_FLAG_EMIT) {
      headers.emplace(rcbuf_view(nv.name), rcbuf_view(nv.value));
      nghttp3_rcbuf_decref(nv.name);
      nghttp3_rcbuf_decref(nv.value);
    }
    if (flags & NGHTTP3_QPACK_DECODE_FLAG_FINAL) {
      return headers;
    }
    if (n == 0 && left == 0 && !(flags & NGHTTP3_QPACK_DECODE_FLAG_EMIT)) {
      return std::nullopt;  // no progress: truncated field section
    }
  }
}

std::vector<uint8_t> encode_response_headers() {
  // Required Insert Count 0, Base 0, then indexed static entry 25 (":status 200").
  std::vector<uint8_t> out{0x00, 0x00, 0xd9};
  // Chromium's draft-02 implementation expects this header on the 200 response.
  append_literal(out, "sec-webtransport-http3-draft", "draft02");
  return out;
}

}  // namespace glassy
