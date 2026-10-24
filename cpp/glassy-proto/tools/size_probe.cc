// References every public function of glassy_proto_core so --gc-sections cannot drop them; the
// binary is only measured (tools/check_size.sh), never run. Inputs come from argv/stdin sizes so
// the compiler cannot constant-fold the calls away.
#include <array>
#include <cstdint>
#include <span>

#include "glassy/proto/aead.h"
#include "glassy/proto/connect_info.h"
#include "glassy/proto/error.h"
#include "glassy/proto/frame.h"
#include "glassy/proto/message.h"
#include "glassy/proto/packet.h"
#include "glassy/proto/pn.h"
#include "glassy/proto/utf8.h"
#include "glassy/proto/varint.h"

using namespace glassy::proto;

namespace {

// Keeps results observable so calls are not optimised out.
volatile uint64_t g_sink = 0;

template <class R>
void eat(const R& r) {
  g_sink = g_sink + static_cast<uint64_t>(r.error());
}

}  // namespace

int main(int argc, char** argv) {
  static std::array<uint8_t, 2048> buf{};
  static std::array<uint8_t, 2048> out{};
  const size_t n = static_cast<size_t>(argc) % buf.size();
  const std::span<const uint8_t> in(buf.data(), n);
  const std::span<uint8_t> dst(out);
  const Key32 key{};
  const std::array<uint8_t, 16> nonce16{};
  const std::array<uint8_t, 8> sid{};
  const Nonce24 nonce24{};
  const uint64_t pn = static_cast<uint64_t>(argc);

  g_sink = g_sink + reinterpret_cast<uintptr_t>(error_code(Error::kOk));
  g_sink = g_sink + is_valid_utf8(in);
  eat(varint_encode(pn, dst));
  eat(varint_decode(in));
  eat(xchacha_seal(key, nonce24, in, in, dst));
  eat(xchacha_open(key, nonce24, in, in, dst));
  g_sink = g_sink + packet_nonce(nonce16, pn)[0];

  static ConnectInfo info;
  eat(decode_connect_info(std::string_view(reinterpret_cast<const char*>(buf.data()), n), info,
                          dst));

  g_sink = g_sink + decode_pn(pn, static_cast<uint32_t>(argc));
  static ReplayWindow window;
  eat(window.check(pn));
  window.commit(pn);

  const ConnectParams params{sid, nonce16, pn, in, in, key, n};
  eat(build_connect(params, dst));
  eat(parse_connect(in));
  eat(peek_reply(in));
  eat(open_accept(in, nonce16, key));
  eat(open_reject(in, nonce16, key));
  eat(parse_header(in));
  eat(seal_data(key, nonce16, sid, pn, in, dst));
  eat(open_data(key, nonce16, in, pn, dst));
  eat(seal_disconnect(key, nonce16, sid, pn, 0));
  eat(open_disconnect(key, nonce16, in, pn));

  FrameReader reader(in);
  Frame frame;
  eat(reader.next(frame));
  eat(encode_ack(AckFrame{}, dst));
  eat(encode_stream(pn, in, dst));
  eat(encode_datagram(in, dst));

  eat(decode_message_header(in));
  eat(encode_message_header(n, dst));

  return static_cast<int>(g_sink & 0x7f);
}
