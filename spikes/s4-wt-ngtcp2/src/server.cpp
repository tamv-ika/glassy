// S4 spike server: WebTransport over HTTP/3 on ngtcp2 + GnuTLS. It accepts the gateway's
// no-shared-state Retry tokens (spec §3.6) and echoes datagrams and bidi streams (spec §6.5).
//
// THROWAWAY: SP0 spike code. One thread, one poll loop, no stream-count or window tuning.

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "cidr.hpp"
#include "h3_codec.hpp"
#include "retry_token.hpp"

namespace {

using glassy::varint_decode;
using glassy::varint_encode;

constexpr size_t kScidLen = 18;
// Bounds on buffered inbound stream bytes and queued echo datagrams (CONVENTIONS §3).
constexpr size_t kMaxStreamBytes = 64 * 1024;
constexpr size_t kMaxQueuedDatagrams = 64;
constexpr size_t kMaxPacket = 1500;
constexpr uint64_t kWtBidiSignal = 0x41;
constexpr uint64_t kFrameHeaders = 0x01;
constexpr uint64_t kFrameSettings = 0x04;
constexpr uint64_t kStreamTypeControl = 0x00;
constexpr uint8_t kStreamTypeQpackEncoder = 0x02;
constexpr uint8_t kStreamTypeQpackDecoder = 0x03;

struct Args {
  uint16_t port = 7103;
  std::string cert;
  std::string key;
  std::vector<std::string> trusted_cidrs;
  std::string settings_log;
};

ngtcp2_tstamp now_ns() {
  timespec ts{};
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return static_cast<ngtcp2_tstamp>(ts.tv_sec) * NGTCP2_SECONDS +
         static_cast<ngtcp2_tstamp>(ts.tv_nsec);
}

std::string hex(const uint8_t* data, size_t len) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  for (size_t i = 0; i < len; ++i) {
    out.push_back(kDigits[data[i] >> 4]);
    out.push_back(kDigits[data[i] & 0x0f]);
  }
  return out;
}

std::string cid_key(const uint8_t* data, size_t len) {
  return std::string(reinterpret_cast<const char*>(data), len);
}

std::string json_escape(const std::string& s) {
  std::string out;
  for (char c : s) {
    if (c == '"' || c == '\\') {
      out.push_back('\\');
      out.push_back(c);
    } else if (static_cast<unsigned char>(c) < 0x20) {
      char buf[8];
      snprintf(buf, sizeof buf, "\\u%04x", static_cast<unsigned char>(c));
      out += buf;
    } else {
      out.push_back(c);
    }
  }
  return out;
}

bool debug_enabled() {
  const char* v = getenv("GLASSY_LOG");
  return v != nullptr && std::string(v) == "debug";
}

void ngtcp2_debug_printf(void*, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
}

// What the S4 test inspects: the client's SETTINGS and its extended CONNECT header fields.
// Setting IDs are written as hex strings because GREASE IDs exceed JSON's exact integer range.
struct SettingsLog {
  std::string path;
  glassy::Settings client_settings;
  std::map<std::string, std::string> connect_headers;

  void write() const {
    if (path.empty()) return;
    std::string json = "{\"client_settings\":[";
    for (size_t i = 0; i < client_settings.size(); ++i) {
      char buf[80];
      snprintf(buf, sizeof buf, "%s[\"0x%llx\",%llu]", i ? "," : "",
               static_cast<unsigned long long>(client_settings[i].first),
               static_cast<unsigned long long>(client_settings[i].second));
      json += buf;
    }
    json += "],\"connect_headers\":{";
    bool first = true;
    for (const auto& [name, value] : connect_headers) {
      json += (first ? "\"" : ",\"") + json_escape(name) + "\":\"" + json_escape(value) + "\"";
      first = false;
    }
    json += "}}\n";
    std::ofstream(path, std::ios::trunc) << json;
  }
};

SettingsLog g_log;
gnutls_certificate_credentials_t g_cred = nullptr;

std::vector<uint8_t> frame(uint64_t type, const std::vector<uint8_t>& payload) {
  std::vector<uint8_t> out(16);
  size_t n = varint_encode(type, out.data());
  n += varint_encode(payload.size(), out.data() + n);
  out.resize(n);
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

// Splits one complete HTTP/3 frame off the front of `buf`; nullopt until it has fully arrived.
std::optional<std::pair<uint64_t, std::vector<uint8_t>>> take_frame(std::vector<uint8_t>& buf) {
  auto type = varint_decode(buf);
  if (!type) return std::nullopt;
  auto len = varint_decode(std::span(buf).subspan(type->second));
  if (!len) return std::nullopt;
  size_t start = type->second + len->second;
  if (buf.size() - start < len->first) return std::nullopt;
  std::vector<uint8_t> payload(buf.begin() + static_cast<ptrdiff_t>(start),
                               buf.begin() + static_cast<ptrdiff_t>(start + len->first));
  buf.erase(buf.begin(), buf.begin() + static_cast<ptrdiff_t>(start + len->first));
  return std::make_pair(type->first, std::move(payload));
}

// One stream's inbound buffer and outbound queue. Outbound chunks are never freed while the
// stream lives because ngtcp2 retransmits lost STREAM data straight from them.
struct Stream {
  enum class Kind { Unknown, Control, Request, WtBidi, Ignored };

  int64_t id = 0;
  Kind kind = Kind::Unknown;
  std::vector<uint8_t> rx;
  std::deque<std::vector<uint8_t>> tx;
  size_t tx_idx = 0;
  size_t tx_off = 0;
  bool fin_queued = false;
  bool fin_sent = false;

  bool has_pending() const { return tx_idx < tx.size() || (fin_queued && !fin_sent); }

  void queue(std::vector<uint8_t> bytes) {
    if (!bytes.empty()) tx.push_back(std::move(bytes));
  }

  void consume(size_t n, bool fin_flag) {
    while (n > 0) {
      size_t left = tx[tx_idx].size() - tx_off;
      if (n >= left) {
        n -= left;
        ++tx_idx;
        tx_off = 0;
      } else {
        tx_off += n;
        n = 0;
      }
    }
    if (fin_flag && tx_idx == tx.size()) fin_sent = true;
  }
};

class Server;

class Conn {
 public:
  Conn(Server& server, int fd, const sockaddr_in& local, const sockaddr_in& remote)
      : server_(server), fd_(fd), local_(local), remote_(remote) {}

  ~Conn() {
    if (conn_ != nullptr) ngtcp2_conn_del(conn_);
    if (tls_ != nullptr) gnutls_deinit(tls_);
  }

  Conn(const Conn&) = delete;
  Conn& operator=(const Conn&) = delete;

  bool init(const ngtcp2_pkt_hd& hd, const std::optional<std::vector<uint8_t>>& odcid,
            ngtcp2_tstamp ts);
  // Each returns false when the connection is finished and must be dropped.
  bool read(const uint8_t* data, size_t len, ngtcp2_tstamp ts);
  bool flush(ngtcp2_tstamp ts);
  bool handle_expiry(ngtcp2_tstamp ts);
  ngtcp2_tstamp expiry() const { return ngtcp2_conn_get_expiry(conn_); }
  const ngtcp2_cid& scid() const { return scid_; }

 private:
  static int on_recv_stream_data(ngtcp2_conn*, uint32_t flags, int64_t sid, uint64_t,
                                 const uint8_t* data, size_t len, void* user, void*);
  static int on_recv_datagram(ngtcp2_conn*, uint32_t, const uint8_t* data, size_t len,
                              void* user);
  static int on_handshake_completed(ngtcp2_conn*, void* user);
  static int on_stream_close(ngtcp2_conn*, uint32_t, int64_t sid, uint64_t, uint64_t, void* user,
                             void*);
  static int on_new_connection_id(ngtcp2_conn*, ngtcp2_cid* cid,
                                  ngtcp2_stateless_reset_token* token, size_t cidlen,
                                  void* user);
  static int on_remove_connection_id(ngtcp2_conn*, const ngtcp2_cid* cid, void* user);

  void on_stream_bytes(int64_t sid, const uint8_t* data, size_t len, bool fin);
  void process_control(Stream& s);
  void process_request(Stream& s);
  bool open_uni(std::vector<uint8_t> bytes);
  ngtcp2_path path();
  void send_packet(const ngtcp2_path& path, const uint8_t* data, size_t len);
  void write_close(int liberr, ngtcp2_tstamp ts);

  Server& server_;
  int fd_;
  sockaddr_in local_;
  sockaddr_in remote_;
  ngtcp2_cid scid_{};
  ngtcp2_conn* conn_ = nullptr;
  gnutls_session_t tls_ = nullptr;
  ngtcp2_crypto_conn_ref conn_ref_{};
  std::map<int64_t, Stream> streams_;
  std::deque<std::vector<uint8_t>> datagrams_;
};

class Server {
 public:
  explicit Server(Args args) : args_(std::move(args)) {}
  bool start();
  [[noreturn]] void run();

  void add_cid(const uint8_t* data, size_t len, Conn* conn) {
    auto it = owners_.find(conn);
    if (it != owners_.end()) by_cid_[cid_key(data, len)] = it->second;
  }
  void remove_cid(const uint8_t* data, size_t len) { by_cid_.erase(cid_key(data, len)); }

 private:
  void on_packet(const uint8_t* data, size_t len, const sockaddr_in& remote, ngtcp2_tstamp ts);
  void accept(const uint8_t* data, size_t len, const sockaddr_in& remote, ngtcp2_tstamp ts);
  void drop(Conn* conn);
  int poll_timeout_ms(ngtcp2_tstamp ts) const;
  void handle_timers(ngtcp2_tstamp ts);

  Args args_;
  int fd_ = -1;
  sockaddr_in local_{};
  std::unordered_map<std::string, std::shared_ptr<Conn>> by_cid_;
  std::unordered_map<Conn*, std::shared_ptr<Conn>> owners_;
};

ngtcp2_conn* get_conn(ngtcp2_crypto_conn_ref* ref) {
  return static_cast<ngtcp2_conn*>(ref->user_data);
}

void rand_bytes(uint8_t* dest, size_t len, const ngtcp2_rand_ctx*) {
  gnutls_rnd(GNUTLS_RND_RANDOM, dest, len);
}

bool Conn::init(const ngtcp2_pkt_hd& hd, const std::optional<std::vector<uint8_t>>& odcid,
                ngtcp2_tstamp ts) {
  ngtcp2_callbacks cb{};
  cb.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
  cb.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
  cb.handshake_completed = on_handshake_completed;
  cb.encrypt = ngtcp2_crypto_encrypt_cb;
  cb.decrypt = ngtcp2_crypto_decrypt_cb;
  cb.hp_mask = ngtcp2_crypto_hp_mask_cb;
  cb.recv_stream_data = on_recv_stream_data;
  cb.rand = rand_bytes;
  cb.remove_connection_id = on_remove_connection_id;
  cb.update_key = ngtcp2_crypto_update_key_cb;
  cb.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
  cb.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
  cb.recv_datagram = on_recv_datagram;
  cb.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
  cb.get_new_connection_id2 = on_new_connection_id;
  cb.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb;
  cb.stream_close2 = on_stream_close;

  scid_.datalen = kScidLen;
  gnutls_rnd(GNUTLS_RND_RANDOM, scid_.data, scid_.datalen);

  ngtcp2_settings settings;
  ngtcp2_settings_default(&settings);
  // Must not be later than the ts of the first read_pkt, or ngtcp2 asserts.
  settings.initial_ts = ts;
  if (debug_enabled()) settings.log_printf = ngtcp2_debug_printf;
  if (odcid) {
    settings.token = hd.token;
    settings.tokenlen = hd.tokenlen;
    settings.token_type = NGTCP2_TOKEN_TYPE_RETRY;
  }

  ngtcp2_transport_params params;
  ngtcp2_transport_params_default(&params);
  params.initial_max_stream_data_bidi_local = 256 * 1024;
  params.initial_max_stream_data_bidi_remote = 256 * 1024;
  params.initial_max_stream_data_uni = 256 * 1024;
  params.initial_max_data = 1024 * 1024;
  params.initial_max_streams_bidi = 100;
  params.initial_max_streams_uni = 100;
  params.max_idle_timeout = 30 * NGTCP2_SECONDS;
  params.max_datagram_frame_size = 65535;
  if (odcid) {
    // The client's first Initial went to the gateway, which answered with Retry; the client
    // checks both IDs against what it saw (RFC 9000 §7.3).
    params.original_dcid.datalen = odcid->size();
    std::copy(odcid->begin(), odcid->end(), params.original_dcid.data);
    params.retry_scid = hd.dcid;
    params.retry_scid_present = 1;
  } else {
    params.original_dcid = hd.dcid;
  }
  params.original_dcid_present = 1;

  ngtcp2_path p = path();
  if (int rv = ngtcp2_conn_server_new(&conn_, &hd.scid, &scid_, &p, hd.version, &cb, &settings,
                                      &params, nullptr, this);
      rv != 0) {
    fprintf(stderr, "ngtcp2_conn_server_new: %s\n", ngtcp2_strerror(rv));
    return false;
  }

  if (gnutls_init(&tls_, GNUTLS_SERVER | GNUTLS_NO_AUTO_SEND_TICKET) != 0) return false;
  const char* priority =
      "%DISABLE_TLS13_COMPAT_MODE:NORMAL:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+AES-128-GCM:"
      "+AES-256-GCM:+CHACHA20-POLY1305:+AES-128-CCM:-GROUP-ALL:+GROUP-X25519:+GROUP-SECP256R1:"
      "+GROUP-SECP384R1:+GROUP-SECP521R1";
  if (gnutls_priority_set_direct(tls_, priority, nullptr) != 0) return false;
  if (ngtcp2_crypto_gnutls_configure_server_session(tls_) != 0) return false;
  conn_ref_.get_conn = get_conn;
  conn_ref_.user_data = conn_;
  gnutls_session_set_ptr(tls_, &conn_ref_);
  if (gnutls_credentials_set(tls_, GNUTLS_CRD_CERTIFICATE, g_cred) != 0) return false;
  static uint8_t kAlpnH3[] = {'h', '3'};
  gnutls_datum_t alpn{kAlpnH3, sizeof kAlpnH3};
  gnutls_alpn_set_protocols(tls_, &alpn, 1,
                            GNUTLS_ALPN_MANDATORY | GNUTLS_ALPN_SERVER_PRECEDENCE);
  ngtcp2_conn_set_tls_native_handle(conn_, tls_);
  return true;
}

ngtcp2_path Conn::path() {
  ngtcp2_path p{};
  p.local.addr = reinterpret_cast<ngtcp2_sockaddr*>(&local_);
  p.local.addrlen = sizeof local_;
  p.remote.addr = reinterpret_cast<ngtcp2_sockaddr*>(&remote_);
  p.remote.addrlen = sizeof remote_;
  return p;
}

bool Conn::read(const uint8_t* data, size_t len, ngtcp2_tstamp ts) {
  ngtcp2_path p = path();
  ngtcp2_pkt_info pi{};
  int rv = ngtcp2_conn_read_pkt(conn_, &p, &pi, data, len, ts);
  if (rv == 0) return true;
  if (rv != NGTCP2_ERR_DRAINING && rv != NGTCP2_ERR_CLOSING && rv != NGTCP2_ERR_DROP_CONN) {
    fprintf(stderr, "ngtcp2_conn_read_pkt: %s\n", ngtcp2_strerror(rv));
    write_close(rv, ts);
  }
  return false;
}

void Conn::write_close(int liberr, ngtcp2_tstamp ts) {
  ngtcp2_ccerr ccerr;
  ngtcp2_ccerr_default(&ccerr);
  if (liberr == NGTCP2_ERR_CRYPTO) {
    ngtcp2_ccerr_set_tls_alert(&ccerr, ngtcp2_conn_get_tls_alert(conn_), nullptr, 0);
  } else {
    ngtcp2_ccerr_set_liberr(&ccerr, liberr, nullptr, 0);
  }
  std::array<uint8_t, kMaxPacket> buf;
  ngtcp2_path_storage ps;
  ngtcp2_path_storage_zero(&ps);
  ngtcp2_pkt_info pi{};
  auto n = ngtcp2_conn_write_connection_close(conn_, &ps.path, &pi, buf.data(), buf.size(),
                                              &ccerr, ts);
  if (n > 0) send_packet(ps.path, buf.data(), static_cast<size_t>(n));
}

void Conn::send_packet(const ngtcp2_path& p, const uint8_t* data, size_t len) {
  if (sendto(fd_, data, len, 0, reinterpret_cast<const sockaddr*>(p.remote.addr),
             p.remote.addrlen) < 0) {
    fprintf(stderr, "sendto: %s\n", strerror(errno));
  }
}

bool Conn::flush(ngtcp2_tstamp ts) {
  std::array<uint8_t, kMaxPacket> buf;
  ngtcp2_path_storage ps;
  ngtcp2_path_storage_zero(&ps);
  ngtcp2_pkt_info pi{};
  std::set<int64_t> blocked;
  for (;;) {
    // Datagrams first: they carry the latency-sensitive echo.
    if (!datagrams_.empty()) {
      int accepted = 0;
      ngtcp2_vec v{datagrams_.front().data(), datagrams_.front().size()};
      auto n = ngtcp2_conn_writev_datagram(conn_, &ps.path, &pi, buf.data(), buf.size(),
                                           &accepted, NGTCP2_WRITE_DATAGRAM_FLAG_NONE, 0, &v, 1,
                                           ts);
      if (n < 0) {
        if (n == NGTCP2_ERR_INVALID_STATE || n == NGTCP2_ERR_INVALID_ARGUMENT) {
          datagrams_.pop_front();
          continue;
        }
        fprintf(stderr, "ngtcp2_conn_writev_datagram: %s\n",
                ngtcp2_strerror(static_cast<int>(n)));
        return false;
      }
      if (accepted) datagrams_.pop_front();
      if (n == 0) {
        ngtcp2_conn_update_pkt_tx_time(conn_, ts);
        return true;
      }
      send_packet(ps.path, buf.data(), static_cast<size_t>(n));
      continue;
    }

    Stream* s = nullptr;
    for (auto& [id, st] : streams_) {
      if (st.has_pending() && !blocked.contains(id)) {
        s = &st;
        break;
      }
    }
    int64_t sid = -1;
    ngtcp2_vec v{};
    size_t vcnt = 0;
    uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_NONE;
    if (s != nullptr) {
      sid = s->id;
      if (s->tx_idx < s->tx.size()) {
        auto& chunk = s->tx[s->tx_idx];
        v = {chunk.data() + s->tx_off, chunk.size() - s->tx_off};
        vcnt = 1;
      }
      if (s->fin_queued && s->tx_idx + vcnt == s->tx.size()) flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
    }
    ngtcp2_ssize consumed = -1;
    auto n = ngtcp2_conn_writev_stream(conn_, &ps.path, &pi, buf.data(), buf.size(), &consumed,
                                       flags, sid, &v, vcnt, ts);
    if (n < 0) {
      if (n == NGTCP2_ERR_STREAM_DATA_BLOCKED || n == NGTCP2_ERR_STREAM_SHUT_WR ||
          n == NGTCP2_ERR_STREAM_NOT_FOUND) {
        blocked.insert(sid);
        continue;
      }
      fprintf(stderr, "ngtcp2_conn_writev_stream: %s\n", ngtcp2_strerror(static_cast<int>(n)));
      write_close(static_cast<int>(n), ts);
      return false;
    }
    // Look the stream up again: a callback inside writev_stream may have closed it.
    if (auto it = streams_.find(sid); it != streams_.end() && consumed >= 0) {
      it->second.consume(static_cast<size_t>(consumed), (flags & NGTCP2_WRITE_STREAM_FLAG_FIN) != 0);
    }
    if (n == 0) {
      ngtcp2_conn_update_pkt_tx_time(conn_, ts);
      return true;
    }
    send_packet(ps.path, buf.data(), static_cast<size_t>(n));
  }
}

bool Conn::handle_expiry(ngtcp2_tstamp ts) {
  if (int rv = ngtcp2_conn_handle_expiry(conn_, ts); rv != 0) {
    if (rv != NGTCP2_ERR_IDLE_CLOSE) {
      fprintf(stderr, "ngtcp2_conn_handle_expiry: %s\n", ngtcp2_strerror(rv));
    }
    return false;
  }
  return flush(ts);
}

bool Conn::open_uni(std::vector<uint8_t> bytes) {
  int64_t sid = -1;
  if (int rv = ngtcp2_conn_open_uni_stream(conn_, &sid, nullptr); rv != 0) {
    fprintf(stderr, "ngtcp2_conn_open_uni_stream: %s\n", ngtcp2_strerror(rv));
    return false;
  }
  Stream& s = streams_[sid];
  s.id = sid;
  s.kind = Stream::Kind::Ignored;
  s.queue(std::move(bytes));
  return true;
}

int Conn::on_handshake_completed(ngtcp2_conn*, void* user) {
  auto* c = static_cast<Conn*>(user);
  std::vector<uint8_t> control{static_cast<uint8_t>(kStreamTypeControl)};
  auto settings = glassy::encode_settings_frame(glassy::kServerSettings);
  control.insert(control.end(), settings.begin(), settings.end());
  // QPACK encoder/decoder streams stay empty: no dynamic table is ever used.
  if (!c->open_uni(std::move(control)) || !c->open_uni({kStreamTypeQpackEncoder}) ||
      !c->open_uni({kStreamTypeQpackDecoder})) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

int Conn::on_recv_stream_data(ngtcp2_conn* conn, uint32_t flags, int64_t sid, uint64_t,
                              const uint8_t* data, size_t len, void* user, void*) {
  auto* c = static_cast<Conn*>(user);
  c->on_stream_bytes(sid, data, len, (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0);
  ngtcp2_conn_extend_max_stream_offset(conn, sid, len);
  ngtcp2_conn_extend_max_offset(conn, len);
  return 0;
}

void Conn::on_stream_bytes(int64_t sid, const uint8_t* data, size_t len, bool fin) {
  Stream& s = streams_[sid];
  s.id = sid;
  if (s.kind == Stream::Kind::Ignored) return;
  if (s.rx.size() + len > kMaxStreamBytes) {
    fprintf(stderr, "stream %lld exceeds %zu buffered bytes; ignoring it\n",
            static_cast<long long>(sid), kMaxStreamBytes);
    s.kind = Stream::Kind::Ignored;
    s.rx.clear();
    return;
  }
  s.rx.insert(s.rx.end(), data, data + len);

  const bool client_uni = (sid & 0x3) == 0x2;
  if (s.kind == Stream::Kind::Unknown) {
    auto first = varint_decode(s.rx);
    if (!first) return;
    if (client_uni) {
      s.kind = first->first == kStreamTypeControl ? Stream::Kind::Control : Stream::Kind::Ignored;
      s.rx.erase(s.rx.begin(), s.rx.begin() + static_cast<ptrdiff_t>(first->second));
    } else if (first->first == kWtBidiSignal) {
      auto session = varint_decode(std::span(s.rx).subspan(first->second));
      if (!session) return;
      s.kind = Stream::Kind::WtBidi;
      s.rx.erase(s.rx.begin(),
                 s.rx.begin() + static_cast<ptrdiff_t>(first->second + session->second));
    } else {
      s.kind = Stream::Kind::Request;
    }
  }

  switch (s.kind) {
    case Stream::Kind::Control:
      process_control(s);
      break;
    case Stream::Kind::Request:
      process_request(s);
      break;
    case Stream::Kind::WtBidi:
      // The reply direction of a client-opened WT stream carries no signal/session prefix,
      // so only the payload goes back.
      s.queue(std::move(s.rx));
      s.rx.clear();
      if (fin) s.fin_queued = true;
      break;
    default:
      s.rx.clear();
      break;
  }
}

void Conn::process_control(Stream& s) {
  while (auto f = take_frame(s.rx)) {
    if (f->first != kFrameSettings) continue;
    auto settings = glassy::decode_settings_payload(f->second);
    if (!settings) {
      fprintf(stderr, "malformed client SETTINGS\n");
      continue;
    }
    g_log.client_settings = *settings;
    g_log.write();
    for (const auto& [id, value] : *settings) {
      printf("client_setting 0x%llx=%llu\n", static_cast<unsigned long long>(id),
             static_cast<unsigned long long>(value));
    }
    fflush(stdout);
  }
}

void Conn::process_request(Stream& s) {
  while (auto f = take_frame(s.rx)) {
    if (f->first != kFrameHeaders) continue;
    auto headers = glassy::qpack_decode_request(f->second);
    if (!headers) {
      fprintf(stderr, "QPACK decode failed on stream %lld\n", static_cast<long long>(s.id));
      continue;
    }
    g_log.connect_headers = *headers;
    g_log.write();
    for (const auto& [name, value] : *headers) {
      printf("connect_header %s: %s\n", name.c_str(), value.c_str());
    }
    fflush(stdout);
    s.queue(frame(kFrameHeaders, glassy::encode_response_headers()));
  }
}

int Conn::on_recv_datagram(ngtcp2_conn*, uint32_t, const uint8_t* data, size_t len,
                           void* user) {
  auto* c = static_cast<Conn*>(user);
  // The quarter-stream-ID prefix names the same session on the way back, so echo verbatim.
  if (c->datagrams_.size() < kMaxQueuedDatagrams) c->datagrams_.emplace_back(data, data + len);
  return 0;
}

int Conn::on_stream_close(ngtcp2_conn*, uint32_t, int64_t sid, uint64_t, uint64_t, void* user,
                          void*) {
  static_cast<Conn*>(user)->streams_.erase(sid);
  return 0;
}

int Conn::on_new_connection_id(ngtcp2_conn*, ngtcp2_cid* cid,
                               ngtcp2_stateless_reset_token* token, size_t cidlen, void* user) {
  auto* c = static_cast<Conn*>(user);
  cid->datalen = cidlen;
  gnutls_rnd(GNUTLS_RND_RANDOM, cid->data, cidlen);
  gnutls_rnd(GNUTLS_RND_RANDOM, token->data, sizeof token->data);
  c->server_.add_cid(cid->data, cid->datalen, c);
  return 0;
}

int Conn::on_remove_connection_id(ngtcp2_conn*, const ngtcp2_cid* cid, void* user) {
  static_cast<Conn*>(user)->server_.remove_cid(cid->data, cid->datalen);
  return 0;
}

bool Server::start() {
  if (gnutls_certificate_allocate_credentials(&g_cred) != 0) return false;
  if (int rv = gnutls_certificate_set_x509_key_file(g_cred, args_.cert.c_str(), args_.key.c_str(),
                                                    GNUTLS_X509_FMT_PEM);
      rv < 0) {
    fprintf(stderr, "loading %s / %s: %s\n", args_.cert.c_str(), args_.key.c_str(),
            gnutls_strerror(rv));
    return false;
  }
  fd_ = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
  if (fd_ < 0) return false;
  local_.sin_family = AF_INET;
  local_.sin_port = htons(args_.port);
  local_.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(fd_, reinterpret_cast<sockaddr*>(&local_), sizeof local_) != 0) {
    fprintf(stderr, "bind 127.0.0.1:%u: %s\n", args_.port, strerror(errno));
    return false;
  }
  return true;
}

void Server::run() {
  printf("READY %u\n", args_.port);
  fflush(stdout);
  std::array<uint8_t, 65536> buf;
  for (;;) {
    pollfd pfd{fd_, POLLIN, 0};
    poll(&pfd, 1, poll_timeout_ms(now_ns()));
    for (;;) {
      sockaddr_in remote{};
      socklen_t remote_len = sizeof remote;
      ssize_t n = recvfrom(fd_, buf.data(), buf.size(), 0, reinterpret_cast<sockaddr*>(&remote),
                           &remote_len);
      if (n < 0) break;
      on_packet(buf.data(), static_cast<size_t>(n), remote, now_ns());
    }
    handle_timers(now_ns());
  }
}

void Server::on_packet(const uint8_t* data, size_t len, const sockaddr_in& remote,
                       ngtcp2_tstamp ts) {
  ngtcp2_version_cid vc;
  if (ngtcp2_pkt_decode_version_cid(&vc, data, len, kScidLen) != 0) return;
  auto it = by_cid_.find(cid_key(vc.dcid, vc.dcidlen));
  if (it == by_cid_.end()) {
    accept(data, len, remote, ts);
    return;
  }
  auto conn = it->second;
  if (!conn->read(data, len, ts) || !conn->flush(ts)) drop(conn.get());
}

void Server::accept(const uint8_t* data, size_t len, const sockaddr_in& remote,
                    ngtcp2_tstamp ts) {
  ngtcp2_pkt_hd hd;
  if (ngtcp2_accept(&hd, data, len) != 0) return;

  std::optional<std::vector<uint8_t>> odcid;
  if (hd.tokenlen > 0) {
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &remote.sin_addr, ip, sizeof ip);
    // Only the gateway's Retry tokens are trusted, and only from the gateway's addresses; the
    // server cannot check the opaque part (spec §3.6, no-shared-state mode).
    if ((hd.token[0] & 0x80) != 0 || !glassy::in_cidrs(ip, args_.trusted_cidrs)) {
      fprintf(stderr, "dropping Initial with untrusted token from %s\n", ip);
      return;
    }
    odcid = glassy::parse_nss_token({hd.token, hd.tokenlen});
    if (!odcid) {
      fprintf(stderr, "dropping Initial with malformed Retry token from %s\n", ip);
      return;
    }
    printf("retry_token_accepted odcid=%s\n", hex(odcid->data(), odcid->size()).c_str());
    fflush(stdout);
  }

  auto conn = std::make_shared<Conn>(*this, fd_, local_, remote);
  if (!conn->init(hd, odcid, ts)) return;
  owners_[conn.get()] = conn;
  by_cid_[cid_key(hd.dcid.data, hd.dcid.datalen)] = conn;
  by_cid_[cid_key(conn->scid().data, conn->scid().datalen)] = conn;
  if (!conn->read(data, len, ts) || !conn->flush(ts)) drop(conn.get());
}

void Server::drop(Conn* conn) {
  std::erase_if(by_cid_, [conn](const auto& kv) { return kv.second.get() == conn; });
  owners_.erase(conn);
}

int Server::poll_timeout_ms(ngtcp2_tstamp ts) const {
  ngtcp2_tstamp next = UINT64_MAX;
  for (const auto& [ptr, conn] : owners_) next = std::min(next, conn->expiry());
  if (next == UINT64_MAX) return 1000;
  if (next <= ts) return 0;
  return static_cast<int>(std::min<ngtcp2_tstamp>((next - ts) / NGTCP2_MILLISECONDS + 1, 1000));
}

void Server::handle_timers(ngtcp2_tstamp ts) {
  std::vector<Conn*> done;
  for (const auto& [ptr, conn] : owners_) {
    if (conn->expiry() <= ts && !conn->handle_expiry(ts)) done.push_back(ptr);
  }
  for (Conn* c : done) drop(c);
}

std::optional<Args> parse_args(int argc, char** argv) {
  Args args;
  for (int i = 1; i + 1 < argc; i += 2) {
    std::string flag = argv[i];
    std::string value = argv[i + 1];
    if (flag == "--port") {
      args.port = static_cast<uint16_t>(std::stoi(value));
    } else if (flag == "--cert") {
      args.cert = value;
    } else if (flag == "--key") {
      args.key = value;
    } else if (flag == "--trusted-cidr") {
      args.trusted_cidrs.push_back(value);
    } else if (flag == "--settings-log") {
      args.settings_log = value;
    } else {
      fprintf(stderr, "unknown flag %s\n", flag.c_str());
      return std::nullopt;
    }
  }
  if (argc % 2 == 0 || args.cert.empty() || args.key.empty()) return std::nullopt;
  return args;
}

}  // namespace

int main(int argc, char** argv) {
  auto args = parse_args(argc, argv);
  if (!args) {
    fprintf(stderr,
            "usage: s4-wt-server --port N --cert PEM --key PEM [--trusted-cidr A.B.C.D/N]... "
            "[--settings-log FILE]\n");
    return 2;
  }
  g_log.path = args->settings_log;
  Server server(std::move(*args));
  if (!server.start()) return 1;
  server.run();
}
