// S2 spike server: ICE-lite WebRTC data-channel echo without a signaling server (spec §3.5).
//
// A browser builds the server's SDP answer itself from ConnectInfo. The first thing this server
// ever sees from a client is a STUN binding request with an unknown ufrag; that request is enough
// to synthesize the client's offer and create the PeerConnection on the fly.

#include <rtc/rtc.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "ice_pwd.hpp"

namespace {

struct Args {
  uint16_t port = 7101;
  std::array<uint8_t, 32> k_gs{};
  std::string cert;
  std::string key;
};

std::array<uint8_t, 32> parse_hex32(const std::string& hex) {
  if (hex.size() != 64) {
    throw std::invalid_argument("--k-gs must be 64 hex chars");
  }
  std::array<uint8_t, 32> out{};
  for (size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<uint8_t>(std::stoi(hex.substr(i * 2, 2), nullptr, 16));
  }
  return out;
}

Args parse_args(int argc, char** argv) {
  Args a;
  for (int i = 1; i + 1 < argc; i += 2) {
    const std::string flag = argv[i];
    const std::string value = argv[i + 1];
    if (flag == "--port") {
      a.port = static_cast<uint16_t>(std::stoi(value));
    } else if (flag == "--k-gs") {
      a.k_gs = parse_hex32(value);
    } else if (flag == "--cert") {
      a.cert = value;
    } else if (flag == "--key") {
      a.key = value;
    } else {
      throw std::invalid_argument("unknown flag " + flag);
    }
  }
  if (a.cert.empty() || a.key.empty()) {
    throw std::invalid_argument("--cert and --key are required");
  }
  return a;
}

// The browser's real offer never reaches us, so this stand-in carries only the client's ICE
// credentials. Clients munge their offer so that ice-pwd == ice-ufrag (the libp2p WebRTC-Direct
// convention); libjuice is a full ICE agent and its own checks need the client's password. The
// DTLS fingerprint is a placeholder because fingerprint verification is disabled; clients
// authenticate later with the server ticket on the reliable channel.
std::string synthesized_offer(const std::string& remote_ufrag) {
  return "v=0\r\n"
         "o=- 0 0 IN IP4 0.0.0.0\r\n"
         "s=-\r\n"
         "t=0 0\r\n"
         "a=group:BUNDLE 0\r\n"
         "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
         "c=IN IP4 0.0.0.0\r\n"
         "a=mid:0\r\n"
         "a=ice-ufrag:" +
         remote_ufrag +
         "\r\n"
         "a=ice-pwd:" +
         remote_ufrag +
         "\r\n"
         "a=fingerprint:sha-256 "
         "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:"
         "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00\r\n"
         "a=setup:active\r\n"
         "a=sctp-port:5000\r\n"
         "a=max-message-size:262144\r\n";
}

void echo_on(const std::shared_ptr<rtc::DataChannel>& dc) {
  std::weak_ptr<rtc::DataChannel> weak = dc;
  dc->onMessage([weak](rtc::message_variant msg) {
    if (auto ch = weak.lock()) {
      ch->send(std::move(msg));
    }
  });
}

// RFC 8839 §5.4: ice-ufrag is 4 to 256 ice-chars (ALPHA / DIGIT / "+" / "/").
bool valid_ice_ufrag(const std::string& ufrag) {
  if (ufrag.size() < 4 || ufrag.size() > 256) {
    return false;
  }
  return std::all_of(ufrag.begin(), ufrag.end(), [](char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           c == '+' || c == '/';
  });
}

struct Session {
  std::shared_ptr<rtc::PeerConnection> pc;
  std::shared_ptr<rtc::DataChannel> reliable;
  std::shared_ptr<rtc::DataChannel> unreliable;
};

}  // namespace

int main(int argc, char** argv) {
  Args args;
  try {
    args = parse_args(argc, argv);
  } catch (const std::exception& e) {
    std::cerr << "usage: s2-webrtc-server --port N --k-gs HEX64 --cert PEM --key PEM (" << e.what()
              << ")\n";
    return 2;
  }
  // GLASSY_LOG=debug turns on libdatachannel/libjuice debug logs for spike investigations.
  const char* log_env = std::getenv("GLASSY_LOG");
  rtc::InitLogger(log_env && std::string(log_env) == "debug" ? rtc::LogLevel::Debug
                                                             : rtc::LogLevel::Warning);

  std::mutex mu;
  std::map<std::string, Session> sessions;  // keyed by "<server ufrag>:<client ufrag>"

  rtc::IceUdpMuxListener listener(args.port);
  listener.OnUnhandledStunRequest([&](rtc::IceUdpMuxRequest req) {
    // Runs on libjuice's C thread with unauthenticated input: validate first, and never let an
    // exception escape into C frames (CONVENTIONS §4), or one bad packet aborts the server.
    if (!valid_ice_ufrag(req.localUfrag) || !valid_ice_ufrag(req.remoteUfrag)) {
      std::cerr << "dropping STUN with an invalid ufrag from " << req.remoteAddress << ":"
                << req.remotePort << "\n";
      return;
    }
    try {
      const std::string key = req.localUfrag + ":" + req.remoteUfrag;
      std::lock_guard lock(mu);
      if (sessions.contains(key)) {
        return;
      }
      std::cerr << "new session from " << req.remoteAddress << ":" << req.remotePort << "\n";

      rtc::Configuration config;
      config.enableIceUdpMux = true;
      config.portRangeBegin = args.port;
      config.portRangeEnd = args.port;
      config.disableFingerprintVerification = true;
      // Otherwise setRemoteDescription() answers immediately with random ICE credentials and the
      // explicit answer below (carrying the derived ufrag/pwd) throws in signaling state "stable".
      config.disableAutoNegotiation = true;
      config.certificatePemFile = args.cert;
      config.keyPemFile = args.key;

      Session s;
      s.pc = std::make_shared<rtc::PeerConnection>(config);
      s.pc->onStateChange([key](rtc::PeerConnection::State state) {
        std::cerr << "session " << key.substr(0, 12) << "... state " << state << "\n";
      });
      s.pc->setRemoteDescription(
          rtc::Description(synthesized_offer(req.remoteUfrag), rtc::Description::Type::Offer));
      s.pc->addRemoteCandidate(rtc::Candidate("candidate:1 1 UDP 1 " + req.remoteAddress + " " +
                                                  std::to_string(req.remotePort) + " typ host",
                                              "0"));

      rtc::DataChannelInit reliable_init;
      reliable_init.negotiated = true;
      reliable_init.id = 0;
      s.reliable = s.pc->createDataChannel("reliable", reliable_init);
      echo_on(s.reliable);

      rtc::DataChannelInit unreliable_init;
      unreliable_init.negotiated = true;
      unreliable_init.id = 1;
      unreliable_init.reliability.unordered = true;
      unreliable_init.reliability.maxRetransmits = 0;
      s.unreliable = s.pc->createDataChannel("unreliable", unreliable_init);
      echo_on(s.unreliable);

      s.pc->setLocalDescription(
          rtc::Description::Type::Answer,
          rtc::LocalDescriptionInit{.iceUfrag = req.localUfrag,
                                    .icePwd = glassy::ice_pwd(args.k_gs, req.localUfrag)});
      sessions.emplace(key, std::move(s));
    } catch (const std::exception& e) {
      std::cerr << "dropping STUN from " << req.remoteAddress << ":" << req.remotePort << ": "
                << e.what() << "\n";
    }
  });

  std::cout << "READY" << std::endl;
  for (;;) {
    std::this_thread::sleep_for(std::chrono::hours(1));
  }
}
