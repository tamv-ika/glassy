# SP0 — Kết quả các spike

- **Spec:** `docs/superpowers/specs/2026-10-21-glassy-architecture-design.md` (§11)
- **Plan:** `docs/superpowers/plans/2026-10-21-sp0-spikes.md`
- **Môi trường chạy tự động:** container Linux 6.18, 4 vCPU / 16GB, Chromium 141.0.7390.37 (Playwright 1.56.1), GnuTLS 3.8.3.

Mỗi mục gồm: **Câu hỏi / Bằng chứng / Kết luận / Việc cho sub-project sau.**

---

## S1 — WebTransport với ticket trong SNI

_Chưa chạy._

---

## S2 — WebRTC không signaling (ticket trong ICE ufrag)

**Câu hỏi:** Browser có chấp nhận một SDP answer do chính nó dựng (`ice-lite`, ufrag dài 80 ký tự, data channel `negotiated`) không? libdatachannel có tạo được PeerConnection ngay khi nhận một STUN có ufrag lạ, với ufrag/pwd do mình đặt và tắt kiểm fingerprint không? Gateway có route được theo ticket trong ufrag không?

**Bằng chứng:**
- `cd spikes/web && npx playwright test s2` → **2 passed**:
  - `S2 direct`: browser nói chuyện thẳng với `s2-webrtc-server`;
  - `S2 via gw-proto`: browser → relay (route theo ticket trong ufrag, có SNAT) → server.
- Cả hai test đều echo được trên channel reliable lẫn unreliable.
- Server dùng libdatachannel v0.24.6 build với **GnuTLS 3.8.3**.

**Kết luận: ĐẠT trên Chromium**, nhưng phải thêm 2 điều chỉnh so với spec §3.5:
1. **Server phải bật `disableAutoNegotiation = true`.** Nếu không, `setRemoteDescription()` sẽ tự sinh answer với ICE credential ngẫu nhiên, và lệnh `setLocalDescription(Answer, {ufrag, pwd})` theo sau ném `logic_error` ở trạng thái `stable`, làm crash cả server.
2. **Client phải sửa offer của chính nó để `ice-pwd = ice-ufrag`** (chuỗi ngẫu nhiên 32 ký tự). Đây là quy ước của libp2p WebRTC-Direct. Lý do: libjuice là một ICE agent đầy đủ, không phải ICE-lite thật, nên nó tự gửi check ngược về browser. Check đó bị browser trả **401** nếu server không biết pwd của client. Với quy ước này, server đọc ufrag của client trong STUN `USERNAME` là suy ra được pwd.

Các điểm khác đã được xác nhận:
- **ufrag 80 ký tự được chấp nhận** bởi cả Chromium lẫn libjuice.
- ICE pwd dẫn xuất bằng HMAC từ `K_gs` khớp nhau giữa Rust (broker) và C++ (server); browser xác thực STUN thành công.
- Relay SNAT không làm hỏng ICE/DTLS: server chỉ thấy địa chỉ upstream của gateway.

**Việc cho sub-project sau:**
- **Cập nhật spec §3.5:** thêm bước client đặt `ice-pwd = ice-ufrag`, và yêu cầu `disableAutoNegotiation` ở server.
- **SP4:** backend HTML5 của client SDK phải sửa SDP local. Rủi ro: Chrome có thể siết việc sửa SDP local trong tương lai. libp2p đang phụ thuộc vào cùng hành vi này, nên cần theo dõi.
- **Bảo mật:** pwd của client là công khai (nằm trong `USERNAME`), nên check từ server về client không được xác thực bằng bí mật. Chấp nhận được, vì browser xác thực server qua DTLS fingerprint, còn server xác thực client bằng server ticket gửi trong channel reliable.
- **Chạy tay (chưa làm):**

  | Browser | Kết quả |
  |---|---|
  | Firefox | chưa chạy |
  | Safari | chưa chạy |

---

## S3 — Khả năng XDP/AF_XDP của ENA

_Chưa chạy._

---

## S4 — ngtcp2 + GnuTLS nhận token Retry qua SNAT, phiên bản draft WT của browser

_Chưa chạy._

---

## S5 — Interface `FleetManager` của Nakama

_Chưa chạy._
