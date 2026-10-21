# SP0 — Kết quả các spike

- **Spec:** `docs/superpowers/specs/2026-10-21-glassy-architecture-design.md` (§11)
- **Plan:** `docs/superpowers/plans/2026-10-21-sp0-spikes.md`
- **Môi trường chạy tự động:** container Linux 6.18, 4 vCPU / 16GB, Chromium 141.0.7390.37 (Playwright 1.56.1), GnuTLS 3.8.3.

Mỗi mục gồm: **Câu hỏi / Bằng chứng / Kết luận / Việc cho sub-project sau.**

---

## S1 — WebTransport với ticket trong SNI

**Câu hỏi:** Browser có chấp nhận URL dạng hostname dài (ticket base32, 2 nhãn × 48 ký tự) kèm `serverCertificateHashes` mà **không kiểm tên trong cert** không? Gateway có đọc được SNI từ gói Initial thật của browser (ClientHello có thể trải nhiều gói, CRYPTO bị xáo thứ tự) không?

**Bằng chứng:**
- `cd spikes/web && npx playwright test s1` → **3 passed**:
  - `S1 direct`: Chromium → `s1-wt-server` (crate `wtransport`). Cert có SAN = `localhost`, còn hostname là `<ticket>.<ticket>.wt.test`. Echo được cả datagram lẫn bidi stream.
  - `S1 via gw-proto SNI`: Chromium → relay (giải mã Initial, đọc SNI, mở ticket, route) → server. Echo được cả hai.
  - `S1 capture`: bắt được 4 datagram Initial thật vào `spikes/gw-proto/tests/fixtures/chromium/`.
- `cargo nextest run -p gw-proto --test chromium_fixture --no-capture` → pass. Output:
  ```
  datagram 0: 1250 bytes, pn 1, PING PADDING PING PADDING CRYPTO@112+53 PING CRYPTO@0+51 CRYPTO@51+61 PING CRYPTO@165+217 PING PADDING PING
  client_hello_datagrams = 1
  client_hello_total_len = 382, datagrams_for_full_hello = 1
  ```

**Kết luận: ĐẠT trên Chromium 141.** Không cần dùng fallback port mapping.
- Chromium **không kiểm SAN** khi dùng `serverCertificateHashes`: cert `localhost` vẫn được chấp nhận cho hostname ticket.
- Hostname 96 ký tự (2 nhãn base32) chạy được, và ticket trong SNI được relay mở thành công.
- **Đã quan sát được "chaos protection":** frame CRYPTO trong một gói bị xáo thứ tự (@112 đứng trước @0) và xen kẽ PING/PADDING. Bộ gom theo offset xử lý đúng.
- Với bản Chromium này, ClientHello chỉ dài 382 byte và nằm gọn trong **1 datagram**: capture không có key share hậu lượng tử (ML-KEM). Khi PQ được bật, ClientHello sẽ dài khoảng 1.2KB trở lên và trải ra 2 datagram. Relay đã xử lý được trường hợp này (test `split_client_hello_two_packets_out_of_order_routes` với gói tự dựng).
- **Phát hiện về môi trường:** khi Chromium kế thừa `HTTPS_PROXY`, nó **không gửi gói UDP nào** cho WebTransport, và lỗi trả về chỉ là `Opening handshake failed`. Phải chạy với `--no-proxy-server`. Ngoài thực tế, người chơi ngồi sau proxy HTTP bắt buộc sẽ không dùng được WebTransport, nên đây thêm một lý do để giữ WebRTC làm fallback.

**Việc cho sub-project sau:**
- **SP5:** gateway parse SNI như prototype: lấy SNI ngay khi đọc được từ phần liền mạch, không cần chờ đủ ClientHello. Cần test lại với Chrome có bật ML-KEM.
- **SP4/SP5:** backend HTML5 cần phân biệt lỗi `Opening handshake failed` để chuyển sang WebRTC.
- **Chạy tay (chưa làm):**

  | Browser | Kết quả |
  |---|---|
  | Firefox | chưa chạy |
  | Safari | chưa chạy |

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

**Câu hỏi:** Game server dùng ngtcp2 + GnuTLS có hoàn tất handshake được không, khi Initial mang token Retry no-shared-state do gateway cấp và đi qua SNAT (server không thấy địa chỉ thật của client)? Chromium nói draft WebTransport nào, gửi SETTINGS và header CONNECT gì? Lớp WT tối thiểu của server cần những gì?

**Bằng chứng:**
- `cd spikes/web && npx playwright test s4` → **2 passed**:
  - `S4 direct`: Chromium → `s4-wt-server` (ngtcp2 v1.25.0, GnuTLS 3.8.3, nghttp3 v1.18.0 chỉ dùng phần QPACK). Echo được cả datagram lẫn bidi stream.
  - `S4 via gw-proto retry=always`: Chromium → relay (gửi Retry, rồi route theo SNI và SNAT) → server. Server in `retry_token_accepted odcid=<hex>` và echo được cả hai.
- SETTINGS mà Chromium 141 gửi trên control stream (lấy từ `--settings-log`):

  | ID | Giá trị | Ý nghĩa |
  |---|---|---|
  | `0x1` | 65536 | `QPACK_MAX_TABLE_CAPACITY` |
  | `0x6` | 16384 | `MAX_FIELD_SECTION_SIZE` |
  | `0x7` | 100 | `QPACK_BLOCKED_STREAMS` |
  | `0x33` | 1 | `H3_DATAGRAM` (RFC 9297) |
  | `0xffd277` | 1 | `H3_DATAGRAM` bản draft-04 (giữ để tương thích) |
  | `0x192e2742` | ngẫu nhiên | GREASE (`0x1f·N + 0x21`) |
  | `0x2b603742` | 1 | `ENABLE_WEBTRANSPORT` (**draft-02**) |

  Chromium **không** gửi `WT_MAX_SESSIONS` (`0xc671706a`, draft-07 trở đi).
- Header của request CONNECT:
  ```
  :method: CONNECT
  :protocol: webtransport
  :scheme: https
  :authority: <ticket>.<ticket>.wt.test:7103
  :path: /glassy
  origin: http://localhost:8080
  sec-webtransport-http3-draft02: 1
  ```
- Thử bỏ từng SETTING phía server (sửa tạm `kServerSettings`, chạy lại với Chromium):

  | Bỏ | Kết quả |
  |---|---|
  | `0xc671706a` (`WT_MAX_SESSIONS`) | vẫn chạy |
  | `0x08` (`ENABLE_CONNECT_PROTOCOL`) | vẫn chạy |
  | `0x33` (`H3_DATAGRAM`) | `Opening handshake failed` |
  | `0x2b603742` (`ENABLE_WEBTRANSPORT`) | `Opening handshake failed` |
  | header response `sec-webtransport-http3-draft: draft02` | vẫn chạy |

- Kiểm điều kiện tin token: chạy server với `--trusted-cidr 10.0.0.0/8` sau relay ở 127.0.0.1 → server log `dropping Initial with untrusted token from 127.0.0.1` (5 lần, mỗi lần Chromium gửi lại) và browser báo `Opening handshake failed`. Token Retry chỉ được tin khi đến từ dải của gateway.

**Kết luận: ĐẠT trên Chromium 141.**
- **Retry + SNAT hoạt động với ngtcp2.** Server chỉ đọc ODCID ở phần cleartext của token, đặt `original_dcid = ODCID` và `retry_scid = DCID của gói` vào transport params, rồi khai `token_type = NGTCP2_TOKEN_TYPE_RETRY`. Chromium kiểm 2 ID này và chấp nhận. Server không cần biết địa chỉ thật của client hay key Retry của gateway. Vậy mode no-shared-state + `trusted_gateway_cidrs` của spec §3.6 đứng vững.
- **Chromium 141 vẫn dùng WebTransport draft-02.** Phía server chỉ bắt buộc 2 SETTING: `H3_DATAGRAM` (`0x33`) và `ENABLE_WEBTRANSPORT` (`0x2b603742`). Server vẫn khai thêm `0x08` và `0xc671706a` để sẵn sàng cho browser dùng draft mới; Chromium bỏ qua 2 giá trị này.
- **QPACK chỉ cần static table.** Server khai capacity 0 (mặc định), nên request của client không dùng dynamic table, và response `:status 200` là một entry static. nghttp3 chỉ được dùng làm QPACK decoder, không dùng tầng HTTP/3 của nó.
- **Stream bidi do client mở:** chiều client → server bắt đầu bằng `0x41` + session ID; chiều trả lời **không** có prefix. Server chỉ echo phần payload. Datagram mang prefix quarter stream ID, server gửi lại nguyên vẹn.
- **Lỗi đáng nhớ của ngtcp2:** `settings.initial_ts` phải ≤ `ts` của lần `ngtcp2_conn_read_pkt` đầu tiên. Nếu lấy đồng hồ mới trong `init`, ngtcp2 dừng chương trình ở assertion `conn->log.last_ts <= ts` (đã gặp và sửa trong spike).
- Server spike dài khoảng 800 dòng C++, binary debug 1.5MB. Không cần đến tầng HTTP/3 đầy đủ.

**Việc cho sub-project sau:**
- **SP5, lớp WT tối thiểu của server SDK:**
  1. Phần QUIC: ngtcp2 + GnuTLS, ALPN `h3`, `max_datagram_frame_size > 0`. Chỉ nhận Initial có token khi token có bit 7 bằng 0 **và** nguồn nằm trong `trusted_gateway_cidrs`; đặt `original_dcid`/`retry_scid` như spike. Khi không có token, server không gửi Retry: gateway lo việc này.
  2. Phần HTTP/3: một control stream gửi SETTINGS `{0x33, 0x2b603742}` (thêm `0x08`, `0xc671706a` để tương thích về sau), hai stream QPACK rỗng; đọc SETTINGS của client, kiểm có `0x33` và `0x2b603742`.
  3. Extended CONNECT: kiểm `:protocol = webtransport`; lấy ticket từ `:authority` để đối chiếu với SNI; kiểm `origin` theo danh sách origin được phép của game; trả `:status 200`.
  4. Data plane: stream bidi (`0x41` + session ID), stream uni (`0x54` + session ID, spike chưa thử), datagram (prefix quarter stream ID).
  5. Spike chưa làm: capsule `CLOSE_WEBTRANSPORT_SESSION`, ánh xạ mã lỗi reset stream của WT, stream do server mở, GOAWAY, giới hạn số session/stream. Chưa thử Retry khi ClientHello trải 2 datagram (PQ); relay đã có unit test cho trường hợp này.
- **SP4:** client HTML5 nên coi draft-02 là mặc định. Khi Chromium chuyển sang draft mới (gửi `0xc671706a`, bỏ `sec-webtransport-http3-draft02`), server phải hỗ trợ cả hai trong giai đoạn chuyển tiếp.
- **Chạy tay (chưa làm):**

  | Browser | Kết quả |
  |---|---|
  | Firefox | chưa chạy |
  | Safari | chưa chạy |

---

## S5 — Interface `FleetManager` của Nakama

_Chưa chạy._
