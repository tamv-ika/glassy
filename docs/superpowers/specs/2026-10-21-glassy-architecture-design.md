# glassy — Kiến trúc tổng thể (SP0)

- **Ngày:** 2026-10-21
- **Trạng thái:** Draft, chờ review
- **Phạm vi:** spec kiến trúc và hợp đồng giữa các thành phần. Chi tiết bên trong từng thành phần nằm ở spec của sub-project tương ứng (SP1–SP7).

---

## 0. Bối cảnh và mục tiêu

### 0.1 Bài toán

Cần một gateway (tương tự Quilkin) đứng giữa người chơi và game server dedicated do **Agones** allocate. Gateway nhận 3 loại traffic:

| Client | Transport |
|---|---|
| Defold native (PC, mobile) | UDP thuần, dùng protocol riêng của glassy |
| Defold HTML5 (WASM trong browser) | **WebTransport** (mặc định) hoặc **WebRTC data channel** (fallback) |

- Game server viết bằng **C++** để dùng chung thư viện simulator (vật lý, game simulation) với client.
- Matchmaking dùng **Nakama**; allocate game server qua **Agones**.
- Chạy trên **Kubernetes bất kỳ** có Agones (k8s tự dựng, k3s, EKS, GKE…), trên **AWS, GCP và bare metal**. Trước mắt là **k8s/k3s tự host trên EC2** (không dùng EKS, để tiết kiệm chi phí).

### 0.2 Mục tiêu hiệu năng (mỗi node gateway)

| Chỉ số | Mục tiêu |
|---|---|
| Session đồng thời | ~50k |
| Throughput fast path (Mode X) | ≥ 1 Mpps trên ≤ 2 vCPU |
| Latency cộng thêm p99 | < 50µs (Mode X/XA), < 200µs (Mode K) |
| Memory | < 256MB khi có 50k session |
| So với Quilkin | không thua ở cặp mode tương đương (xem §10) |

### 0.3 Mục tiêu chức năng

- Gateway hỗ trợ cả kernel stack (Mode K) lẫn kernel bypass bằng XDP + AF_XDP (Mode X, XA, A). Mode được **tự chọn bằng capability detector**.
- Gateway **không giải mã** QUIC hay DTLS (passthrough L4). Payload native được **mã hoá end-to-end** giữa client và game server.
- Ứng dụng game chỉ làm việc với lớp **Session/Channel**, không cần biết client dùng transport nào.
- Client SDK native nhỏ nhất có thể: chỉ có UDP, mục tiêu ≤ 150KB.

### 0.4 Ngoài phạm vi MVP

- IPv6 phía client (cần dịch header IPv6 ↔ IPv4).
- Nhiều cluster hoặc nhiều region dùng chung gateway. Đã chừa sẵn chỗ mở rộng qua `Provider` (§5.1).
- Fallback qua TCP cho mạng chặn UDP.
- Console (PS5, Switch, Xbox). Thiết kế C++ không chặn hướng này, nhưng chưa làm.
- Gateway học lại flow khi client đổi 5-tuple. Thay vào đó dùng **reconnect tường minh** (§3.7).

---

## 1. Các quyết định chính

| # | Quyết định | Lý do chính |
|---|---|---|
| D1 | **Passthrough L4**: gateway không giải mã QUIC/DTLS | fast path chạy được trọn trong XDP, CPU thấp, gateway không giữ TLS key |
| D2 | **Gateway là một edge tier riêng**; game server nằm trong subnet private | một entry point duy nhất, ẩn IP game server, chặn DDoS ở rìa |
| D3 | Server SDK có **3 transport + lớp Session/Channel**. Client native chỉ có UDP; HTML5 dùng API của browser | binary client nhỏ nhất; app không phải biết transport |
| D4 | Native UDP **luôn mã hoá E2E** (AEAD, kiểu netcode.io) | ngang mức bảo mật của WebRTC/WT; chống cướp session và chèn gói |
| D5 | **Gateway và control plane viết bằng Rust**; **core và SDK viết bằng C++**; wire format chốt bằng **spec + golden test vectors** (không dùng FFI) | parser ở edge được memory-safe; Defold extender tự biên dịch C++; console vẫn khả thi; phần parse dùng chung giữa gateway và SDK rất nhỏ |
| D6 | **Routing ticket nằm trong gói mở đầu, sau đó route bằng flow 5-tuple** (khác Quilkin, vốn gắn token vào mọi gói) | browser không thể gắn byte vào gói DTLS/QUIC; ticket có AEAD và hạn dùng; không có race với control plane |
| D7 | Vị trí ticket theo transport: native → gói `CONNECT`; WebRTC → **server ICE ufrag**; WebTransport → **SNI** (fallback: mỗi game server một port) | chỉ dùng những chỗ protocol cho phép gắn dữ liệu |
| D8 | WebTransport: **gateway làm QUIC Retry offload** ở mode **no-shared-state** (draft-ietf-quic-retry-offload). Game server chỉ tin token Retry khi gói đến từ `trusted_gateway_cidrs` | chặn Initial giả IP ở edge. Mode shared-state **không dùng được**: token bị ràng buộc vào IP client, nhưng sau SNAT game server chỉ thấy IP gateway, và gateway không sửa được token vì header Initial được AEAD bảo vệ |
| D9 | **Không học lại flow**; khi client đổi IP/port thì **reconnect tường minh** bằng ticket cũ, và game server **resume** session theo `session_id` | ít logic; gói data từ địa chỉ lạ bị XDP drop, nên chống DDoS tốt hơn |
| D10 | **`server_id` = UID của GameServer** (16 byte) | không cần bộ cấp ID, không cần leader |
| D11 | Gateway lấy cấu hình qua trait **`Provider`**; MVP chỉ có **`K8sProvider`** watch trực tiếp `GameServer` và `Secret` | không cần xDS hay distributor ở MVP; sau này mở rộng sang xDS hoặc gossip mà không phải đổi data plane |
| D12 | `glassy-control` = **broker stateless**: allocate qua Agones, mint ticket | không có leader; N replica |
| D13 | Tích hợp Nakama qua **`FleetManager` (Go plugin)** gọi gRPC sang broker | điểm tích hợp chính thức của Nakama; crypto chỉ nằm ở Rust và C++ |
| D14 | Gateway → game server dùng **SNAT, mỗi flow một upstream port** | game server nhận UDP chuẩn, nên `libdatachannel` và `ngtcp2` chạy nguyên bản |
| D15 | Server SDK: WebRTC dùng **libdatachannel**; WebTransport dùng **ngtcp2 + lớp HTTP/3 + WT tự viết**; TLS mặc định là **GnuTLS** dùng chung cho QUIC và DTLS | ngtcp2 cho app kiểm soát token Retry (bắt buộc với D8); tự chủ theo kịp phiên bản draft WT của browser |
| D16 | 4 data plane mode **K / X / XA / A**, chọn bằng capability detector; **XA là mặc định trên AWS** nếu máy cho phép | XDP xử lý fast path ngay trong kernel; AF_XDP xử lý slow path khi bị flood; A tương đương Quilkin để benchmark |
| D17 | **Portable mặc định:** chỉ dựa vào những gì cluster k8s nào cũng có. Gateway gửi tới **`nodeIP:hostPort`** (Agones `portPolicy: Dynamic`); gateway là DaemonSet `hostNetwork` trên node có IP public; không dùng LoadBalancer của cloud. Gửi thẳng tới pod IP chỉ là tối ưu tuỳ chọn | chạy được trên k8s/k3s/EKS/GKE và AWS/GCP/bare metal mà không phải sửa code; khác biệt giữa các môi trường chỉ nằm ở capability detector và cấu hình |

---

## 2. Kiến trúc tổng thể

```
                      ┌──────────────── control plane ─────────────────┐
 Nakama ──gRPC──▶ glassy-control (Rust, broker stateless, N replica)   │
 [glassy-nakama:  │  Allocate / Join / Get / List / Delete             │
  FleetManager Go]│  → Agones GameServerAllocation (k8s API)           │
                  │  → mint routing ticket + server ticket             │
                  └────────────────────────────────────────────────────┘
                                   k8s API (watch GameServer, Secret)
                                              │
 Client ═══ UDP :443 ═══▶ glassy-gateway (Rust + eBPF, edge node, EIP) ═══▶ GameServer pods (C++)
  native: client SDK UDP     │ XDP fast path / slow path                  │ glassy-sdk-server
  HTML5:  WT / WebRTC        │ Mode K / X / XA / A (tự detect)            │ UDP / WebRTC / WT
         (browser)           │ K8sProvider → bảng GS, K_gw               │ → Session / Channel
```

### 2.1 Các thành phần

| Thành phần | Ngôn ngữ | Biết gì | Không biết gì |
|---|---|---|---|
| `glassy-gateway` | Rust + eBPF (aya) | `K_gw`, `K_retry_gw`, bảng GS | session key, payload game |
| `glassy-control` (broker) | Rust | `K_gw`, `K_gs`, Agones API | traffic game |
| `glassy-nakama` | Go | gRPC client gọi broker | format ticket, crypto |
| `glassy-sdk-server` | C++ | `K_gs` của fleet, session key, cert DTLS và WT | `K_gw` |
| `glassy-sdk-client` | C++ (+ JS glue cho HTML5) | session key của chính nó | mọi key hệ thống |
| `glassy-proto` | spec + golden vectors; implement bằng Rust (gateway, broker) và C++ (SDK) | là hợp đồng chung | — |

### 2.2 Một port public, tách loại gói theo byte đầu tiên

Gateway nhận **mọi transport trên UDP 443**, tách loại gói mở đầu theo byte đầu tiên (theo tinh thần RFC 9443):

| Byte đầu | Loại |
|---|---|
| `0x00–0x03` | STUN (WebRTC) |
| `0x14–0x3F` | DTLS (chỉ đi theo flow đã có) |
| `0x40–0x7F` | QUIC short header (chỉ đi theo flow đã có) |
| `0x80–0xBF` | **native protocol của glassy** |
| `0xC0–0xFF` | QUIC long header (Initial của WT) |

- Dải `0x80–0xBF` dùng được vì glassy không dùng RTP/RTCP, và game server **không** khai báo `grease_quic_bit`, nên browser không làm biến đổi fixed bit của QUIC.
- Game server **mở port riêng cho từng transport** (vì `libdatachannel` tự quản lý socket). Bảng GS lưu port của từng transport.

### 2.3 Các sub-project và thứ tự

| # | Sub-project | Kết quả |
|---|---|---|
| SP0 | Spec này + các spike ở §11 | hợp đồng giữa các thành phần |
| SP1 | `glassy-proto`: spec wire format, golden vectors, crate Rust, lib C++ | |
| SP2 | **MVP native UDP end-to-end**: broker, gateway Mode K, `glassy-nakama`, server SDK (UDP), client SDK native | chơi được trên PC/mobile |
| SP3 | Fast path XDP (Mode X) + capability detector trên AWS ENA | |
| SP4 | WebRTC: slow path STUN ở gateway, transport WebRTC ở server SDK, backend HTML5 | |
| SP5 | WebTransport: slow path QUIC (Retry, đọc SNI) ở gateway, ngtcp2 + HTTP/3 + WT ở server SDK, backend HTML5 | |
| SP6 | AF_XDP (Mode XA, A) + tăng cường chống DDoS | |
| SP7 | GCP (gVNIC) và bare metal (mlx5, ice) | |

Mỗi sub-project đi qua một vòng spec → plan → implement riêng.

---

## 3. Luồng connect, ticket và key

### 3.1 Key

| Key | Ai giữ | Dùng cho | Xoay vòng |
|---|---|---|---|
| `K_gw` | broker, gateway | mã hoá routing ticket bằng **AES-128-GCM** | key ring có `key_id` 1 byte; gateway chấp nhận key hiện tại và key trước đó |
| `K_gs[fleet]` | broker, game server của fleet đó (k8s Secret mount vào pod) | mã hoá server ticket bằng **ChaCha20-Poly1305 (RFC 8439)**; dẫn xuất ICE pwd | có `key_id`; server SDK đọc lại file khi Secret thay đổi |
| `K_retry_gw` | **chỉ gateway** | xác thực phần opaque của token Retry no-shared-state (HMAC-SHA256) | gateway tự sinh và tự xoay; chấp nhận key hiện tại và trước đó |
| Session key `c2s` / `s2c` | client, game server | mã hoá E2E cho native UDP | mỗi session một cặp, broker sinh ngẫu nhiên 32 byte |
| Cert DTLS | game server tự sinh | fingerprint SHA-256 trong SDP | sinh khi khởi động |
| Cert WT (ECDSA P-256, hạn ≤ 14 ngày) | game server tự sinh | `serverCertificateHashes` | game server sống quá ~13 ngày thì tự sinh lại và cập nhật annotation |

Toàn bộ key lưu trong k8s Secret. Xoay key bằng cách cập nhật Secret: `K8sProvider` của gateway và server SDK tự đọc lại.

### 3.2 Routing ticket (gateway đọc)

```
RoutingTicket = ver(1) | key_id(1) | nonce(12) | AES-128-GCM_K_gw( body ) | tag(16)
body          = server_id(16 = GameServer UID) | session_id(8) | expiry(4, unix giây)
              | transports(1, bitmask) | flags(1)
→ tổng cộng khoảng 60 byte
```

| Transport | Cách encode | Độ dài |
|---|---|---|
| Native | nguyên byte trong `CONNECT` | 60 byte |
| WebRTC | **server ICE ufrag** = base64 không padding (ice-char là `A-Za-z0-9+/`) | ~80 ký tự (giới hạn 4–256, RFC 8839) |
| WebTransport | **nhãn SNI** = base32 chữ thường (`a-z2-7`), chia thành 2 nhãn DNS ≤ 63 ký tự | ~96 ký tự + domain |

- **Cấp theo từng player** cho cả 3 transport.
- **Hạn dùng = thời lượng trận + một khoảng dự phòng**, để reconnect không phải gọi lại Nakama.
- Gateway kiểm tra: AEAD hợp lệ, `key_id` đã biết, chưa hết hạn, transport của gói nằm trong `transports`, `session_id` khớp header (với native), và `server_id` **có trong bảng GS ở trạng thái route được** (§5.2).

### 3.3 Server ticket (game server đọc)

```
ServerTicket = ver(1) | key_id(1) | nonce(24) | XChaCha20-Poly1305_K_ticket( body ) | tag(16)
K_ticket     = HKDF-SHA256(ikm = K_gs, salt = rỗng, info = "glassy-server-ticket", L = 32)
body         = user_id_len(1) | user_id(1..64) | server_id(16) | session_id(8) | expiry(4) | transport(1)
             | [key_c2s(32) | key_s2c(32)]   (chỉ native)
             | metadata_len(u16) | metadata(≤256, do Nakama truyền xuống)
```

Đổi so với bản đầu (SP1, §3.2 của spec SP1): thêm `ver` và `server_id` (ticket chỉ hợp lệ trên đúng game server được cấp); XChaCha20-Poly1305 với nonce 24 byte; `K_gs` không dùng trực tiếp mà dẫn xuất `K_ticket` bằng HKDF; **mỗi player có một server ticket cho mỗi transport** (key native chỉ nằm trong ticket native). Chi tiết byte và thứ tự kiểm tra: `docs/superpowers/specs/2026-10-23-sp1-glassy-proto-design.md` §3.2.

| Transport | Server ticket đi tới game server bằng cách nào |
|---|---|
| Native | nằm trong `CONNECT` |
| WebRTC | message đầu tiên trên channel reliable, **bên trong DTLS** |
| WebTransport | nằm trong path của request extended CONNECT (`/glassy?t=<base64url>`), **bên trong TLS** |

Với WebRTC và WT, ticket nằm trong kênh đã mã hoá nên không bị sniff được. Do đó không cần thêm proof.

### 3.4 Native UDP

**Các loại gói** (byte đầu nằm trong dải `0x80–0xBF`; giá trị chốt ở SP1: `0x80` `CONNECT`, `0x81` `ACCEPT`, `0x82` `DATA`, `0x83` `DISCONNECT`, `0x84` `REJECT`, còn lại reserved, drop):

| Loại | Hướng | Nội dung |
|---|---|---|
| `CONNECT` | C→S | `ver`, `session_id`, `conn_id` (ngẫu nhiên, mỗi lần gửi một giá trị mới), `connect_seq`, routing ticket, server ticket, `proof_tag` (tag AEAD_c2s của plaintext rỗng, nonce `conn_id|0⁸`), padding |
| `ACCEPT` | S→C | `server_nonce` (16 byte, server sinh mới cho mỗi `ACCEPT`/`REJECT`) + `AEAD_s2c(...)`; AAD ràng buộc `conn_id`; **kích thước cố định 59 byte < `CONNECT`** (không thể bị dùng để khuếch đại) |
| `DATA` | hai chiều | header `type | session_id(8) | pn_low(4)` + `AEAD(frames)`, AAD = header (13 byte). **Keepalive = `DATA` không có frame** |
| `DISCONNECT` | hai chiều | `type | session_id(8) | pn_low(4)` + `AEAD(reason)` |
| `REJECT` | S→C | `connect_seq`, `server_nonce` + `AEAD_s2c(reason | last_connect_seq)`; kích thước cố định 58 byte; chỉ gửi sau khi `CONNECT` qua toàn bộ kiểm tra crypto |

```
client ──CONNECT──▶ gateway (slow path)
   kiểm routing ticket → server_id → tra bảng GS → cấp upstream port → tạo flow CHƯA XÁC NHẬN
   forward CONNECT + gắn thêm trailer client_addr (để game server biết IP thật của client)
GS: bóc trailer → giải mã server ticket → lấy session key → kiểm proof_tag
    (`connect_seq` phải lớn hơn hẳn giá trị đã chấp nhận gần nhất của session, không so với đồng hồ thật) → ACCEPT,
    hoặc REJECT (ví dụ `stale_connect_seq`, kèm `last_connect_seq` để client nhảy lên trên)
gateway: thấy có gói đi chiều về → flow ĐÃ XÁC NHẬN
DATA: route theo 5-tuple trong fast path, không cần giải mã gì
```

- Nonce AEAD 24 byte = `server_nonce(16) | pn(u64 BE)`; `pn` là bộ đếm riêng mỗi chiều và mỗi kết nối, trên wire chỉ gửi 4 byte thấp (bên nhận dựng lại theo RFC 9000 A.3). Cùng một `pn` dùng cho AEAD, chống replay (cửa sổ 256) và ack.
- AEAD mặc định: XChaCha20-Poly1305 (nonce 24 byte), Monocypher ở cả client và server.
- Hành vi session (tombstone, kết nối ứng viên, rate limit `REJECT`) thuộc SP2; xem §4.7 của spec SP1.

### 3.5 WebRTC (không cần signaling server)

**Phía client (JS trong backend HTML5):**
1. Tạo `RTCPeerConnection` và 2 data channel `negotiated: true` với id cố định:
   - `reliable`: ordered, reliable;
   - `unreliable`: `ordered: false`, `maxRetransmits: 0`.
2. `createOffer()`, **sửa offer để `ice-pwd` = `ice-ufrag`** (chuỗi ngẫu nhiên 32 ký tự, giống quy ước của libp2p WebRTC-Direct), rồi `setLocalDescription()` với offer đã sửa. Nhờ vậy server suy ra được pwd của client từ `USERNAME` và trả lời được các check ICE (spike S2).
3. **Tự dựng SDP answer từ ConnectInfo**: `a=ice-lite`, `ice-ufrag` = routing ticket (base64), `ice-pwd`, `fingerprint` của cert DTLS game server, `setup:passive`, candidate = các IP gateway `:443/udp`, `sctp-port`, `max-message-size`. Rồi `setRemoteDescription()`.
4. Browser gửi STUN binding request tới `gateway:443` với `USERNAME = <server_ufrag>:<client_ufrag>`.

**Gateway:** parse STUN → lấy phần trước dấu `:` → base64 decode → kiểm routing ticket → tạo flow → forward tới port WebRTC của game server.

**Game server** (libdatachannel, mux nhiều kết nối trên một port; answer khai `a=ice-lite` nhưng libjuice thực chất là ICE agent đầy đủ):
- Khi nhận STUN có ufrag lạ: tạo PeerConnection mới. Local ufrag = ufrag trong `USERNAME`; local pwd = `base64(HMAC-SHA256(HKDF(K_gs, "glassy-ice"), ufrag))` (≥ 22 ký tự).
- Client ufrag lấy từ `USERNAME`, và **pwd của client = ufrag của client** (bước 2 ở trên). Lý do: libjuice là ICE agent đầy đủ nên tự gửi check về browser; browser trả 401 nếu check không mang đúng pwd của client.
- Bật `disableAutoNegotiation`: server tự dựng offer của phía browser rồi `setRemoteDescription`, sau đó `setLocalDescription(Answer, {ufrag, pwd})`. Nếu không bật, libdatachannel tự sinh answer với credential ngẫu nhiên và lệnh đặt answer sau đó ném `logic_error` (spike S2).
- **Chỉ tạo PeerConnection sau khi kiểm MESSAGE-INTEGRITY** của binding request bằng pwd dẫn xuất. libjuice gọi callback cho mọi binding request có MESSAGE-INTEGRITY mà không kiểm nó, và một PeerConnection mới sẽ gửi check ICE về địa chỉ khai báo: spike S2 đo được khuếch đại 6.2 lần. Mỗi server ufrag chỉ một PeerConnection, session cũ bị evict. ufrag phải hợp lệ theo RFC 8839, và callback không được ném exception qua C (một gói sai dạng từng làm sập server spike).
- **Tắt kiểm fingerprint của client.** Client được xác thực bằng server ticket gửi trên channel `reliable`. pwd của client là công khai (nằm trong `USERNAME`), nên check từ server về client không dựa vào bí mật; browser vẫn xác thực server qua DTLS fingerprint.
- Cách làm này giống libp2p WebRTC-Direct. Spike S2 đã kiểm chứng với libdatachannel v0.24.6 (GnuTLS) và Chromium 141: `IceUdpMuxListener`, callback `OnUnhandledStunRequest`, `LocalDescriptionInit` để đặt ufrag/pwd, `disableFingerprintVerification`. ufrag 80 ký tự được chấp nhận.

**Đổi mạng:** tạo `RTCPeerConnection` mới với **cùng** ConnectInfo (ticket vẫn còn hạn). ICE, DTLS và SCTP chạy lại; game server resume session bằng server ticket.

### 3.6 WebTransport

**Phía client:**
```js
new WebTransport("https://<b32-ticket-1>.<b32-ticket-2>.wt.<domain>/glassy?t=<server_ticket>",
                 { serverCertificateHashes: [{ algorithm: "sha-256", value: H }] })
```
- DNS: wildcard `*.wt.<domain>` (nhà cung cấp DNS bất kỳ, §5.5) → IP public của các gateway.
- Channel `unreliable` → datagram; channel `reliable` → một bidi stream, mỗi message có prefix độ dài.

**Gateway (slow path):**
```
Initial #1 (token rỗng)  → gửi Retry: SCID = RSCID ngẫu nhiên; token no-shared-state =
                            0|ODCIL (1 byte) | ODCID (cleartext) | expiry (8) |
                            HMAC-SHA256_K_retry_gw(byte đầu | ODCID | expiry | IP client | port client | RSCID)[0..16]
                            (chưa parse SNI, nên chi phí rất thấp)
Initial #2.. (có token)  → kiểm token → giải mã Initial (key dẫn xuất từ DCID theo RFC 9001 §5.2)
                          → gom các frame CRYPTO (tối đa 2 gói hoặc 100ms; xử lý được thứ tự bị xáo
                            do "chaos protection" của Chrome và ClientHello có key share ML-KEM dài)
                          → đọc SNI → bỏ phần đuôi domain → base32 decode → kiểm routing ticket
                          → tạo flow → forward các gói đã buffer (giữ nguyên token) tới port WT của game server
```
- **Retry mặc định luôn bật** (cấu hình `always` / `never`). Không làm chế độ bật tự động theo tải, để tránh "transition mode".
- **Bất biến của gateway:** token loại Retry (bit đầu 0) được kiểm ở **cả hai** mode; token không do gateway phát thì drop, vì game server tin mọi token như vậy đến từ gateway. Gateway chỉ xử lý (và chỉ gửi Retry cho) Initial nằm trong datagram ≥ 1200 byte, có DCID 8–20 byte, CID ≤ 20 byte, để Retry không bao giờ lớn hơn gói kích hoạt nó.
- **Game server (ngtcp2):** token có bit đầu = 0 **và** gói đến từ một IP thuộc `trusted_gateway_cidrs` → **không kiểm token** (đúng yêu cầu của mode no-shared-state), coi như địa chỉ đã được xác thực, đặt `retry_source_connection_id` = DCID của gói, `original_destination_connection_id` = ODCID lấy từ token. Gói mang token nhưng đến từ nguồn khác thì bị drop. Spike S4 đã kiểm chứng với ngtcp2 v1.25.0 + GnuTLS: Chromium chấp nhận transport params này, kể cả khi đi qua gateway có SNAT.
- Mode no-shared-state đòi hỏi **gateway nằm trên mọi đường vào game server**, nên firewall chặn truy cập trực tiếp vào game server là **bắt buộc** khi bật WebTransport (§5.5). `trusted_gateway_cidrs` là lớp phòng thủ thứ hai khi firewall cấu hình sai.
- **Fallback port mapping** (mỗi game server một port trên gateway, route theo dst port) **không cần dùng**: spike S1 đạt trên Chromium 141. Chromium không kiểm SAN khi dùng `serverCertificateHashes`, và gateway đọc SNI ngay khi phần đầu của ClientHello đến liền mạch (ClientHello hiện chỉ dài 382 byte, nằm trong 1 datagram; sẽ dài hơn khi bật ML-KEM). Giữ phương án này trong tài liệu phòng khi Firefox/Safari (chưa chạy) không đạt.
- Browser đứng sau HTTP proxy bắt buộc sẽ không gửi gói UDP nào cho WebTransport (lỗi chỉ là `Opening handshake failed`). Client HTML5 phải coi lỗi này là tín hiệu để chuyển sang WebRTC.

### 3.7 Reconnect và vòng đời flow

- **Gateway không học lại flow.** Gói không thuộc flow nào thì chỉ có **gói mở đầu** (`CONNECT`, STUN binding request, QUIC Initial) được lên slow path; mọi gói khác bị **XDP drop**.
- Flow **chưa xác nhận**: timeout 5s; tối đa 2 flow chưa xác nhận cho mỗi `session_id`. Flow **đã xác nhận** (đã thấy game server trả lời): timeout 60s. Với WebRTC, "trả lời" phải là STUN success response hoặc DTLS từ server, vì server còn gửi check ICE khi nhận STUN chưa xác thực (§3.5, spike S2).
- **Client đổi IP/port** (đổi mạng, NAT rebinding, gói rơi vào node gateway khác):

| Transport | Client | Game server |
|---|---|---|
| Native | event đổi mạng (`notify_network_changed()`), hoặc quá ~2s không nhận được gói → gửi lại `CONNECT` với ticket cũ và proof mới | session ở trạng thái GRACE → `on_resume` |
| WebRTC | tạo PeerConnection mới với cùng ConnectInfo | resume bằng server ticket |
| WebTransport | kết nối lại cùng URL | resume bằng server ticket |

### 3.8 Mô hình tin cậy

| Bị lộ / chiếm quyền | Kẻ tấn công làm được | Kẻ tấn công không làm được |
|---|---|---|
| Gateway | drop hoặc chuyển hướng gói | đọc hay giả mạo traffic game |
| `K_gw` | tạo flow tới bất kỳ game server nào | xác thực như player (thiếu `K_gs` và session key) |
| `K_gs` của một fleet | giả server ticket trong fleet đó | đụng tới fleet khác |
| Một game server | đọc các session của chính nó | đụng tới game server khác |
| Ticket native bị sniff | tạo flow chưa xác nhận (≤ 2 flow, 5s) | gửi gói hợp lệ, resume session (thiếu session key cho proof) |
| Ticket WebRTC bị sniff (ufrag đi dạng rõ) | tạo flow chưa xác nhận; nếu server không kiểm MESSAGE-INTEGRITY trước khi tạo PeerConnection (§3.5) thì còn khiến server gửi check ICE tới địa chỉ giả | hoàn tất DTLS, xác thực như player |
| Game server bị truy cập trực tiếp (firewall sai) | flood thẳng vào game server; nếu giả được IP nguồn thuộc `trusted_gateway_cidrs` thì bỏ qua được bước xác thực địa chỉ của QUIC | xác thực như player, đọc traffic |

---

## 4. Gateway data plane

### 4.1 Pipeline XDP (Mode X, XA)

```
NIC RX ─▶ XDP
 1. parse eth / IPv4 / UDP. IPv4 có options hoặc bị phân mảnh → drop (với port glassy) hoặc XDP_PASS
 2. không phải UDP, hoặc không phải port glassy ───────────────────────────────▶ XDP_PASS
 3. dst = :443 (client → GS)
      ├─ khớp flow_down[5-tuple] → SNAT, cập nhật last_seen ─────────────────▶ XDP_TX
      └─ không khớp:
           ├─ là gói mở đầu (theo byte đầu, §2.2) + còn token bucket của IP nguồn
           │     ─▶ slow path (X: XDP_PASS → kernel socket; XA: XSKMAP → AF_XDP)
           └─ còn lại ──────────────────────────────────────────────────────▶ XDP_DROP
 4. dst ∈ 61000–65535 (GS → client)
      ├─ khớp flow_up[gs_ip, gs_port, up_port] → viết lại header, đặt cờ ĐÃ XÁC NHẬN ─▶ XDP_TX
      └─ không khớp ──────────────────────────────────────────────────────────▶ XDP_DROP
```

- Viết lại header gồm: đổi IP và port, **cập nhật incremental checksum** cho IP và UDP (không cần TX checksum offload), MAC next hop lấy bằng `bpf_fib_lookup`. Gateway dùng một ENI duy nhất cho cả 2 chiều, nên `XDP_TX` là đủ.
- **Bảng flow:** 2 BPF hash map **cấp phát sẵn** (mặc định 256k entry), **pin vào bpffs**. Chỉ slow path ghi entry mới; XDP chỉ cập nhật `last_seen` (khi lệch quá ~100ms) và cờ xác nhận.
- **Đếm drop theo lý do** bằng per-CPU array, xuất ra metric.

### 4.2 SNAT và upstream port

- Mỗi flow có một upstream port riêng **cho từng game server**, lấy từ dải 61000–65535 (khoảng 4.5k flow cho mỗi game server trên mỗi IP gateway).
- Đặt `ip_local_reserved_ports=61000-65535` để kernel không cấp trùng.
- Khi flow hết hạn, port bị **cách ly 60s** rồi mới dùng lại, để gói trễ từ game server không route nhầm sang client mới.
- IP thật của client: với native thì có trailer `client_addr` trong `CONNECT`; với WebRTC và WT thì MVP chưa có.

### 4.3 Slow path (một thư viện Rust dùng chung cho cả 4 mode)

| Gói mở đầu | Xử lý |
|---|---|
| glassy `CONNECT` | kiểm routing ticket → tra bảng → cấp port → ghi flow → forward kèm `client_addr` |
| STUN binding request | đọc `USERNAME` → giải mã ticket → ghi flow → forward |
| QUIC Initial không có token | gửi Retry (§3.6) |
| QUIC Initial có token | kiểm token → giải mã Initial → gom ClientHello → đọc SNI → giải mã ticket → ghi flow → forward |

**Sweeper** chạy mỗi giây: đọc map theo lô (`BPF_MAP_LOOKUP_BATCH`), xoá flow hết hạn, trả port về pool (vào trạng thái cách ly), xoá flow trỏ tới game server không còn trong bảng.

### 4.4 Bốn mode

| Mode | Fast path | Slow path | Thread | Ghi chú |
|---|---|---|---|---|
| K | userspace: `io_uring` (fallback `recvmmsg`/`sendmmsg`), `SO_REUSEPORT` mỗi core, một socket cho mỗi upstream port | userspace | mỗi core một worker, flow table chia shard | fallback |
| X | **trong XDP** | kernel socket | vài worker cho slow path | |
| XA | **trong XDP** | **AF_XDP** (`need_wakeup`, không busy poll) | mỗi queue một AF_XDP socket | **mặc định trên AWS** nếu detector cho phép |
| A | AF_XDP ở userspace (có busy poll) | AF_XDP | mỗi queue một core | tương đương Quilkin XDP; dùng cho tính năng cần userspace và cho benchmark |

### 4.5 Capability detector

Chạy lúc khởi động, theo thứ tự:
1. Kernel và BTF.
2. Driver NIC (`ethtool -i`: `ena`, `gve`, `mlx5_core`, `ice`, …).
3. Thử attach XDP ở driver mode → không được thì generic mode.
4. Thử bind AF_XDP với `XDP_ZEROCOPY` → không được thì `XDP_COPY`. Gặp `EBUSY` thì bind lại sau 50ms (tối đa khoảng 2s): kernel giải phóng queue của socket AF_XDP đã đóng một cách bất đồng bộ, nên probe ngay sau một probe khác sẽ báo "bận" thay vì kết quả thật (spike S3, veth).
5. Giới hạn MTU khi bật XDP: ENA chỉ nhận XDP native khi MTU ≤ khoảng 3498, trong khi EC2 mặc định MTU 9001. Detector báo rõ lý do và cho phép tự hạ MTU.
6. Số queue (đồng bộ RX/TX; riêng **ENA chỉ dùng tối đa một nửa số queue** khi bật XDP).

Công cụ đo `spikes/cap-probe` (đã chạy được trên veth) là bản mẫu của detector. Số liệu ENA thật chờ kết quả `bench/aws/s3-ena-probe.sh` (S3).

Kết quả: mode cao nhất chạy được, kèm báo cáo (log, metric `capability_info`, endpoint `/capabilities`). Có thể ép mode bằng config. Tham khảo thêm `quilkin/src/net/io/nic/xdp/diagnostics.rs`.

### 4.6 Các giới hạn lấy theo Quilkin

| Giới hạn | Quilkin | glassy |
|---|---|---|
| Idle timeout | 60s | 60s cho flow đã xác nhận, 5s cho flow chưa xác nhận |
| Kích thước gói | buffer 2048B, frame XDP 2KB, không phân mảnh | giống Quilkin |
| Header IP ở fast path | IPv4 không options, IPv6 không extension header | giống Quilkin (MVP chỉ IPv4) |
| Upstream port | ≥ 61000 | 61000–65535 + `ip_local_reserved_ports` |
| Rate limit | filter `LocalRateLimit` | token bucket theo IP nguồn **ngay trong XDP** |
| Queue NIC | đồng bộ RX/TX, kiểm TX checksum offload | giống Quilkin + ràng buộc riêng của ENA; fast path không cần checksum offload |

### 4.7 Giới hạn của MVP

- Chỉ IPv4 phía client.
- Các node gateway độc lập, không đồng bộ flow. Node chết thì client reconnect sang node khác.

---

## 5. Control plane và tích hợp

### 5.1 `Provider` (trong gateway)

```rust
trait Provider {
    /// Stream cập nhật: GameServer thêm / sửa / xoá; key ring thay đổi.
    fn watch(&self) -> impl Stream<Item = ConfigUpdate>;
}
```

- **MVP: `K8sProvider`.** Dùng `kube-rs` watch `GameServer` (lọc theo label `glassy.dev/enabled=true`) và `Secret` (chứa `K_gw`).
- Sau này có thể thêm `XdsProvider`, gossip (kiểu Corrosion của Quilkin) hoặc gRPC stream mà không phải sửa data plane.
- Bảng GS và key được thay thế nguyên khối (ArcSwap). `/readyz` chỉ pass sau khi đã nhận đủ snapshot đầu tiên.

### 5.2 Bảng GS

| Trường | Nguồn |
|---|---|
| `server_id` | `metadata.uid` của GameServer |
| địa chỉ | mặc định **`nodeIP:hostPort`** (Agones `portPolicy: Dynamic`): chạy trên mọi CNI và mọi môi trường. Tuỳ chọn `addressMode: podIP` khi CNI cho pod IP route được trên mạng vật lý (EKS VPC CNI, GKE VPC-native, Cilium native routing, Calico không encap). Với overlay như flannel VXLAN (mặc định của k3s), XDP không gửi thẳng tới pod IP được |
| port theo transport | các port đặt tên `glassy-udp`, `glassy-webrtc`, `glassy-wt` trong spec của GameServer; hostPort tương ứng lấy từ `status.ports` |
| trạng thái | **route được khi `Ready`, `Reserved` hoặc `Allocated`**; bị xoá khi `Shutdown`, `Unhealthy` hoặc khi object bị xoá |

- Game server có mặt trong bảng **từ lúc `Ready`**, tức trước khi được allocate. Race gần như không xảy ra; nếu có thì client tự gửi lại (`CONNECT` retry, browser tự retransmit STUN và Initial).
- Khi k8s API không truy cập được, gateway giữ bảng gần nhất và vẫn phục vụ.

### 5.3 Broker (`glassy-control`)

```protobuf
service Broker {
  rpc Allocate(AllocateRequest) returns (AllocateResponse); // fleet_selector, players[], metadata, match_ttl
  rpc Join(JoinRequest)         returns (JoinResponse);     // chỉ mint ticket cho player mới
  rpc Get(GetRequest)           returns (Instance);
  rpc List(ListRequest)         returns (ListResponse);
  rpc Delete(DeleteRequest)     returns (Empty);
}
```

`Allocate`:
1. Tạo `GameServerAllocation` (k8s API), gắn metadata của trận (match id, danh sách player).
2. Đọc từ GameServer được cấp: UID, annotation `glassy.dev/dtls-fp`, `glassy.dev/wt-cert-sha256`.
3. Với mỗi player: sinh `session_id` và session key; mint routing ticket và server ticket; tạo `ConnectInfo`.

```
ConnectInfo {
  session_id, expiry,
  native: { gateways[], routing_ticket, server_ticket, key_c2s, key_s2c },
  webrtc: { gateways[] (candidate), ice_ufrag, ice_pwd, dtls_fingerprint, server_ticket },
  webtransport: { url, cert_sha256 }
}
```

- Broker stateless, chạy N replica, không cần leader.
- Nakama và broker xác thực nhau bằng mTLS, cộng NetworkPolicy chỉ cho Nakama gọi broker.
- Agones Allocator Service (mTLS, nhiều cluster) để sau MVP.

### 5.4 `glassy-nakama` (Go plugin)

- Implement `runtime.FleetManagerInitializer` (nakama-common v1.48.0 / Nakama v3.41.0) và đăng ký bằng `initializer.RegisterFleetManager(...)`. Nakama gọi `Init(nk runtime.NakamaModule, callbackHandler runtime.FmCallbackHandler)` lúc đăng ký.
- Map hàm: `Create` → `Allocate`; `Join` → `Join`; `Get` / `List` / `Delete` → hàm cùng tên. `Update` là no-op, vì số player lấy từ Agones.
- **ConnectInfo của từng player nằm trong `SessionInfo.SessionId`**, dạng base64url không padding của JSON, encode **không** HTML-escape. Mỗi user một `SessionInfo`, theo thứ tự `userIds`. Code runtime của game (hook `MatchmakerMatched` hoặc RPC) gọi `Create`, rồi gửi `SessionId` cho đúng client qua notification hoặc phản hồi RPC. `InstanceInfo.ConnectionInfo` chỉ để tham khảo.
- `Create` trả map `nil`, vì core Nakama không bao giờ gọi `Create` và không đọc giá trị này. Phần allocate chạy trong goroutine tách khỏi context của caller (`context.WithoutCancel` + timeout riêng), rồi báo kết quả qua `callbackHandler.InvokeCallback`. Registry callback là **cục bộ trên từng node**, nên kết quả phải được invoke trên đúng node đã gọi `Create`.
- Plugin phải build trùng chính xác Go 1.27.1, các version dependency và cờ build của Nakama (`-trimpath`…). Dùng image `heroiclabs/nakama-pluginbuilder:<version>`. Đã kiểm chứng ở spike S5 (prototype + load thử bằng `plugin.Open`); chạy trong Nakama thật (cần database) để SP2.

### 5.5 Triển khai (portable)

**Yêu cầu chung, giống nhau ở mọi môi trường:**
- Một cluster Kubernetes bất kỳ (k8s tự dựng, k3s, EKS, GKE…) có Agones.
- **Node gateway:** gắn label và taint `glassy.dev/gateway`, có **IP public**. Gateway chạy dạng DaemonSet với `hostNetwork`, cần `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN` và mount `/sys/fs/bpf`. Không dùng Service kiểu LoadBalancer.
- **Node game server:** Agones `portPolicy: Dynamic`, mỗi GameServer có 3 port (một cho mỗi transport).
- **Firewall (bắt buộc khi bật WebTransport):** gateway nhận UDP 443 từ internet; node game server chỉ nhận các port glassy từ IP của gateway. Server SDK cấu hình `trusted_gateway_cidrs` bằng dải IP của các node gateway.
- **DNS:** một nhà cung cấp DNS bất kỳ có bản ghi wildcard (Route53, Cloud DNS, Cloudflare…) cho `*.wt.<domain>` trỏ về IP các gateway.

**Khác biệt theo môi trường (chỉ nằm ở cấu hình và capability detector):**

| | AWS (k8s/k3s tự host trên EC2, hoặc EKS) | GCP (tự host trên GCE, hoặc GKE) | Bare metal |
|---|---|---|---|
| IP public của gateway | Elastic IP gắn vào node | external IP tĩnh | IP public của server |
| NIC / driver | ENA | gVNIC (hoặc virtio) | mlx5, ice, i40e… |
| Firewall | security group | VPC firewall rule | nftables trên host |
| Instance gợi ý cho gateway | c7gn (Graviton), c6in (x86) | C3 / C4 có Tier_1 networking | NIC Intel/Mellanox 10–25G |
| `addressMode: podIP` dùng được khi | EKS + VPC CNI | GKE VPC-native | CNI route được (Cilium, Calico) |

Trước mắt: **k8s/k3s tự host trên EC2**, mặc định `addressMode: hostPort`.

---

## 6. SDK

### 6.1 Phân lớp (giống nhau ở client và server)

```
Application (game logic, simulator)
  ↕ Session API: on_connect / on_message / on_disconnect / on_resume, send(session, channel, bytes), rtt(), user_id()
Session layer: xác thực server ticket, resume theo session_id, chia channel, keepalive, timeout
  ↕ Transport interface: start / poll / send / close
Transport: UDP native │ WebRTC │ WebTransport
```

### 6.2 Channel

| Channel | Native UDP | WebRTC | WebTransport |
|---|---|---|---|
| `reliable` | native: byte stream có offset trong frame `STREAM` (SP1 §5.3), SDK tự làm ack + resend | data channel ordered, reliable | một bidi stream, message có prefix độ dài |
| `unreliable` | gửi thẳng | data channel `ordered:false, maxRetransmits:0` | datagram |
| `unreliable_sequenced` | **để sau MVP** (MVP chỉ `reliable` và `unreliable`) | | |

- Message `unreliable` tối đa khoảng 1100 byte (cấu hình được; lấy theo transport nhỏ nhất).
- Lớp reliability của native nằm trong `glassy-proto` C++, dùng chung cho client và server.

### 6.3 Vòng đời session

```
transport connect → nhận server ticket (+ proof với native) → on_connect     (không xác thực xong sau 5s → đóng)
mất kết nối → GRACE (mặc định 20s) → reconnect cùng session_id → on_resume
hết GRACE → on_disconnect
```

**Khi resume, channel reliable được reset.** Message reliable đang bay có thể mất; app nhận `on_resume` và tự gửi snapshot đầy đủ. Cả 3 transport dùng cùng ngữ nghĩa này.

### 6.4 Mô hình thread

- Một **network thread** sở hữu socket và các transport (`libdatachannel` có thread riêng của nó; `ngtcp2` và native theo kiểu sans-IO).
- Game thread gọi `poll()` mỗi tick để lấy event và gọi `send()` để đẩy vào hàng đợi SPSC. Game code **không bao giờ** bị callback từ thread khác gọi vào.

### 6.5 Server SDK

| Hạng mục | Lựa chọn |
|---|---|
| Native UDP | `glassy-proto` (C++) |
| WebRTC | `libdatachannel`: answer khai `ice-lite`, mux trên một port, tạo PeerConnection khi nhận STUN lạ **sau khi kiểm MESSAGE-INTEGRITY**, mỗi server ufrag một PeerConnection, ICE pwd dẫn xuất từ `K_gs` (§3.5) |
| WebTransport | `ngtcp2` + **lớp HTTP/3 + WT tối giản tự viết**: SETTINGS (hỗ trợ nhiều phiên bản draft; Chromium 141 dùng draft-02 và chỉ cần `H3_DATAGRAM` `0x33` + `ENABLE_WEBTRANSPORT` `0x2b603742`, spike S4), decode QPACK chỉ với bảng tĩnh và literal (dung lượng bảng động = 0), extended CONNECT, stream WT (bidi `0x41`, uni `0x54`), datagram có prefix quarter stream ID, capsule `CLOSE` / `DRAIN`; nhận token Retry no-shared-state khi nguồn thuộc `trusted_gateway_cidrs`. Ước lượng 1.5k–3k dòng. Code tham khảo: lsquic và `h3zero` của picoquic (đều MIT). |
| TLS | **GnuTLS** cho cả ngtcp2 (QUIC) và libdatachannel (DTLS): một thư viện, cả hai bên đều hỗ trợ chính thức. Phương án thay thế: aws-lc (QUIC) + Mbed TLS (DTLS), cân nhắc theo kết quả benchmark |
| Agones | **REST API của sidecar Agones** (`/ready`, `/health`, `/metadata/annotation`, `/watch/gameserver`); không dùng gRPC |
| Khởi động | đọc `K_gs` và `trusted_gateway_cidrs` → sinh cert DTLS và cert WT → ghi annotation `glassy.dev/dtls-fp`, `glassy.dev/wt-cert-sha256` → `Ready()` |
| Tắt | gửi `DISCONNECT` hoặc đóng kết nối đúng chuẩn cho mọi session → `Shutdown()` |

### 6.6 Client SDK

| | Native (desktop, mobile) | HTML5 (Defold → WASM) |
|---|---|---|
| Transport | UDP native | **WT mặc định**; tự fallback sang **WebRTC** nếu browser không hỗ trợ `WebTransport` hoặc `serverCertificateHashes` |
| Implementation | C++, `glassy-proto` + Monocypher | C++ mỏng + `library_glassy.js` gọi API của browser |
| Giữ ánh xạ NAT | **một socket suốt session**; keepalive mỗi 10s khi idle | WebRTC tự giữ nhờ ICE consent (RFC 7675); WT gửi datagram heartbeat |
| Reconnect | quá ~2s không nhận được gói, hoặc game gọi `notify_network_changed()` → gửi lại `CONNECT`, có backoff | kết nối lại với cùng ConnectInfo |
| Kích thước | **≤ 150KB**; build không exceptions, không RTTI, không iostream | gần như 0 |
| Mã lỗi | `ticket_expired`, `auth_failed`, `server_unreachable`, `timeout`; nguồn của các lỗi bị từ chối là gói `REJECT` (SP1 §4.6) | như native |

Bắt event đổi mạng của từng hệ điều hành (Android `ConnectivityManager`, iOS `NWPathMonitor`) nằm **ngoài** lõi SDK; game hoặc extension Defold gọi `notify_network_changed()`.

---

## 7. Xử lý lỗi

| Tình huống | Hành vi |
|---|---|
| Node gateway chết | client timeout → reconnect sang IP gateway khác (WebRTC: nhiều candidate; WT: nhiều bản ghi A) |
| Restart hoặc nâng cấp process gateway | BPF map đã pin nên **fast path vẫn forward**; kết nối mới retry |
| k8s API không truy cập được | dùng bảng GS gần nhất |
| Ticket sai hoặc hết hạn | drop không phản hồi + metric theo lý do |
| Game server crash | bảng GS xoá game server → sweeper xoá flow → client nhận `server_unreachable` → quay về Nakama |
| Slow path quá tải | token bucket theo IP nguồn + trần pps tổng; ring AF_XDP đầy thì drop + metric |
| BPF map đầy | từ chối tạo flow mới + cảnh báo; không đẩy flow đang có ra |
| Chương trình XDP bị gỡ | health check fail → pod restart → detector chạy lại |
| Xoay key | chấp nhận `key_id` hiện tại và trước đó |

---

## 8. Observability

- **Metric Prometheus** (không có label theo session):
  - pps và bytes theo hướng và theo mode;
  - drop theo lý do;
  - số flow (đã/chưa xác nhận) và số flow tạo mới mỗi giây theo transport;
  - latency của slow path, lỗi ticket theo lý do, số Retry đã gửi, số lần ghép ClientHello bị timeout;
  - mức dùng pool upstream port và mức đầy BPF map;
  - `capability_info{mode, driver, zerocopy}`.
- **Admin endpoint:** `/healthz`, `/readyz`, `/capabilities`, `/debug/flows`.
- **Log:** structured (`tracing`), có rate limit.
- **SDK:** thống kê RTT, tỉ lệ mất gói và bytes theo session; hook để app tự ghi log.

---

## 9. Testing

### 9.1 Các tầng môi trường test

Phần lớn việc test **không cần cloud**. Chỉ tầng 3 cần AWS, và chỉ trong thời gian ngắn.

| Tầng | Chạy ở đâu | Test được gì | Cần chuẩn bị |
|---|---|---|---|
| 0. CI | GitHub Actions | unit, fuzz, golden vectors, eBPF qua `BPF_PROG_TEST_RUN`, verifier trên nhiều kernel | không |
| 1. Máy Linux bất kỳ (dev hoặc VM) | network namespace + **veth** (XDP driver mode, AF_XDP copy mode), k3s/k3d + Agones, Chromium/Firefox thật qua Playwright | **toàn bộ chức năng**: 3 transport, Mode K/X/XA/A, reconnect, chaos | không |
| 2. Bare metal có NIC thật | 2 máy (hoặc 1 máy NIC 2 cổng) với NIC Intel (i40e/ice) hoặc Mellanox (mlx5); máy ở văn phòng hoặc thuê dedicated theo tháng | **benchmark chính, so với Quilkin** (so sánh tương đối, phần cứng nào cũng có giá trị) | 2 máy |
| 3. Kiểm chứng trên cloud | AWS: 2–3 instance EC2 trong ~1–2 giờ, chạy script dựng sẵn (có thể chạy từ AWS CloudShell). GCP để tới SP7 | chỉ những gì riêng của NIC cloud (ENA, gVNIC): giới hạn XDP, queue, zero-copy, pps tuyệt đối | một tài khoản AWS có quyền chạy EC2 |

DNS wildcard cho WebTransport khi test không cần Route53:
- **Local:** Chromium chạy với `--host-resolver-rules="MAP *.wt.test 127.0.0.1"`, hoặc dùng dnsmasq làm wildcard.
- **Từ xa:** hostname dạng `<ticket>.<ip>.sslip.io` tự resolve về IP nằm trong tên.

### 9.2 Test theo lớp

| Lớp | Cách test |
|---|---|
| `glassy-proto` | golden vectors chạy chung cho Rust, C++ và eBPF (`BPF_PROG_TEST_RUN`); differential fuzzing Rust ↔ C++ |
| Parser trong gateway | `cargo-fuzz` + proptest (STUN, QUIC Initial, ClientHello, `CONNECT`, ticket) |
| Parser trong SDK | libFuzzer + ASan/UBSan trong CI |
| Chương trình eBPF | `BPF_PROG_TEST_RUN`; verifier trên nhiều kernel (5.15, 6.1, 6.6, 6.12, …) bằng vmtest hoặc virtme-ng |
| Tích hợp | cluster kind có Agones + broker + gateway (Mode K, và Mode X trên veth) + game server test + client native |
| Browser | Playwright với Chromium và Firefox thật cho WebRTC/WT; Safari test tay ở giai đoạn đầu |
| Chaos | kill gateway hoặc game server, cắt k8s API, giả lập client đổi port nguồn |

---

## 10. Benchmark so với Quilkin

- **Môi trường:**
  - **Benchmark chính ở tầng 2** (bare metal, NIC Intel/Mellanox): gateway, máy sinh traffic và máy echo (đóng vai game server) tách riêng.
  - **Kiểm chứng ở tầng 3** trên AWS: một lượt ngắn trên **c7gn** và **c6in**, cùng một AZ, placement group dạng cluster, để có số tuyệt đối trên ENA.
- **Các cặp so sánh** (Quilkin pin một phiên bản cụ thể, cấu hình `Capture` suffix + `TokenRouter`):

| Quilkin | glassy |
|---|---|
| proxy + `io_uring` | Mode K |
| proxy + XDP (AF_XDP) | Mode A |
| — | Mode X, Mode XA |

- **Ma trận tải:** kích thước gói 64 / 256 / 1024 / 1400 byte; số session 1k / 10k / 50k / 100k; tần suất mỗi session 30 / 60 / 128 Hz. Thêm **kịch bản flood**: ~1 Mpps gói mở đầu giả chạy song song với traffic thật.
- **Chỉ số đo:** pps tối đa với mất gói < 0.1%; latency cộng thêm p50/p99/p999 (RTT qua proxy trừ RTT đi thẳng); số core cho mỗi Mpps; memory (RSS + BPF map) cho mỗi 10k session; tốc độ thiết lập kết nối; **tỉ lệ mất gói của traffic thật khi bị flood**.
- **Riêng AWS:** theo dõi các counter `*_allowance_exceeded` của ENA (đọc qua `ethtool -S`) để phân biệt giới hạn của VPC/NIC với giới hạn phần mềm.
- **Tiêu chí đạt:** đạt các mục tiêu ở §0.2 và không thua Quilkin ở cặp mode tương đương.
- Script và hạ tầng benchmark (IaC) nằm trong `bench/` để ai cũng chạy lại được. Chạy theo đợt và **huỷ hạ tầng sau khi đo**.

---

## 11. Các spike của SP0

Chi tiết: `docs/superpowers/spikes/2026-10-21-sp0-findings.md`.

| # | Câu hỏi | Đạt khi | Nếu thất bại | Kết quả |
|---|---|---|---|---|
| S1 | WT với ticket trong SNI: Chrome, Firefox, Safari có chấp nhận URL dạng hostname dài kèm `serverCertificateHashes` mà **không kiểm tên trong cert** không? Gateway có parse được ClientHello trải nhiều gói (ML-KEM, chaos protection) không? | browser kết nối thành công qua một prototype gateway | port mapping cho mỗi game server (§3.6) | ĐẠT trên Chromium 141; Firefox/Safari chưa chạy (chạy tay). Không cần port mapping |
| S2 | WebRTC không signaling: browser có chấp nhận SDP answer tự dựng (`ice-lite`, ufrag ~80 ký tự, data channel `negotiated`) không? libdatachannel có: mux listener kèm callback khi gặp STUN lạ, cho đặt ufrag/pwd local, cho tắt kiểm fingerprint không? | browser ↔ server prototype trao đổi được data | (a) ticket ngắn hơn (chỉ số tra bảng); (b) signaling relay qua Nakama | ĐẠT trên Chromium 141, với điều kiện client đặt `ice-pwd = ice-ufrag` và server bật `disableAutoNegotiation` (§3.5); Firefox/Safari chưa chạy |
| S3 | ENA trên c7gn và c6in (Amazon Linux 2023, kernel 6.12), chạy ở tầng 3 trong ~1–2 giờ: XDP driver mode, `XDP_TX`, ràng buộc queue và MTU, AF_XDP zero-copy, pps của một reflector `XDP_TX` | có bảng capability và pps nền | detector chọn mode thấp hơn; điều chỉnh mục tiêu §0.2 | Phần veth ĐẠT (`cap-probe`); phần ENA chờ người dùng chạy `bench/aws/s3-ena-probe.sh` |
| S4 | Chrome, Firefox, Safari hiện dùng phiên bản draft WT nào (SETTINGS, loại stream)? ngtcp2 + GnuTLS có hoàn tất handshake khi nhận token Retry no-shared-state do gateway phát (đi qua SNAT) không? | handshake + datagram + bidi stream chạy được với Chrome và Firefox | lớp WT hỗ trợ nhiều draft; nếu cần, xem lại lsquic | ĐẠT trên Chromium 141 (draft-02), cả handshake qua Retry + SNAT; Firefox/Safari chưa chạy |
| S5 | Type chính xác của `FleetManager` trong Nakama và chỗ đặt ConnectInfo cho từng user | prototype module Go gọi được broker giả lập | dùng hook `MatchmakerMatched` + RPC | ĐẠT: `Init(nk, cb)`, ConnectInfo trong `SessionInfo.SessionId`, `Create` trả `nil` (§5.4); chạy trong Nakama thật để SP2 |

---

## 12. Những gì cần chuẩn bị cho test

Tầng 0 và 1 (§9.1) không cần chuẩn bị gì; spec, SP1 và SP2 làm được hoàn toàn trên CI và máy Linux.

**Tầng 2 (benchmark chính):** 2 máy bare metal có NIC Intel (i40e/ice) hoặc Mellanox (mlx5), nối trực tiếp hoặc qua switch. Máy văn phòng hay thuê dedicated đều được.

**Tầng 3 (AWS, một lượt ngắn cho S3 và để có số tuyệt đối):**
1. Một tài khoản AWS có quyền chạy và huỷ EC2 trong một region (ví dụ `ap-southeast-1`), có budget alert.
2. Quota đủ cho 2–3 instance c7gn/c6in cỡ `.2xlarge`.
3. Bạn tự chạy script dựng sẵn trong `bench/aws/` (dựng instance → đo → **tự huỷ hạ tầng**), có thể chạy từ AWS CloudShell, rồi gửi lại file kết quả. **Không cần** EKS, Route53 hay OIDC.

**Tích hợp Nakama (SP2):** phiên bản Nakama và Go đang dùng, để build Go plugin cho khớp.

Không bao giờ dán key hay credential vào chat. Nếu sau này muốn Claude chạy trực tiếp từ session, credential được đặt trong phần cài đặt môi trường cloud của session.

---

## 13. Các điểm còn mở cần kiểm chứng

- Agones: phiên bản tối thiểu cần hỗ trợ; một GameServer có 3 port `Dynamic`; với `addressMode: podIP`, lấy pod IP từ `status.addresses`.
- Ràng buộc XDP và AF_XDP của ENA trên các instance mục tiêu, cùng pps nền (S3, chờ số liệu AWS).
- Firefox và Safari: WT với ticket trong SNI, WebRTC không signaling, draft WT (S1, S2, S4, chạy tay).
- Chromium bật ML-KEM: ClientHello trải 2 datagram qua Retry (relay đã có unit test, chưa thử với browser).

---

## 14. Tài liệu tham khảo

- QUIC-LB: <https://datatracker.ietf.org/doc/draft-ietf-quic-load-balancers/>
- QUIC Retry Offload: <https://github.com/quicwg/load-balancers/blob/main/draft-ietf-quic-retry-offload.md>
- RFC 9000 (QUIC), RFC 9001 (QUIC-TLS, §5.2 Initial keys), RFC 9221 (datagram), RFC 9287 (grease QUIC bit)
- RFC 9443 / RFC 7983 (tách loại gói theo byte đầu), RFC 8839 (SDP cho ICE, ufrag), RFC 7675 (ICE consent freshness)
- W3C WebTransport (`serverCertificateHashes`): <https://w3c.github.io/webtransport/>
- WebTransport over HTTP/3: <https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/>
- Quilkin: <https://github.com/googleforgames/quilkin>
- Nakama session-based multiplayer / FleetManager: <https://heroiclabs.com/docs/nakama/concepts/multiplayer/session-based/>
- ngtcp2: <https://github.com/ngtcp2/ngtcp2>, nghttp3: <https://github.com/ngtcp2/nghttp3>
- libdatachannel: <https://github.com/paullouisageneau/libdatachannel>
- lsquic (tham khảo): <https://github.com/litespeedtech/lsquic>; picoquic / h3zero (tham khảo): <https://github.com/private-octopus/picoquic>
- netcode.io (connect token, AEAD): <https://github.com/mas-bandwidth/netcode>
- libp2p WebRTC-Direct: <https://github.com/libp2p/specs/blob/master/webrtc/webrtc-direct.md>
