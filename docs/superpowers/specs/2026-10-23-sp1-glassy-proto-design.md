# SP1 — `glassy-proto`: wire format, golden vectors, crate Rust, lib C++

- **Ngày:** 2026-10-23
- **Trạng thái:** Đã duyệt
- **Spec cha:** `docs/superpowers/specs/2026-10-21-glassy-architecture-design.md` (gọi tắt là **spec kiến trúc**). Các mục `§x` không ghi rõ nguồn là của spec kiến trúc.
- **Tham chiếu đã đọc source:** netcode, reliable.io, yojimbo (mas-bandwidth), KCP (skywind3000), GameNetworkingSockets (Valve). Bảng so sánh ở §11.

Ký hiệu nguồn quyết định trong spec này:
- **[người dùng]**: người dùng đã chốt trong buổi brainstorm.
- **[kiến trúc]**: lấy nguyên từ spec kiến trúc.
- **[Claude]**: Claude tự quyết; người dùng có thể bác khi review.
- **[Claude, khi hiện thực]**: quyết định phát sinh lúc hiện thực Rust và C++; cả hai ngôn ngữ đã làm đúng như ghi và golden vectors khoá lại.

---

## 0. Mục đích

`glassy-proto` là **hợp đồng byte** giữa các thành phần viết bằng nhiều ngôn ngữ (D5): gateway và broker (Rust), server SDK và client SDK (C++, kể cả phần WASM của client HTML5). Spec kiến trúc mới chốt khung; SP1 chốt **từng byte**, rồi hiện thực hoá thành:

1. một tài liệu wire format đủ chính xác để viết một implementation độc lập tương thích từng byte (giống `STANDARD.md` của netcode/reliable.io);
2. golden vectors (JSON) do Rust sinh ra, mà C++ phải khớp;
3. crate Rust `glassy-proto`;
4. lib C++ `glassy-proto`.

**Vì sao làm riêng trước SP2:** SP2 dựng broker, gateway Mode K, server SDK và client SDK song song. Nếu hợp đồng byte chưa chốt và chưa có vectors, mỗi bên sẽ tự đoán và lỗi chỉ lộ ra khi chạy end-to-end. SP1 làm cho mọi bên dựa vào cùng một nguồn, có kiểm chứng tự động.

### 0.1 Mục tiêu

- Chốt các giá trị spec kiến trúc để mở (§13 của spec kiến trúc): byte loại gói native, kích thước `seq`, header.
- Chốt format của mọi thứ đi qua ranh giới ngôn ngữ: routing ticket, server ticket, token Retry (phần game server đọc), ICE pwd, `ConnectInfo`, các gói native, các frame bên trong gói `DATA`, framing message cho WebRTC và WebTransport.
- Golden vectors cho từng mục; Rust và C++ cùng pass.
- Mọi parser chịu được input tuỳ ý: fuzz, có trần cho mọi độ dài và buffer.

### 0.2 Ngoài phạm vi (để SP sau)

| Hạng mục | Để ở đâu |
|---|---|
| State machine reliability: RTO, resend, NACK, pacing, cửa sổ, ghép stream, bộ mô phỏng mạng tất định | SP2 [người dùng] |
| Session layer (GRACE, `on_resume`, keepalive timer), transport, socket | SP2 |
| Quyết định nhận/từ chối `CONNECT`, tombstone, chọn kết nối ứng viên, rate limit `REJECT` (§4.7) | SP2 [người dùng] |
| Broker, gRPC, gateway data plane, `K8sProvider` | SP2 |
| Parser STUN, QUIC Initial, ClientHello/SNI (chỉ gateway Rust dùng, không phải hợp đồng chéo ngôn ngữ) | SP4, SP5 (đã có bản spike trong `spikes/gw-proto`) |
| eBPF/XDP (chỉ đọc byte đầu và 5-tuple) | SP3 |
| Channel `unreliable_sequenced` | sau MVP [người dùng] |
| Lanes / độ ưu tiên giữa nhiều luồng reliable | sau MVP |
| Congestion control (ước lượng băng thông) | sau MVP; MVP chỉ pacing tốc độ cố định (SP2) |

### 0.3 Anti-goals (coi là thất bại dù chạy được)

- Có gói nào gateway hoặc game server **trả về lớn hơn gói kích hoạt nó** khi chưa xác thực (khuếch đại).
- Có buffer hoặc hàng đợi nào **tăng theo input từ mạng** mà không có trần (CONVENTIONS §3).
- Rust và C++ **khác nhau âm thầm**: một bên chấp nhận, bên kia từ chối cùng một chuỗi byte mà không có test nào bắt được.
- **Nonce AEAD bị dùng lại** dưới bất kỳ kịch bản nào: retry `CONNECT`, resume, client restart, đổi mạng.
- Phần C++ mà client native cần làm vượt ngân sách kích thước (client SDK tổng ≤ 150KB, §6.6) hoặc kéo theo GnuTLS/nettle vào client.
- Go (`glassy-nakama`) phải hiểu format ticket hay crypto (D13).

---

## 1. Quy ước chung của wire format

| Quy ước | Giá trị | Nguồn |
|---|---|---|
| Số nguyên kích thước cố định | **big-endian** (network byte order). Khớp với routing ticket và token Retry trong spike | [Claude] |
| Số nguyên kích thước thay đổi | **QUIC varint** (RFC 9000 §16): 2 bit đầu cho độ dài 1/2/4/8 byte, giá trị ≤ 2^62−1. Encoder **phải** dùng dạng ngắn nhất; decoder **phải** từ chối dạng không tối thiểu (canonical, giống reliable.io) | [Claude] |
| Base64 | `std` không padding cho ICE ufrag và ICE pwd (§3.5); `url` không padding cho mọi chỗ khác (server ticket trong URL, `ConnectInfo`) | [kiến trúc] + [Claude] |
| Base32 | RFC 4648, chữ thường, không padding (SNI) | [kiến trúc] |
| Độ dài tối đa của một datagram UDP glassy native | **1200 byte** (payload UDP). Encoder không bao giờ gửi lớn hơn; decoder từ chối gói lớn hơn 1200 (+8 byte trailer `client_addr` ở phía game server, §4.2) | [Claude], theo §6.2 (message unreliable ≤ ~1100) |
| Giá trị dành riêng (reserved) | encoder ghi 0; decoder **từ chối** nếu khác 0 (để sau này dùng được mà không mơ hồ) | [Claude] |

Mỗi mục bên dưới có một danh sách **"Receiver obligations"**. Đây là các bước kiểm tra bắt buộc, không phải gợi ý; vi phạm bất kỳ bước nào thì **drop không phản hồi**.

---

## 2. Bảng tổng hợp: ai đọc, ai ghi cái gì

| Hạng mục | Ghi (mint/encode) | Đọc (open/decode) | Rust | C++ |
|---|---|---|---|---|
| Routing ticket (§3.1) | broker | gateway | ✔ | ✘ (C++ chỉ coi là bytes opaque) |
| Server ticket (§3.2) | broker | game server | ✔ | ✔ (open) |
| ICE pwd (§3.3) | broker | game server | ✔ | ✔ (server-only) |
| Token Retry (§3.4) | gateway | gateway (validate), game server (đọc ODCID) | ✔ | ✔ (chỉ parse) |
| `ConnectInfo` (§3.5) | broker | client native (C++), client HTML5 (C++ trong WASM, §6.3) | ✔ | ✔ (parse) |
| Gói native `CONNECT`/`ACCEPT`/`DATA`/`DISCONNECT`/`REJECT` (§4) | client, game server | gateway (chỉ `CONNECT`, phần rõ), client, game server | ✔ (đủ để gateway parse `CONNECT` và để test/bench client) | ✔ |
| Frame trong `DATA` (§5) | client, game server | client, game server | ✔ (chỉ để sinh vectors và cho test client) | ✔ |
| Framing WebRTC/WT (§6) | client, game server | client, game server | ✔ (vectors) | ✔ |

---

## 3. Ticket, key và `ConnectInfo`

### 3.1 Routing ticket (gateway đọc) — giữ nguyên format spike

```
RoutingTicket (60 byte) = ver(1)=0x01 | key_id(1) | nonce(12) | AES-128-GCM_K_gw(body)(30) | tag(16)
AAD  = ver | key_id
body = server_id(16) | session_id(8) | expiry(u32, unix giây) | transports(1) | flags(1)
```

- `transports` bitmask: `0x01` native, `0x02` WebRTC, `0x04` WebTransport. Các bit khác reserved.
- `flags`: reserved, phải bằng 0 [Claude].
- `nonce`: broker sinh ngẫu nhiên 12 byte cho mỗi ticket. Với AES-GCM, nonce ngẫu nhiên 96 bit an toàn tới khoảng 2^32 ticket cho mỗi key; `K_gw` xoay vòng nên không chạm giới hạn này. Spec ghi rõ giới hạn để broker có metric đếm số ticket đã mint theo `key_id` [Claude].
- Encode: ICE ufrag = base64 std không padding (80 ký tự); SNI = base32 chữ thường, chia 2 nhãn × 48 ký tự, theo sau là hậu tố domain cấu hình (`<48>.<48>.wt.<domain>`). Decode SNI không phân biệt hoa thường.

**Receiver obligations (gateway):** độ dài đúng 60 (trước khi decode base64/base32: ufrag đúng 80 ký tự, hai nhãn SNI đúng 48 ký tự); `ver` = 1; `key_id` có trong key ring; AEAD hợp lệ; `expiry` ≥ now; `flags` = 0; transport của gói nằm trong `transports`; với native, `session_id` trong ticket = `session_id` trong header `CONNECT`; `server_id` có trong bảng GS ở trạng thái route được (§5.2 kiến trúc; kiểm tra này thuộc gateway SP2, ghi ở đây cho đủ).

**Thứ tự kiểm tra** [Claude, khi hiện thực]: độ dài → `ver` → `key_id` → AEAD → `flags` và bit reserved của `transports` (`reserved_nonzero`) → `expiry` < now (`expired`) → transport của gói không nằm trong `transports` (`bad_transport`) → `session_id` không khớp (`session_mismatch`). Mã lỗi nào cũng trả về theo thứ tự này, nên hai ngôn ngữ cho cùng một mã với cùng một input.

### 3.2 Server ticket (game server đọc) — đổi so với spec kiến trúc

```
ServerTicket = ver(1)=0x01 | key_id(1) | nonce(24) | XChaCha20-Poly1305_K_ticket(body) | tag(16)
K_ticket = HKDF-SHA256(ikm = K_gs, salt = rỗng, info = "glassy-server-ticket", L = 32)
AAD  = ver | key_id
body = user_id_len(1) | user_id(1..64, UTF-8)
     | server_id(16) | session_id(8) | expiry(u32) | transport(1)
     | [key_c2s(32) | key_s2c(32)]          ← chỉ khi transport = native (0x01)
     | metadata_len(u16) | metadata(0..256)
```

- **Đổi 1 [Claude]: XChaCha20-Poly1305 (nonce 24 byte) thay cho ChaCha20-Poly1305 (nonce 12 byte).** `K_gs` sống lâu và mỗi ticket có nonce ngẫu nhiên; nonce 24 byte loại bỏ hẳn rủi ro trùng nonce ngẫu nhiên. Monocypher, libsodium và crate `chacha20poly1305` đều hỗ trợ trực tiếp. Tốn thêm 12 byte.
- **Đổi 2 [Claude]: thêm `ver`**, để đổi format sau này mà không phải đoán.
- **Đổi 3 [Claude, sau review]: tách key theo mục đích.** `K_gs` không dùng trực tiếp làm key AEAD. `K_ticket` và key của ICE pwd (§3.3) đều dẫn xuất bằng HKDF với `info` khác nhau.
- **Đổi 4 [Claude, sau review]: thêm `server_id`.** Ticket chỉ hợp lệ trên đúng game server mà broker đã cấp, không dùng được cho game server khác trong cùng fleet. Với WebRTC/WT, game server không có routing ticket để đối chiếu, nên đây là chỗ duy nhất ràng buộc điều này.
- `transport`: đúng một bit theo bitmask ở §3.1. Mỗi player có **một server ticket cho mỗi transport** (khoá native chỉ nằm trong ticket native), để ticket WebRTC/WT bị lộ không làm lộ key native.
- `user_id_len` = 0 không hợp lệ (Nakama luôn có user id).
- Kích thước body: tối thiểu 1+1+16+8+4+1+2 = 33 (không phải native), 97 (native); tối đa 1+64+16+8+4+1+64+2+256 = 416. Ticket = 42 + body: **75–394 byte** (WebRTC/WT), **139–458 byte** (native).

**Receiver obligations (game server):** độ dài trong [75, 458]; `ver` = 1; `key_id` đã biết; AEAD hợp lệ; `user_id_len` trong [1, 64] và `user_id` là UTF-8 hợp lệ; `server_id` = UID GameServer của chính nó; `expiry` ≥ now; `transport` là đúng một bit đã định nghĩa và khớp transport nhận ticket; có key native khi và chỉ khi `transport` = native; `metadata_len` ≤ 256; tổng độ dài các trường khớp đúng độ dài body (không thừa, không thiếu).

**Thứ tự kiểm tra** [Claude, khi hiện thực]: độ dài [75, 458] → `ver` → `key_id` → AEAD → parse body theo thứ tự byte: `user_id_len` ∈ [1, 64] (`bad_user_id`) → thiếu byte (`bad_length`) → `transport` ∈ (1, 2, 4) (`bad_transport`) → key native (nếu native) → `metadata_len` ≤ 256 (`bad_metadata`) → phần còn lại đúng bằng `metadata_len` (`bad_length`) → `user_id` là UTF-8 theo RFC 3629 (`bad_user_id`) → `server_id` (`wrong_server`) → `expiry` < now (`expired`) → `transport` ≠ transport nhận ticket (`bad_transport`).

### 3.3 ICE pwd — giữ nguyên spike

```
pwd = base64_std_nopad( HMAC-SHA256( HKDF-SHA256(ikm = K_gs, salt = rỗng, info = "glassy-ice", L = 32), ufrag ) )
```

Kết quả 43 ký tự. Vector đã có: `spikes/vectors/ice_pwd.json` (chuyển sang `vectors/` của SP1).

### 3.4 Token Retry no-shared-state — giữ nguyên spike

```
token = byte0 (bit7 = 0, bit0..6 = ODCIL ∈ [8, 20]) | ODCID | expiry(u64 BE, unix giây) | tag(16)
tag   = HMAC-SHA256_K_retry_gw( byte0 | ODCID | expiry | ip16(client) | port(u16) | RSCIL(1) | RSCID )[0..16]
```

- Gateway (Rust): mint + validate (đã có trong spike, chuyển vào crate).
- Game server (C++): **chỉ parse**: kiểm `bit7 = 0`, `ODCIL ∈ [8, 20]`, độ dài = 1 + ODCIL + 8 + 16, rồi lấy ODCID. Không kiểm tag (không có key, §3.6 kiến trúc).
- Vector đã có: `spikes/vectors/retry_token.json`.
- [Claude, khi hiện thực] Các kiểm tra cấu trúc dùng chung cho cả parse (game server) và validate (gateway), theo thứ tự: rỗng → `bad_length`; `bit7` = 1 → `bad_token_type`; ODCIL ∉ [8, 20] → `bad_odcil`; độ dài ≠ 1 + ODCIL + 8 + 16 → `bad_length`. Validate kiểm thêm **tag trước, hạn sau**: tag sai → `auth_failed`; `now` > `expiry` → `expired`. Làm vậy để token giả không dò được hạn.

### 3.5 `ConnectInfo`

Broker tạo, Nakama chuyển nguyên vẹn, client đọc. Đi trong `SessionInfo.SessionId` dưới dạng base64url không padding của JSON UTF-8, **không** HTML-escape (§5.4).

```json
{
  "v": 1,
  "session_id": "<16 hex>",
  "expiry": 1798000000,
  "native": {
    "gateways": ["203.0.113.10:443", "203.0.113.11:443"],
    "routing_ticket": "<b64url, 60 byte>",
    "server_ticket": "<b64url>",
    "key_c2s": "<b64url, 32 byte>",
    "key_s2c": "<b64url, 32 byte>"
  },
  "webrtc": {
    "candidates": ["203.0.113.10:443"],
    "ice_ufrag": "<80 ký tự>",
    "ice_pwd": "<43 ký tự>",
    "dtls_fingerprint": "sha-256 AB:CD:…",
    "server_ticket": "<b64url>"
  },
  "webtransport": {
    "url": "https://<48>.<48>.wt.example.com:443/glassy?t=<b64url server ticket>",
    "cert_sha256": "<b64url, 32 byte>"
  }
}
```

- Mỗi khối transport là **tuỳ chọn**: broker chỉ đưa vào những transport mà fleet bật.
- Trường lạ: decoder **bỏ qua** (để broker thêm trường mà không phá client cũ). `v` khác 1: từ chối.
- **Quy tắc decode** [Claude, khi hiện thực], theo đúng thứ tự (lỗi đầu tiên thắng; Rust và C++ phải cho cùng mã):
  1. Chuỗi base64url tối đa **5462** ký tự và decode nghiêm ngặt (không padding, không ký tự lạ, bit thừa = 0), dài hơn → `too_large`, sai → `bad_encoding`.
  2. JSON tối đa **4096** byte (`too_large`).
  3. Độ sâu lồng nhau tối đa **8**; quét ngoài chuỗi ký tự (`bad_json`).
  4. Toàn bộ tài liệu là UTF-8 hợp lệ (`bad_json`).
  5. Toàn bộ tài liệu là JSON hợp lệ theo RFC 8259, kể cả phần ngoài các trường đã biết: rác phía sau bị từ chối; escape `\ud800` đứng một mình được chấp nhận; số rất lớn trong trường lạ được chấp nhận (`bad_json`).
  6. `v` ở top-level được kiểm **trước mọi trường khác**: thiếu hoặc không phải token số nguyên → `bad_json`; số nguyên ≠ 1 → `bad_version`. Nhờ vậy phiên bản tương lai có schema mới vẫn nhận mã `bad_version` thay vì lỗi của trường.
  7. Trường đã biết: trùng key đã biết → `bad_json`; trùng key lạ thì bỏ qua; key có chứa escape không bao giờ khớp tên đã biết; trường chuỗi đã biết không được chứa escape.
  8. Kiểm giá trị: `session_id` 16 hex chữ thường; có ít nhất một khối transport; `gateways` và `candidates` có 1..4 phần tử, mỗi phần tử 1..64 byte; `routing_ticket` 60 byte; `server_ticket` native [139, 458], WebRTC [75, 394]; `key_c2s`, `key_s2c`, `cert_sha256` 32 byte; `ice_ufrag` 80 và `ice_pwd` 43 ký tự thuộc bảng base64 std (bit thừa của `ice_pwd` **không** kiểm); `dtls_fingerprint` 1..128 ký tự ASCII in được; `url` 1..1024 byte (`bad_length`) và bắt đầu bằng `https://` (`bad_encoding`); `expiry` là u32 bất kỳ, kể cả 0.
  9. Kiểu giá trị sai (ví dụ `null`) hoặc thiếu trường của một khối transport → `bad_json`; thứ tự kiểm giá trị theo thứ tự trong tài liệu (`session_id`, `native`, `webrtc`, `webtransport`). Decoder C++ không cấp phát động (có test đếm allocation).
- Kích thước: JSON ≤ **4096 byte** trước base64 [Claude]. Với ticket lớn nhất và cả 3 transport, JSON khoảng 2.6KB, nên 4096 còn dư. Decoder C++ từ chối JSON lớn hơn trước khi parse. SP2 phải kiểm chứng Nakama thật chấp nhận `SessionId` dài cỡ ~5.5KB (4096 byte sau base64); spike S5 mới thử tới ~1.5KB.
- **Go không parse `ConnectInfo`** [Claude]: broker trả về sẵn chuỗi base64url cho từng player; `glassy-nakama` chỉ đặt chuỗi đó vào `SessionId`. Như vậy D13 giữ nguyên: Go không biết gì về format.
- Parser JSON phía C++ là một parser tối giản, có trần độ sâu và độ dài, không cấp phát động ngoài buffer cố định. Không kéo thư viện JSON lớn vào client [Claude].

---

## 4. Gói native UDP

### 4.1 Byte đầu và cấu trúc chung

| Byte đầu | Loại | Hướng |
|---|---|---|
| `0x80` | `CONNECT` | C→S |
| `0x81` | `ACCEPT` | S→C |
| `0x82` | `DATA` | hai chiều |
| `0x83` | `DISCONNECT` | hai chiều |
| `0x84` | `REJECT` | S→C |
| `0x85–0xBF` | reserved: drop | |

[Claude] Giá trị nằm trong dải `0x80–0xBF` theo §2.2. Gateway XDP chỉ cần nhận ra `0x80` là gói mở đầu; các loại khác đi theo flow đã có.

**Nonce, packet number (`pn`) và kết nối** — điểm thiết kế quan trọng nhất của SP1 [Claude, sửa sau review]:

Nguyên tắc: **mỗi bên tự bảo đảm tính duy nhất của nonce mà nó dùng để mã hoá, bằng phần ngẫu nhiên do chính nó sinh**, không dựa vào giá trị do bên kia chọn và không dựa vào bộ nhớ có thể mất (session đã đóng, pod restart). Bản trước dùng `conn_id` do client chọn cho cả chiều S→C; review chỉ ra rằng replay một `CONNECT` cũ sau khi server quên session sẽ khiến server mã hoá lại với nonce cũ.

- **Client** sinh `conn_id` ngẫu nhiên 16 byte mới cho **mỗi lần gửi `CONNECT`**. Nonce của proof = `conn_id | 0⁸`.
- **Server** sinh `server_nonce` ngẫu nhiên 16 byte mới cho **mỗi `ACCEPT` hoặc `REJECT`** nó gửi, và gửi `server_nonce` dạng rõ trong gói đó. Một kết nối = một `server_nonce` đã được `ACCEPT`.
- Mọi gói sau `ACCEPT` (`DATA`, `DISCONNECT`, cả hai chiều) dùng **XChaCha20-Poly1305** với:
  - key = `key_c2s` (client gửi) hoặc `key_s2c` (server gửi);
  - nonce 24 byte = `server_nonce(16) | pn(u64 BE)`.
- Chiều S→C: server sinh `server_nonce` nên tự bảo đảm duy nhất. Chiều C→S: client chỉ dùng `server_nonce` của một `ACCEPT` hợp lệ trả lời đúng `CONNECT` đang chờ của nó (AAD của `ACCEPT` ràng buộc `conn_id`, §4.3), nên kẻ tấn công không ép được client dùng lại một `server_nonce` cũ.
- `pn` là bộ đếm 64 bit **riêng cho mỗi chiều và mỗi kết nối**, giá trị 0 dành cho `ACCEPT`/`REJECT` (S→C) và không dùng ở C→S; gói `DATA` đầu tiên của mỗi chiều dùng `pn` = 1. Mỗi gói gửi đi (kể cả keepalive và gói chứa dữ liệu gửi lại) dùng một `pn` mới, tăng dần.
- Vì mỗi kết nối có `server_nonce` mới, `pn` bắt đầu lại khi resume mà **không dùng lại nonce**, kể cả khi client restart rồi dùng lại `ConnectInfo`.
- Trên wire, `pn` được gửi dưới dạng **4 byte thấp**; bên nhận dựng lại 64 bit theo thuật toán RFC 9000 Appendix A.3, dựa trên `pn` lớn nhất đã xác thực trong kết nối đó. [Claude, khi hiện thực] Dùng `pn_nbits` = 32 và điều kiện chặn `candidate < 2^62 − 2^32` (so sánh **chặt**); hiện thực phải tránh underflow số không dấu khi `largest` nhỏ.
- [Claude, khi hiện thực] **Bên gửi từ chối `pn` = 0** ở `DATA` và `DISCONNECT` (sẽ dùng lại nonce `server_nonce | 0⁸` của `ACCEPT`/`REJECT` dưới `key_s2c`). `seal_data` kiểm `frames` > 1171 byte (`too_large`) **trước** khi kiểm `pn` = 0.
- **Một `pn` duy nhất cho cả AEAD, chống replay và ack** [người dùng]: frame `ACK` (§5.2) tham chiếu chính `pn` này; không có seq thứ hai.

**Chống replay** (theo netcode): bên nhận giữ cửa sổ đúng 256 `pn`, tức (`largest` − 256, `largest`]. Gói có `pn` + 256 ≤ `largest` bị drop (`too_old`); gói có `pn` đã nhận bị drop (`replayed`); `pn` = 0 luôn bị drop (`replayed`, vì 0 dành cho `ACCEPT`/`REJECT`). Chỉ cập nhật cửa sổ **sau khi** AEAD hợp lệ. [Claude, khi hiện thực]

**Định danh kết nối:** header `DATA` không mang định danh kết nối; server phân biệt kết nối bằng cách thử giải mã. Quy tắc giữ và chọn kết nối là hành vi session (§4.7, SP2).

### 4.2 `CONNECT` (C→S, qua gateway)

```
0x80 | ver(1)=0x01 | session_id(8) | conn_id(16) | connect_seq(u64)
     | routing_ticket(60)
     | server_ticket_len(u16) | server_ticket(139..458)
     | proof_tag(16)
     | padding (0x00…)
[gateway thêm khi forward:] client_addr trailer = addr | port(u16) | reserved(1)=0 | family(1)
                            family 0x04: addr = ipv4(4), trailer 8 byte
                            (0x06 dành cho IPv6 sau MVP: addr = ipv6(16), trailer 20 byte)
```

- `proof_tag` = tag của XChaCha20-Poly1305 với key `key_c2s`, nonce `conn_id | 0⁸`, plaintext rỗng, AAD = toàn bộ byte từ `0x80` tới hết `server_ticket`.
- **Mỗi lần gửi lại `CONNECT` (retry, reconnect) phải dùng `conn_id` mới.** Dùng lại `conn_id` với `connect_seq` khác là dùng lại nonce với AAD khác.
- `connect_seq`: client tăng dần qua các lần gửi `CONNECT` của cùng session. **Đổi so với spec kiến trúc [Claude]:** thay cho "timestamp trong cửa sổ cho phép". Game server chỉ yêu cầu `connect_seq` **lớn hơn hẳn** giá trị đã chấp nhận gần nhất của session, không so với đồng hồ thật, vì đồng hồ máy mobile có thể lệch nhiều. Client lấy giá trị ban đầu từ đồng hồ hệ thống tính bằng ms, rồi tăng tối thiểu 1 mỗi lần. Nếu đồng hồ lùi (client restart), server trả `REJECT` kèm `connect_seq` đã chấp nhận gần nhất để client nhảy lên trên giá trị đó (§4.6, §4.7), thay vì bị khoá ngoài trận.
- `padding`: tuỳ ý, toàn byte 0.
- `client_addr` trailer: gateway gắn vào cuối. Byte `family` nằm **cuối cùng** để game server đọc từ cuối gói ngược lên. Game server chỉ bóc trailer khi gói đến từ IP thuộc `trusted_gateway_cidrs`; ngược lại coi như không có trailer. MVP chỉ IPv4 (§0.4 kiến trúc); `0x06` được dành chỗ để thêm IPv6 mà không đổi cách parse.
- Kích thước: tối thiểu 34+60+2+139+16 = **251 byte**; tối đa 1200 (+ trailer).

**Receiver obligations — gateway:** độ dài trong [251, 1200]; `ver` = 1; routing ticket hợp lệ theo §3.1 với transport native và `session_id` khớp; `server_ticket_len` trong [139, 458] và không vượt quá phần còn lại. Gateway **không** kiểm `proof_tag` (không có session key).

**Thứ tự kiểm tra** [Claude, khi hiện thực]: *gateway (parse)*: độ dài [251, 1200] → loại gói → `ver` → `server_ticket_len` ∈ [139, 458] và vừa trong gói. *Game server (verify, sau parse)*: padding toàn 0 (`bad_padding`) → mở server ticket (qua phần native, §3.2) → `session_id` khớp (`session_mismatch`) → `proof_tag` (`auth_failed`). `build_connect` cũng từ chối server ticket ngoài [139, 458].

**Receiver obligations — game server:** như gateway về độ dài, `ver` và `server_ticket_len` (không mở routing ticket); trailer có `family` = `0x04` và `reserved` = 0 khi nguồn là gateway; server ticket hợp lệ theo §3.2 với transport native, `session_id` khớp header; `proof_tag` hợp lệ với `key_c2s` trong ticket; padding toàn 0. **Phần của SP1 dừng ở đây:** lib trả về một `CONNECT` đã xác thực (`session_id`, `conn_id`, `connect_seq`, nội dung server ticket). Việc gửi `ACCEPT` hay `REJECT` là quyết định của session layer (§4.7, SP2).

### 4.3 `ACCEPT` (S→C)

```
0x81 | session_id(8) | connect_seq(u64) | server_nonce(16) | AEAD_s2c( body ) | tag(16)
nonce = server_nonce | 0⁸
AAD   = byte từ 0x81 tới hết server_nonce | conn_id(16)      ← conn_id của CONNECT được trả lời, không gửi trên wire
body  = flags(1) [bit0 = resumed] | reserved(1)=0 | server_time_ms(u64)
```

- Client biết `CONNECT` nào được trả lời nhờ `connect_seq` (client giữ ánh xạ `connect_seq → conn_id` cho tối đa **4** `CONNECT` đang chờ). Đưa `conn_id` vào AAD ràng buộc `ACCEPT` với đúng `CONNECT` đó: một `ACCEPT` cũ bị phát lại không khớp `conn_id` nào đang chờ.
- [Claude, khi hiện thực] **Peek một phản hồi** (client chưa biết là `ACCEPT` hay `REJECT`): độ dài ∉ {58, 59} → `bad_length`; sau đó loại gói phải khớp độ dài (59 ↔ `0x81` `ACCEPT`, 58 ↔ `0x84` `REJECT`), nếu không `bad_type`. Bit flag reserved và byte `reserved` của `ACCEPT` ≠ 0 → `reserved_nonzero`, kiểm **sau** AEAD.
- Kích thước cố định 1+8+8+16+10+16 = **59 byte**, nhỏ hơn `CONNECT` tối thiểu (251). Không thể dùng để khuếch đại.

### 4.4 `DATA` (hai chiều)

```
0x82 | session_id(8) | pn_low(4) | AEAD( frames ) | tag(16)
AAD = 13 byte header
```

- Overhead cố định: 13 + 16 = **29 byte**. Plaintext frames ≤ 1200 − 29 = **1171 byte**.
- [Claude, khi hiện thực] `seal_data` từ chối `pn` = 0 (§4.1).
- Keepalive = `DATA` có thể không chứa frame nào, hoặc chỉ chứa `ACK` (§5).
- `session_id` giữ trong header theo spec kiến trúc: game server tra session bằng `session_id`, không dựa vào địa chỉ nguồn.

**Receiver obligations:** độ dài trong [29, 1200]; session tồn tại và có kết nối (hiện hành hoặc ứng viên, §4.7); `pn` dựng lại không nằm ngoài hoặc đã có trong cửa sổ replay của kết nối đó; AEAD hợp lệ; frames parse đúng và **được giữ lại trọn vẹn** theo §5 (nếu không, drop **cả gói**, không áp dụng một phần và **không ack** gói đó, §5.0).

### 4.5 `DISCONNECT` (hai chiều)

```
0x83 | session_id(8) | pn_low(4) | AEAD( reason(1) ) | tag(16)
```

- `reason`: `0x00` bình thường, `0x01` server shutdown, `0x02` bị kick, `0x03` protocol error; giá trị khác hợp lệ nhưng coi như `0x00`.
- [Claude, khi hiện thực] `seal_disconnect` từ chối `pn` = 0 (§4.1).
- Chỉ gửi trong một kết nối đã `ACCEPT`. Nhận được `DISCONNECT` hợp lệ: đóng session ngay, không vào GRACE.

### 4.6 `REJECT` (S→C) [Claude, sau review]

```
0x84 | session_id(8) | connect_seq(u64) | server_nonce(16) | AEAD_s2c( reason(1) | last_connect_seq(u64) ) | tag(16)
nonce = server_nonce | 0⁸;  AAD = byte từ 0x84 tới hết server_nonce | conn_id(16)
```

- Chỉ được gửi sau khi `CONNECT` đã qua **toàn bộ** kiểm tra crypto (server ticket + `proof_tag`), nên người ngoài không kích hoạt được. Kích thước cố định **58 byte** < `CONNECT` tối thiểu: không khuếch đại.
- `reason`: `0x01` `stale_connect_seq` (kèm `last_connect_seq` để client nhảy lên trên), `0x02` `kicked`, `0x03` `session_closed`, `0x04` `server_full`; giá trị khác hợp lệ, client coi như `session_closed`. Client ánh xạ sang mã lỗi của SDK (§6.6 kiến trúc). Lỗi ở gateway (ticket hỏng, hết hạn) vẫn **drop không phản hồi** như §7 kiến trúc; client tự biết `ticket_expired` từ `expiry` trong `ConnectInfo`.

### 4.7 Hành vi session mà format này phục vụ (hiện thực ở SP2) [người dùng]

SP1 chỉ chốt byte và hàm thuần (seal/open, verify ticket và proof, dựng lại `pn`, cửa sổ replay). Các quy tắc dưới đây cần state của session nên thuộc SP2. Chúng được ghi ở đây vì format ở trên được thiết kế để phục vụ chúng; SP2 không được đổi chúng mà không xem lại format.

- **Nhận `CONNECT` đã xác thực:** `connect_seq` > giá trị đã chấp nhận gần nhất của session → tạo hoặc resume, gửi `ACCEPT`; `connect_seq` không lớn hơn → `REJECT stale_connect_seq`.
- **Session đã đóng mà nhận `CONNECT` hợp lệ mới** [người dùng]: luôn tạo **session mới** (app nhận `on_connect`, không phải `on_resume`), dù session cũ đóng do `DISCONNECT`, hết GRACE hay bị kick. [Claude] Chặn người bị kick là việc của game và broker (không cấp ticket mới, hoặc game từ chối trong `on_connect`); SP1 vẫn giữ mã `kicked` trong `REJECT` để dùng khi cần.
- **Tombstone** [Claude]: khi session đóng, server giữ `session_id → max connect_seq` tới khi ticket hết hạn, có trần (mặc định 1024; đầy thì bỏ bản ghi hết hạn sớm nhất). Mục đích: một `CONNECT` cũ bị phát lại (có `connect_seq` ≤ giá trị đã thấy) không mở lại session. `CONNECT` có `connect_seq` lớn hơn thì mở session mới như trên. Mất tombstone khi pod restart chỉ làm mất khả năng nhận ra replay, không gây dùng lại nonce (nonce S→C do server sinh ngẫu nhiên, §4.1).
- **Kết nối ứng viên** [Claude]: khi `ACCEPT` bị mất, client gửi lại `CONNECT` và server có thể đã chấp nhận nhiều lần. Để hai bên hội tụ:
  - Client nhận `ACCEPT` của bất kỳ `CONNECT` nào đang chờ (tối đa 4, §4.3), miễn `connect_seq` của nó ≥ `connect_seq` của kết nối đang dùng; kết nối đó trở thành hiện hành, các `CONNECT` cũ hơn bị bỏ.
  - Server giữ tối đa **2** kết nối mỗi session (mới nhất và trước đó), thử giải mã `DATA`/`DISCONNECT` với kết nối mới nhất trước (tối đa 2 lần AEAD mỗi gói). Kết nối giải mã được trở thành hiện hành; kết nối cũ hơn bị xoá. Server gửi bằng kết nối hiện hành.
- **Rate limit:** tối đa 1 `REJECT` mỗi giây cho mỗi session.

---

## 5. Frame bên trong `DATA`

Lấy cảm hứng từ SNP của GNS (frame có byte loại) và QUIC (varint), đơn giản hoá [Claude] theo hướng [người dùng] đã chốt: **reliable là một byte stream có offset** (kiểu GNS); chỉ có 2 channel `reliable` và `unreliable`.

| Byte loại | Frame |
|---|---|
| `0x01` | `ACK` |
| `0x02` | `STREAM` (reliable) |
| `0x03` | `DATAGRAM` (unreliable) |
| khác | reserved: drop cả gói |

Một gói có thể chứa nhiều frame, theo thứ tự bất kỳ; tối đa một `ACK`.

### 5.0 Gói nào được ack [Claude, sau review]

Có **hai tập `pn` khác nhau** ở bên nhận:
- **Cửa sổ replay** (§4.1): cập nhật ngay khi AEAD hợp lệ.
- **Tập được ack**: một `pn` chỉ vào tập này khi **mọi frame trong gói đã được parse và giữ lại trọn vẹn**. Gói có bất kỳ phần nào không được giữ lại (dữ liệu `STREAM` vượt cửa sổ hoặc vượt trần số lỗ, §5.3) thì bị drop cả gói và **không được ack**, để bên gửi coi như mất và gửi lại. Nếu ack một gói mà lại bỏ một phần dữ liệu trong đó, bên gửi sẽ tưởng dữ liệu đã tới, không bao giờ gửi lại, và stream kẹt vĩnh viễn.

### 5.1 `DATAGRAM` (channel `unreliable`)

```
0x03 | len(varint) | bytes(len)
```
- Một message unreliable nằm trọn trong một frame, không chia mảnh. `len` ≤ **1100** [kiến trúc §6.2]; message lớn hơn bị `send()` từ chối.

### 5.2 `ACK`

```
0x01 | largest_pn_low(4) | ack_delay(u16, đơn vị 32µs) | mask_flags(1) | ack_bits bytes…
```

- `largest_pn_low`: 4 byte thấp của `pn` lớn nhất đã nhận từ chiều kia trong kết nối này; dựng lại như `pn` ở §4.1.
- `ack_delay`: thời gian từ lúc nhận `largest_pn` tới lúc gửi frame này, đơn vị 32µs (giống GNS). `0xFFFF` = không có thông tin. Bên gửi dữ liệu dùng nó để đo RTT chính xác mà không cần trường `ts` trong mỗi segment.
- `ack_bits`: 64 bit, bit `n` (0..63) = đã nhận `largest − 1 − n`. Nén kiểu reliable.io: `mask_flags` bit `i` (0..7) = byte `i` của `ack_bits` **có mặt**; byte vắng mặt mang giá trị `0xFF`. Encoding canonical: byte bằng `0xFF` **không được** gửi; bit 0 là byte thấp nhất. Không mất gói thì frame `ACK` dài 8 byte.
- Gói cũ hơn `largest − 64` không được ack theo cách này; bên gửi coi như mất và dựa vào RTO (state machine SP2).

### 5.3 `STREAM` (channel `reliable`)

```
0x02 | offset(varint) | len(varint) | bytes(len)
```

- Một chiều có một byte stream reliable duy nhất, offset bắt đầu từ 0 **cho mỗi kết nối** (resume = reset channel reliable, §6.3 kiến trúc).
- Bên gửi được phép gửi lại một dải byte với ranh giới khác lần trước (GNS). Bên nhận chấp nhận dữ liệu trùng lặp hoặc chồng lấn: phần nằm dưới `consumed_offset` (đã giao đi, không còn trong buffer) bị bỏ qua mà không so sánh; phần chồng lên byte **còn trong buffer** phải khớp từng byte, khác nhau = protocol error, drop gói.
- **Message trong stream:** mỗi message reliable = `len(varint) | bytes(len)`. Cùng framing với stream reliable của WebTransport (§6.2), nên dùng chung code.
- **Trần (receiver obligations)** [Claude, sửa sau review]:
  - `consumed_offset` = số byte đầu stream mà session layer đã lấy ra dưới dạng message hoàn chỉnh. Buffer nhận chứa đúng các byte trong `[consumed_offset, consumed_offset + RECV_WINDOW)`. Dữ liệu `STREAM` có `offset + len` > `consumed_offset + RECV_WINDOW` thì gói bị drop và không ack (§5.0).
  - Message reliable tối đa `MAX_MESSAGE` byte; `len` lớn hơn = protocol error. Ràng buộc `MAX_MESSAGE + 8` (varint dài nhất) ≤ `RECV_WINDOW` bảo đảm message lớn nhất luôn nằm vừa cửa sổ.
  - Số lỗ (gap) trong buffer nhận ≤ **32**. Dữ liệu tạo thêm lỗ vượt trần thì gói bị drop và không ack (§5.0); bên gửi sẽ gửi lại sau, khi các lỗ trước đã được lấp.
  - Việc kiểm các trần này nằm trong bộ ghép stream (SP2); SP1 chỉ chốt giá trị và ý nghĩa.
  - **Hằng số của protocol `ver` = 1, không cấu hình** (hai bên không thể lệch nhau, vì không quảng bá trên wire): `RECV_WINDOW` = **512 KiB**, `MAX_MESSAGE` = **256 KiB**. Muốn đổi thì tăng `ver`.

**Quy tắc decode frame** [Claude, khi hiện thực]: decode trả về **lỗi đầu tiên theo thứ tự byte**. `DATAGRAM` có `len` > 1100 → `too_large`, kiểm **trước** khi kiểm dữ liệu bị cắt. `STREAM` có `offset + len` > 2^62 − 1 → `value_too_large`, cũng kiểm trước khi kiểm dữ liệu bị cắt. `ACK` thứ hai → `duplicate_ack`, báo tại byte loại của nó. `STREAM` và `DATAGRAM` có độ dài 0 là hợp lệ.

Codec frame thuộc SP1. Logic **dùng** các frame này (khi nào gửi `ACK`, khi nào gửi lại byte nào, pacing) thuộc SP2.

---

## 6. Framing cho WebRTC và WebTransport

[người dùng] chỉ có `reliable` và `unreliable`, nên framing ở hai transport này rất mỏng:

### 6.1 WebRTC

| Channel | Đi trên | Framing |
|---|---|---|
| `reliable` | data channel `reliable` (`negotiated: true`, id **0**) | không có: mỗi message của data channel = một message của glassy |
| `unreliable` | data channel `unreliable` (`negotiated: true`, id **1**, `ordered:false, maxRetransmits:0`) | không có |

- Message đầu tiên client gửi trên `reliable` **phải** là server ticket (bytes thô, §3.2). Server đóng kết nối nếu không nhận được ticket hợp lệ trong 5s (§6.3 kiến trúc).
- Id của data channel là quyết định [Claude].

### 6.2 WebTransport

| Channel | Đi trên | Framing |
|---|---|---|
| `reliable` | một bidi stream do client mở ngay sau khi session WT được thiết lập | `len(varint) | bytes(len)`, giống message trong `STREAM` của native (§5.3) |
| `unreliable` | datagram | không có: payload datagram = message |

- Server ticket đi trong path của extended CONNECT: `/glassy?t=<base64url server ticket>` (§3.6 kiến trúc). Ticket WT không có key native, dài tối đa 394 byte, nên path dài nhất là `/glassy?t=` + 526 ký tự.
- Trần message reliable giống native (`MAX_MESSAGE` = 256 KiB).
- [Claude, khi hiện thực] **Thứ tự parse path:** path dài hơn 536 byte → `too_large`; không có tiền tố `/glassy?t=` hoặc có `&` hay `#` → `bad_encoding`; base64url lỗi → `bad_encoding`; ticket ∉ [75, 394] byte → `bad_length` (với ticket dài thì không tới được vì trần path đã chặn trước).

### 6.3 Phía HTML5 [Claude, sau review]

- Client HTML5 chỉ dùng WebRTC hoặc WebTransport (§6.1, §6.2); **không** dùng gói native (§4) và frame (§5). Phần SP1 mà nó cần: parse `ConnectInfo`, server ticket (message đầu tiên với WebRTC, trong URL với WT), framing `len` của stream WT.
- **JS không parse gì của `glassy-proto`.** `library_glassy.js` chỉ chuyển bytes giữa API của browser và phần C++ chạy trong WASM. Parse `ConnectInfo`, framing `len` của stream WT và kiểm tra đều do `glassy_proto_core` (C++) làm. Vì vậy không cần bản JS của vectors.
- `glassy_proto_core` phải build được bằng Emscripten. CI của SP1 có một bước build WASM và chạy các test vectors dưới Node (không có ngưỡng kích thước cho WASM ở SP1).

---

## 7. Golden vectors

- Thư mục: `vectors/` ở gốc repo. File JSON, mỗi file một hạng mục, do test Rust `#[ignore]` sinh ra và commit vào repo (CONVENTIONS §2.3).
- Mỗi file có hai loại case:
  - **valid**: input (key, nonce, field) → bytes mong đợi, và chiều ngược lại;
  - **invalid**: bytes → mã lỗi mong đợi. Mỗi "receiver obligation" ở trên có ít nhất một case invalid.
- Mọi nguồn ngẫu nhiên (nonce, `conn_id`) được cố định trong vectors để kết quả tất định.
- Danh sách tối thiểu: `routing_ticket.json`, `server_ticket.json`, `ice_pwd.json`, `retry_token.json`, `connect_info.json`, `native_packets.json` (`CONNECT`/`ACCEPT`/`DATA`/`DISCONNECT`/`REJECT`, dựng lại `pn`, cửa sổ replay), `frames.json` (`ACK`/`STREAM`/`DATAGRAM`, varint canonical), `wt_framing.json`.
- Rust test sinh vectors; Rust test khác đọc lại để kiểm tra; C++ test (GoogleTest) đọc cùng file. Mã lỗi được đặt tên giống nhau ở hai ngôn ngữ (ví dụ `bad_version`, `auth_failed`, `expired`, `non_canonical_varint`) để so sánh được.
- Vectors cho thuật toán chuẩn lấy known-answer từ RFC (XChaCha20-Poly1305 từ draft-irtf-cfrg-xchacha, AES-128-GCM, HKDF RFC 5869, HMAC-SHA256 RFC 4231, varint RFC 9000 §16) và chép vào `tests/fixtures/*.hex` theo CONVENTIONS.

### 7.1 Bảng mã lỗi [Claude, khi hiện thực]

27 mã, chuỗi snake_case giống hệt ở Rust (`crates/glassy-proto/src/error.rs`, `Error::code()`) và C++. Vectors so sánh bằng chuỗi này.

| Mã | Ý nghĩa |
|---|---|
| `truncated` | Input kết thúc giữa chừng một trường. |
| `bad_length` | Độ dài sai (ngoài khoảng cho phép, không khớp trường, hoặc thiếu byte). |
| `bad_type` | Byte loại gói không đúng với ngữ cảnh. |
| `bad_version` | `ver` hoặc `v` không được hỗ trợ. |
| `unknown_key` | `key_id` không có trong key ring. |
| `auth_failed` | AEAD, `proof_tag` hoặc tag token không hợp lệ. |
| `expired` | `expiry` đã qua so với now. |
| `reserved_nonzero` | Bit hoặc byte reserved khác 0. |
| `bad_transport` | Transport không hợp lệ, không được phép hoặc không khớp. |
| `session_mismatch` | `session_id` không khớp giữa các thành phần. |
| `wrong_server` | `server_id` trong ticket không phải của game server này. |
| `bad_user_id` | `user_id` có độ dài sai hoặc không phải UTF-8. |
| `bad_metadata` | `metadata_len` vượt 256. |
| `bad_padding` | Padding của `CONNECT` có byte khác 0. |
| `bad_trailer` | Trailer `client_addr` sai. |
| `non_canonical_varint` | Varint không ở dạng ngắn nhất. |
| `value_too_large` | Giá trị vượt giới hạn số học (ví dụ offset + len > 2^62 − 1). |
| `too_large` | Gói, message hoặc path vượt trần kích thước. |
| `duplicate_ack` | Có hơn một frame `ACK` trong gói. |
| `non_canonical_ack` | `ACK` không ở dạng canonical (gửi byte `0xFF`, hoặc mask không khớp). |
| `bad_token_type` | Token Retry có `bit7` = 1. |
| `bad_odcil` | ODCIL của token Retry ngoài [8, 20]. |
| `bad_encoding` | Base64, UTF-8, tiền tố hay ký tự không hợp lệ. |
| `bad_json` | `ConnectInfo` không phải JSON hợp lệ hoặc vi phạm cấu trúc. |
| `too_old` | `pn` rơi ra ngoài cửa sổ replay (`pn` + 256 ≤ `largest`). |
| `replayed` | `pn` đã nhận, hoặc `pn` = 0. |
| `buffer_too_small` | Chỉ encoder trả về: buffer đầu ra quá nhỏ. |

---

## 8. Hiện thực

### 8.1 Bố cục repo [Claude]

```
Cargo.toml                 ← workspace gốc (members: crates/*), theo mẫu CONVENTIONS §3.2
.cargo/config.toml, .config/nextest.toml
crates/glassy-proto/       ← crate Rust
cpp/glassy-proto/          ← lib C++ (CMake), có thư mục third_party/monocypher
vectors/                   ← golden vectors (JSON)
.github/workflows/proto.yml
```

`spikes/` vẫn là workspace riêng và không bị phụ thuộc vào. Code spike (ticket, ICE pwd, token Retry) được **chép và làm lại** vào crate mới với kiểm tra đầy đủ, không import.

### 8.2 Crate Rust `glassy-proto`

- Edition 2024, lỗi bằng enum riêng, không `unwrap`/`expect`/index không kiểm tra trên dữ liệu mạng (CONVENTIONS §4).
- Parse không cấp phát (trả view mượn từ buffer) cho các đường gateway dùng: `CONNECT`, routing ticket, token Retry.
- Crypto: crate RustCrypto (`aes-gcm`, `chacha20poly1305` với `XChaCha20Poly1305`, `hmac`, `hkdf`, `sha2`) như spike.
- Có API mint/encode cho broker và cho client test/bench (Rust test client dùng ở SP2).

### 8.3 Lib C++ `glassy-proto`

- C++20, namespace `glassy::proto`, build không exceptions và không RTTI (`-fno-exceptions -fno-rtti`) vì client dùng chung; lỗi trả bằng enum/`expected`-style.
- Không cấp phát động trên đường parse; buffer có kích thước cố định.
- Crypto:
  - **XChaCha20-Poly1305 bằng Monocypher** (vendor, CC0/BSD-2) cho **cả client và server** [Claude]. Một implementation, một bộ test, và nhỏ. Điều này làm rõ câu "client dùng Monocypher, server dùng GnuTLS/nettle" ở §3.4 kiến trúc: GnuTLS vẫn dùng cho DTLS/QUIC trong server SDK, còn AEAD của native và server ticket dùng Monocypher ở cả hai phía.
  - **HMAC-SHA256/HKDF (ICE pwd) chỉ có ở target server.** Target client **không được** link phần này, cũng không link GnuTLS/nettle. Builder chọn nguồn SHA-256 cho target server (nettle sẵn có trong server SDK, hoặc một implementation nhỏ được vendor).
- Hai target CMake: `glassy_proto_core` (client + server) và `glassy_proto_server` (thêm ICE pwd, parse token Retry, mở server ticket).
- Ngân sách kích thước: `glassy_proto_core` build `-Os`, strip, ≤ **40KB** trên x86_64 và arm64 [Claude] (phần còn lại của 150KB dành cho session layer, reliability và socket ở SP2). CI đo và fail nếu vượt.

### 8.4 Testing

| Loại | Rust | C++ |
|---|---|---|
| Unit + golden vectors | `cargo nextest run -p glassy-proto` | GoogleTest + CTest |
| Known-answer RFC | `tests/fixtures/*.hex` | đọc cùng fixtures |
| Fuzz | `cargo-fuzz` cho mọi parser gateway dùng (`CONNECT`, routing ticket, token Retry, `ConnectInfo`) | libFuzzer + ASan/UBSan cho mọi parser (gói native, frames, server ticket, `ConnectInfo`, token Retry) |
| Differential | một CLI nhỏ ở mỗi ngôn ngữ đọc bytes, in kết quả decode dạng JSON canonical; CI chạy cả hai trên corpus fuzz chung và so sánh từng dòng | |
| Property | roundtrip encode → decode cho mọi frame và gói (proptest) | |

CI (`.github/workflows/proto.yml`): fmt, clippy `-D warnings`, nextest, build C++ với `-Wall -Wextra -Werror`, ctest, build Emscripten + chạy vectors dưới Node (§6.3), đo kích thước `glassy_proto_core` (hiệu `text + data` của `size -B` giữa `size_probe` và `size_baseline`, luôn build MinSizeRel nên không phụ thuộc build type; chạy trên cả x86_64 và arm64), fuzz smoke 60 giây cho mỗi target, differential trên corpus. Giới hạn song song theo CONVENTIONS §3.

---

## 9. Thay đổi đối với spec kiến trúc

Khi spec này được duyệt, cập nhật spec kiến trúc cho khớp:

| Mục kiến trúc | Thay đổi |
|---|---|
| §3.3 Server ticket | thêm `ver` và `server_id`; key `K_ticket` dẫn xuất bằng HKDF từ `K_gs`; XChaCha20-Poly1305 với nonce 24 byte; một ticket cho mỗi transport |
| §3.4 Native UDP | byte loại `0x80–0x84` (thêm `REJECT`); `conn_id` cho proof, `server_nonce` do server sinh cho mọi gói sau `ACCEPT`, nonce `server_nonce|pn`; `pn` 4 byte trên wire; `connect_seq` tăng dần thay cho timestamp trong cửa sổ; hành vi session ở §4.7 (SP2); trailer `client_addr` có byte `family` ở cuối; layout theo §4 |
| §6.6 Mã lỗi client | thêm nguồn cho `auth_failed` và các lỗi bị từ chối: gói `REJECT` (§4.6) |
| §3.4 AEAD mặc định | XChaCha20-Poly1305, Monocypher ở cả client và server |
| §6.2 Channel | MVP chỉ `reliable` và `unreliable`; `unreliable_sequenced` để sau. Native reliable dùng byte stream có offset (§5.3) |
| §13 Điểm mở | bỏ dòng "giá trị byte cụ thể của các loại gói native" |

---

## 10. Phần để builder tự quyết

- Tên API cụ thể của crate Rust và lib C++, cách chia module.
- Cách sinh corpus fuzz ban đầu và số lượng case trong mỗi file vectors (miễn đạt yêu cầu ở §7).
- Chọn nguồn SHA-256 cho target server C++ (§8.3).
- Parser JSON tối giản cho `ConnectInfo` ở C++: tự viết hay vendor một parser nhỏ không cấp phát (miễn tuân trần ở §3.5).
- Cấu hình chi tiết của CI (runner, cache).

---

## 11. Phụ lục: so sánh các thư viện tham chiếu

Đọc source (bản clone ngày 2026-10-23), dùng để chọn thiết kế reliability ở §4–§5:

| | netcode + reliable.io + yojimbo | KCP | GameNetworkingSockets |
|---|---|---|---|
| Seq | 2 seq: netcode 64 bit (nonce), reliable 16 bit (ack) | `sn` cho mỗi segment | packet number dùng cho cả nonce và ack |
| Ack | `ack` + `ack_bits` 32 bit, byte `0xFF` được lược bỏ (header 4–9B) | ack segment 24B cho mỗi segment, có `ts` | latest + ack delay + khối ACK/NACK nén RLE + `stop_waiting` |
| Message reliable | `msg_id` 16 bit; message lớn đi theo block, từng block một | `sn` + `frg` (≤ 255 mảnh) | byte stream có offset; message được đóng khung bên trong stream |
| Resend | cố định 100ms | RTO từ RTT (nodelay ×1.5) + fast resend | theo NACK (chờ 3ms) + RTO = 3×RTT + 50ms |
| Kiểm soát tốc độ | không | cwnd/ssthresh kiểu TCP | token bucket tốc độ cố định (bản open source không ước lượng băng thông; mặc định 256KB/s) |
| Chống peer xấu | "Receiver obligations", encoding canonical | chỉ kiểm `len`, `cmd`, `conv` | trần số lỗ (62 lỗ gói, 20–30 lỗ stream) |
| Test | fuzz (oss-fuzz), soak, conformance vector | simulator mất gói 10% | test kết nối |

Những gì glassy lấy:
- **Từ GNS:** một packet number cho nonce và ack; reliable là byte stream có offset; `ack_delay`; trần số lỗ. Resend theo NACK + RTO, cùng pacing bằng token bucket, để SP2.
- **Từ reliable.io:** `ack_bits` lược bỏ byte `0xFF`; encoding canonical bắt buộc.
- **Từ netcode:** cửa sổ chống replay 256; danh sách receiver obligations; fuzz + soak + conformance vector.
- **Không lấy:** header 24B mỗi segment của KCP; cơ chế 2 seq của reliable.io/yojimbo; resend cố định 100ms của yojimbo.
