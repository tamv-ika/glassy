# SP1 `glassy-proto` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Hiện thực hợp đồng byte `glassy-proto` (ticket, `ConnectInfo`, gói native, frame, framing WT) bằng một crate Rust và một lib C++ khớp nhau từng byte, kiểm chứng bằng golden vectors, fuzz, differential và CI.

**Architecture:** Rust là implementation tham chiếu và sinh `vectors/*.json`; C++ đọc cùng vectors và phải cho cùng kết quả hoặc cùng mã lỗi. Mọi hàm là hàm thuần (không state session, không socket); state session thuộc SP2 (spec §4.7). C++ chia hai target: `glassy_proto_core` (client + server, chỉ Monocypher) và `glassy_proto_server` (thêm phần cần SHA-256, dùng nettle).

**Tech Stack:** Rust 1.90 edition 2024 (RustCrypto: `aes-gcm` 0.11.1, `chacha20poly1305` 0.11.0, `hkdf` 0.13.0, `hmac` 0.13.0, `sha2` 0.11.1; `base64` 0.23.1, `data-encoding` 2.11.1, `serde` 1 + `serde_json` 1.0.154; dev: `hex` 0.4.3, `proptest` 1.12.0), cargo-nextest, cargo-fuzz (nightly). C++20, CMake ≥ 3.28, Monocypher 4.0.3 (vendor), nettle ≥ 3.9 (pkg-config, chỉ target server), GoogleTest v1.15.2 + nlohmann/json v3.12.0 (FetchContent, chỉ cho test/tool), libFuzzer (clang 18), Emscripten 5.0.4 + Node 20.

**Spec:** `docs/superpowers/specs/2026-10-23-sp1-glassy-proto-design.md` (gọi tắt **spec**; `§x` không ghi nguồn là của spec này).

## Global Constraints

- Tuân `CONVENTIONS.md`: comment, tên, log, lỗi, tên test, commit bằng tiếng Anh; test Rust chạy bằng `cargo nextest run`, không dùng `cargo test` (trừ `--doc`).
- Chống OOM: `[build] jobs = 2`, nextest `test-threads = 2`, integration test chạy tuần tự, `cmake --build … --parallel 2`, `ctest -j2 --timeout 120`. Fuzz chạy `-jobs=1 -workers=1 -rss_limit_mb=2048`.
- Rust: edition 2024, `cargo fmt`, `cargo clippy --all-targets -- -D warnings`. Không `unwrap`/`expect`/index không kiểm tra trên dữ liệu mạng; lỗi bằng enum `glassy_proto::Error`.
- C++: C++20, `clang-format` (Google, ColumnLimit 100), `-Wall -Wextra -Werror` cho code của mình, `-fno-exceptions -fno-rtti`, namespace `glassy::proto`, hàm `snake_case`, type `PascalCase`, hằng `kPascalCase`. Không cấp phát động trong lib; input là `std::span<const uint8_t>`, output vào buffer do caller cấp.
- Production không phụ thuộc `spikes/`; code spike được chép và làm lại.
- Số nguyên cố định: big-endian. Varint: QUIC (RFC 9000 §16), encoder dạng ngắn nhất, decoder từ chối dạng không tối thiểu (`non_canonical_varint`), giá trị ≤ 2^62−1.
- Datagram native ≤ **1200** byte (+8 byte trailer ở phía game server). Trường reserved: ghi 0, đọc khác 0 → `reserved_nonzero`.
- Base64: `std` không padding cho ICE ufrag/pwd; `url` không padding cho mọi chỗ khác. Decoder từ chối padding, ký tự ngoài bảng, và bit thừa khác 0 ở ký tự cuối (`bad_encoding`).
- Hằng số protocol `ver` = 1: `MAX_DATAGRAM` = 1100, `MAX_MESSAGE` = 262144, `RECV_WINDOW` = 524288, `MAX_STREAM_GAPS` = 32, `REPLAY_WINDOW` = 256, `MAX_CONNECT_INFO_JSON` = 4096. Rust và C++ cùng export các tên này.
- Mã lỗi: chỉ dùng danh sách ở Task 1, chuỗi giống hệt ở hai ngôn ngữ.

## Review Focus

1. **Mọi độ dài cắt ngắn.** Mọi parser nhận mọi prefix của một input hợp lệ (độ dài 0..=n) và mọi input dài thêm 1 byte phải trả lỗi, không panic hay đọc ngoài buffer. Test: `every_prefix_is_rejected` trong Task 13 (Rust, chạy trên mọi case valid của mọi file vectors) và `EveryPrefixIsRejected` trong Task 19 (C++ dưới ASan).
2. **`pn` quanh biên 2^32.** Khi `largest` = `0xFFFF_FFF0` hoặc `0x1_0000_0005` và 4 byte thấp nhảy qua biên, `pn` dựng lại phải đúng. Test: `decode_pn_crosses_32_bit_boundary` (Task 7), và cùng các case trong `native_packets.json`.
3. **`ConnectInfo` hợp lệ nhưng lạ.** Thứ tự key bị xáo, có whitespace, trường lạ chứa escape hoặc unicode hay object lồng nhau: phải được chấp nhận. Escape trong trường đã biết, key trùng, độ sâu > 8: phải bị từ chối, giống nhau ở hai ngôn ngữ. Test: các case `shuffled_keys`, `unknown_nested_field`, `escape_in_unknown_field`, `escape_in_known_field`, `duplicate_key`, `depth_9` trong `connect_info.json` (Task 6).
4. **Biên `expiry`.** Ticket có `expiry == now` thì hợp lệ, `expiry == now - 1` thì `expired`; token Retry có `now == expiry` thì hợp lệ, `now == expiry + 1` thì `expired`. Test: case `expiry_equals_now` và `expired_by_one` trong `routing_ticket.json`, `server_ticket.json`, `retry_token.json` (Task 3–5).
5. **Trailer giả.** Client tự gắn 8 byte giống trailer vào `CONNECT` rồi gửi thẳng tới game server. Vì `verify_connect` không tự bóc trailer, gói phải bị từ chối với `bad_padding`. Test: case `fake_trailer_without_split` trong `native_packets.json` (Task 8).

### Giá trị cố định dùng trong mọi vectors và test

| Tên | Giá trị |
|---|---|
| `K_gw` (routing ticket) | `11` × 16, `key_id` = 1 |
| `K_gs` | `22` × 32, `key_id` = 1 |
| `K_retry_gw` | `33` × 32 |
| `key_c2s` / `key_s2c` | `44` × 32 / `55` × 32 |
| `server_id` | `ab` × 16 |
| `session_id` | `0102030405060708` |
| `conn_id` | `66` × 16 |
| `server_nonce` | `77` × 16 |
| nonce ticket | routing `88` × 12; server `99` × 24 |
| `now` / `expiry` | `1900000000` / `2000000000` |
| `user_id` | `"user-1"` |

### Format chung của file vectors

Mỗi file là `{"cases": [ … ]}`. Mỗi case có `"name"` (snake_case, duy nhất trong file), các input (bytes được viết là hex chữ thường trong trường có hậu tố `_hex`), rồi **hoặc** `"expect": { … }` **hoặc** `"error": "<mã lỗi>"`. Trường của từng file được ghi trong task tạo ra file đó. Generator Rust ghi JSON bằng `serde_json::to_string_pretty`, thêm `\n` ở cuối và giữ thứ tự case cố định, để chạy lại không gây diff.

---

### Task 1: Workspace, `Error`, varint

**Files:**
- Create: `Cargo.toml` (workspace gốc), `.cargo/config.toml`, `.config/nextest.toml` (chép nguyên mẫu CONVENTIONS §3.2), `.gitignore` (`/target`, `/build*`, `crates/glassy-proto/fuzz/target`, `crates/glassy-proto/fuzz/corpus`, `crates/glassy-proto/fuzz/artifacts`)
- Create: `crates/glassy-proto/Cargo.toml`, `src/lib.rs`, `src/error.rs`, `src/varint.rs`, `src/consts.rs`
- Create: `crates/glassy-proto/tests/fixtures/varint.hex`, `tests/common/mod.rs`, `tests/kat.rs`

**Interfaces:**
- Produces:
  - `pub enum Error` (đủ 27 biến thể dưới đây), `impl Error { pub fn code(&self) -> &'static str }`, `impl Display` (in `code()`), `impl std::error::Error`.
  - `pub mod varint { pub const MAX: u64 = (1 << 62) - 1; pub fn encoded_len(v: u64) -> Result<usize, Error>; pub fn encode(v: u64, out: &mut Vec<u8>) -> Result<(), Error>; pub fn decode(buf: &[u8]) -> Result<(u64, usize), Error> }` (`decode` trả giá trị và số byte đã đọc).
  - `src/consts.rs` export các hằng số trong Global Constraints, re-export ở gốc crate.
  - `tests/common/mod.rs`: `fn vectors_dir() -> PathBuf` (`<repo>/vectors`), `fn read_fixture(name) -> Vec<(String, Vec<u8>)>` (đọc file `.hex`: mỗi dòng `label: hex`, bỏ dòng trống và dòng bắt đầu bằng `#`), `fn write_vectors(name, &serde_json::Value)`, `fn read_vectors(name) -> serde_json::Value`.

Danh sách mã lỗi (biến thể Rust → `code()`): `Truncated`→`truncated`, `BadLength`→`bad_length`, `BadType`→`bad_type`, `BadVersion`→`bad_version`, `UnknownKey`→`unknown_key`, `AuthFailed`→`auth_failed`, `Expired`→`expired`, `ReservedNonzero`→`reserved_nonzero`, `BadTransport`→`bad_transport`, `SessionMismatch`→`session_mismatch`, `WrongServer`→`wrong_server`, `BadUserId`→`bad_user_id`, `BadMetadata`→`bad_metadata`, `BadPadding`→`bad_padding`, `BadTrailer`→`bad_trailer`, `NonCanonicalVarint`→`non_canonical_varint`, `ValueTooLarge`→`value_too_large`, `TooLarge`→`too_large`, `DuplicateAck`→`duplicate_ack`, `NonCanonicalAck`→`non_canonical_ack`, `BadTokenType`→`bad_token_type`, `BadOdcil`→`bad_odcil`, `BadEncoding`→`bad_encoding`, `BadJson`→`bad_json`, `TooOld`→`too_old`, `Replayed`→`replayed`, `BufferTooSmall`→`buffer_too_small` (chỉ do encoder trả khi buffer output không đủ).

- [ ] **Step 1: Tạo workspace và crate rỗng.** `Cargo.toml` gốc: `[workspace] resolver = "3"`, `members = ["crates/*"]`, `exclude = ["crates/glassy-proto/fuzz", "spikes"]`, cùng các khối `[profile.dev]` lấy từ CONVENTIONS §3.2. Crate `glassy-proto` khai báo dependency đúng version ở Tech Stack. Chạy `cargo build -p glassy-proto`, kết quả mong đợi: build thành công.

- [ ] **Step 2: Viết test thất bại.** File fixture `tests/fixtures/varint.hex` chép nguyên văn ví dụ của RFC 9000 Appendix A.1 (`c2197c5eff14e88c`, `9d7f3e7d`, `7bbd`, `25`, `4025`). Viết các test trong `tests/kat.rs`:
  - `varint_rfc9000_examples`: giá trị lần lượt 151288809941952652, 494878333, 15293, 37. `4025` phải trả `Error::NonCanonicalVarint`, vì RFC chấp nhận dạng này nhưng glassy bắt buộc canonical.
  - Trong `src/varint.rs`, test `encode_uses_shortest_form`: 63 → 1 byte, 64 → 2 byte, 16383 → 2, 16384 → 4, 2^30−1 → 4, 2^30 → 8, `MAX` → 8. `MAX + 1` trả `ValueTooLarge`.
  - Test `decode_truncated`: `[0x40]` và `[]` đều trả `Truncated`.
  - proptest `varint_roundtrip`: với mọi v ≤ `MAX`, `decode(encode(v))` trả `(v, encoded_len(v))`.

- [ ] **Step 3: Chạy `cargo nextest run -p glassy-proto`.** Kết quả mong đợi: FAIL vì `varint` chưa có.

- [ ] **Step 4: Hiện thực `Error`, `varint`, `consts`.** Decoder coi là không canonical nếu giá trị đọc được vẫn vừa trong dạng ngắn hơn.

- [ ] **Step 5: Chạy lại `cargo nextest run -p glassy-proto` và `cargo clippy -p glassy-proto --all-targets -- -D warnings`.** Kết quả mong đợi: PASS, không có cảnh báo.

- [ ] **Step 6: Commit** `feat(proto): add workspace, error codes and canonical varint`.

---

### Task 2: AEAD và dẫn xuất key (Rust)

**Files:**
- Create: `crates/glassy-proto/src/crypto.rs`
- Create: `tests/fixtures/xchacha20poly1305.hex`, `aes128gcm.hex`, `hkdf_sha256.hex`, `hmac_sha256.hex`
- Modify: `tests/kat.rs`

**Interfaces:**
- Produces (module `crypto`):
  - `pub fn xchacha_seal(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], plaintext: &[u8]) -> Vec<u8>`: trả `ciphertext | tag16`.
  - `pub fn xchacha_open(key: &[u8; 32], nonce: &[u8; 24], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, Error>`: `sealed` ngắn hơn 16 byte → `Truncated`; tag sai → `AuthFailed`.
  - `pub fn packet_nonce(server_nonce: &[u8; 16], pn: u64) -> [u8; 24]` = `server_nonce | pn BE`.
  - `pub fn k_ticket(k_gs: &[u8; 32]) -> [u8; 32]` (HKDF-SHA256, salt rỗng, info `"glassy-server-ticket"`).
  - `pub fn k_ice(k_gs: &[u8; 32]) -> [u8; 32]` (info `"glassy-ice"`).
  - `pub fn hmac_sha256(key: &[u8], msg: &[&[u8]]) -> [u8; 32]`.

- [ ] **Step 1: Viết test thất bại.** Fixtures chép nguyên văn từ các nguồn sau: draft-irtf-cfrg-xchacha-03 §A.3.1 (key, nonce, AAD, plaintext, ciphertext, tag); "The Galois/Counter Mode of Operation (GCM)" (McGrew–Viega) Test Case 4; RFC 5869 §A.1 Test Case 1; RFC 4231 §4.3 Test Case 2. Comment đầu mỗi test ghi tên RFC và mục.
  - `xchacha_draft_a31`: seal ra đúng `ciphertext | tag`; open trả lại plaintext; lật 1 bit trong tag → `AuthFailed`.
  - `aes128gcm_test_case_4`: dùng trực tiếp crate `aes-gcm`, khoá dependency dùng ở Task 3.
  - `hkdf_rfc5869_case1`, `hmac_rfc4231_case2`.
  - `k_ticket_differs_from_k_ice`: với `K_gs` = `22`×32, hai key khác nhau và khác `K_gs`.

- [ ] **Step 2: Chạy `cargo nextest run -p glassy-proto --test kat`.** Kết quả mong đợi: FAIL.

- [ ] **Step 3: Hiện thực `crypto.rs`** bằng `chacha20poly1305::XChaCha20Poly1305`, `hkdf::Hkdf<Sha256>`, `hmac::Hmac<Sha256>`. Các lời gọi `expect` chỉ được dùng cho lỗi không thể xảy ra với độ dài cố định, và mỗi chỗ có comment giải thích.

- [ ] **Step 4: Chạy lại test.** Kết quả mong đợi: PASS.

- [ ] **Step 5: Commit** `feat(proto): add XChaCha20-Poly1305 and key derivation with RFC known answers`.

---

### Task 3: Routing ticket (Rust, chỉ gateway và broker dùng)

**Files:**
- Create: `crates/glassy-proto/src/routing_ticket.rs`, `tests/vectors.rs`
- Create (generated): `vectors/routing_ticket.json`
- Tham khảo (không import): `spikes/gw-proto/src/ticket.rs`

**Interfaces:**
- Consumes: `Error` (Task 1).
- Produces:
  - `pub const ROUTING_TICKET_LEN: usize = 60`.
  - `pub mod transport { pub const NATIVE: u8 = 1; pub const WEBRTC: u8 = 2; pub const WEBTRANSPORT: u8 = 4; }` ở gốc crate; Task 4 dùng chung.
  - `pub struct RoutingTicket { pub server_id: [u8; 16], pub session_id: [u8; 8], pub expiry: u32, pub transports: u8 }`.
  - `pub struct RoutingKeyRing`, với `new(current_id: u8, key: [u8; 16])`, `insert(id, key)`, `current_id()`. Trần 16 key; `insert` thêm key thứ 17 trả `Err(TooLarge)`.
  - `pub fn seal_routing(t: &RoutingTicket, ring: &RoutingKeyRing, nonce: [u8; 12]) -> [u8; 60]`. `flags` luôn ghi 0.
  - `pub fn open_routing(b: &[u8], ring: &RoutingKeyRing, now: u32, via: u8, connect_session_id: Option<&[u8; 8]>) -> Result<RoutingTicket, Error>`.
  - `pub fn to_ufrag(&[u8; 60]) -> String`, `pub fn from_ufrag(&str) -> Result<[u8; 60], Error>`, `pub fn to_sni_labels(&[u8; 60]) -> String`, `pub fn from_sni(host: &str, suffix: &str) -> Result<[u8; 60], Error>`.

Thứ tự kiểm tra trong `open_routing` (chốt để vectors và differential khớp nhau):
1. len ≠ 60 → `BadLength`
2. `ver` ≠ 1 → `BadVersion`
3. `key_id` không có trong ring → `UnknownKey`
4. AEAD sai → `AuthFailed`
5. `flags` ≠ 0, hoặc `transports` có bit ngoài `0x07` → `ReservedNonzero`
6. `expiry < now` → `Expired`
7. `transports & via == 0` → `BadTransport`
8. `connect_session_id` có giá trị và khác `session_id` → `SessionMismatch`

`open_routing` không cấp phát: giải mã in-place (`decrypt_in_place_detached`) vào mảng 30 byte trên stack (spec §8.2).

Decode ufrag và SNI: ufrag phải đúng 80 ký tự, mỗi nhãn SNI phải đúng 48 ký tự, nếu không → `BadLength`. Ký tự ngoài bảng → `BadEncoding`. Host không kết thúc bằng `.{suffix}` → `BadEncoding`.

Schema `routing_ticket.json`: các trường `ticket_hex`, `via`, `now`, `connect_session_id_hex` (có thể vắng), `ufrag`, `sni` (với case valid); `expect` = `{server_id_hex, session_id_hex, expiry, transports}`.

- [ ] **Step 1: Viết test thất bại.** Trong module:
  - `seal_open_roundtrip`;
  - một test cho mỗi bước kiểm tra ở trên (mỗi test chỉ vi phạm đúng một điều kiện);
  - `ufrag_is_ice_char_only`;
  - `sni_case_insensitive`.

  Trong `tests/vectors.rs`:
  - `write_routing_ticket_vectors` (`#[ignore]`), với các case: `valid_native`, `valid_webrtc_ufrag`, `valid_wt_sni`, `expiry_equals_now`, `expired_by_one`, `bad_length_59`, `bad_version`, `unknown_key`, `tampered_tag`, `flags_nonzero`, `reserved_transport_bit`, `transport_not_allowed`, `session_mismatch`;
  - `check_routing_ticket_vectors`: đọc lại file, so từng case.

- [ ] **Step 2: Chạy test.** Kết quả mong đợi: FAIL.

- [ ] **Step 3: Hiện thực `routing_ticket.rs`.**

- [ ] **Step 4: Sinh vectors và kiểm tra:**
  ```bash
  cargo nextest run -p glassy-proto --run-ignored only -E 'test(write_routing_ticket_vectors)'
  cargo nextest run -p glassy-proto
  ```
  Kết quả mong đợi: PASS và có file `vectors/routing_ticket.json`. Chạy generator lần nữa rồi `git diff --exit-code vectors/`: không có diff.

- [ ] **Step 5: Commit** `feat(proto): add routing ticket with full receiver checks and vectors`.

---

### Task 4: Server ticket (Rust)

**Files:**
- Create: `crates/glassy-proto/src/server_ticket.rs`
- Modify: `tests/vectors.rs`
- Create (generated): `vectors/server_ticket.json`

**Interfaces:**
- Consumes: `crypto::{xchacha_seal, xchacha_open, k_ticket}`, `transport`.
- Produces:
  - `pub struct ServerTicket { pub user_id: String, pub server_id: [u8; 16], pub session_id: [u8; 8], pub expiry: u32, pub transport: u8, pub native_keys: Option<NativeKeys>, pub metadata: Vec<u8> }`.
  - `pub struct NativeKeys { pub c2s: [u8; 32], pub s2c: [u8; 32] }`.
  - `pub struct ServerKeyRing`: `new(current_id, k_gs: [u8; 32])`, `insert`, trần 16 key. Ring lưu sẵn `k_ticket` đã dẫn xuất.
  - `pub fn seal_server(t: &ServerTicket, ring: &ServerKeyRing, nonce: [u8; 24]) -> Result<Vec<u8>, Error>`. Encoder từ chối `user_id` rỗng hoặc dài hơn 64 byte (`BadUserId`), `metadata` dài hơn 256 (`BadMetadata`), `native_keys` không khớp `transport` (`BadTransport`).
  - `pub fn open_server(b: &[u8], ring: &ServerKeyRing, now: u32, self_server_id: &[u8; 16], via: u8) -> Result<ServerTicket, Error>`.
  - `pub const SERVER_TICKET_MIN: usize = 75; pub const SERVER_TICKET_MAX: usize = 458; pub const SERVER_TICKET_NATIVE_MIN: usize = 139;`

Thứ tự kiểm tra trong `open_server`:
1. len ∉ [75, 458] → `BadLength`
2. `ver` ≠ 1 → `BadVersion`
3. `key_id` lạ → `UnknownKey`
4. AEAD sai → `AuthFailed`
5. Parse body tuần tự:
   - `user_id_len` ∉ [1, 64] → `BadUserId`;
   - thiếu byte ở bất kỳ trường nào → `BadLength`;
   - `transport` ∉ {1, 2, 4} → `BadTransport`;
   - nếu native thì đọc 64 byte key;
   - `metadata_len` > 256 → `BadMetadata`;
   - số byte còn lại ≠ `metadata_len` → `BadLength`.
6. `user_id` không phải UTF-8 → `BadUserId`
7. `server_id` ≠ `self_server_id` → `WrongServer`
8. `expiry < now` → `Expired`
9. `transport` ≠ `via` → `BadTransport`

Schema `server_ticket.json`: `ticket_hex`, `now`, `self_server_id_hex`, `via`; `expect` = `{user_id, server_id_hex, session_id_hex, expiry, transport, key_c2s_hex?, key_s2c_hex?, metadata_hex}`.

- [ ] **Step 1: Viết test thất bại.**
  - `seal_open_roundtrip_native` và `seal_open_roundtrip_webrtc`.
  - `sizes_match_spec`: ticket WebRTC với `user_id` 1 byte và metadata rỗng dài 75; native tối thiểu 139; native với `user_id` 64 byte và metadata 256 byte dài 458.
  - Một test cho mỗi bước kiểm tra. Các ticket hỏng sau AEAD (ví dụ `user_id_len` = 0) được tạo bằng cách tự ghép body rồi gọi `xchacha_seal`.
  - Generator `write_server_ticket_vectors` với các case: `valid_native`, `valid_webrtc`, `valid_wt_max_size`, `expiry_equals_now`, `expired_by_one`, `too_short_74`, `too_long_459`, `bad_version`, `unknown_key`, `tampered`, `user_id_len_zero`, `user_id_len_65`, `user_id_not_utf8`, `transport_three`, `native_without_keys` (transport native nhưng body hết sau `transport`, nên thiếu byte → `BadLength`), `metadata_257`, `trailing_byte`, `wrong_server`, `via_mismatch`.
  - Test `check_server_ticket_vectors`.

- [ ] **Step 2: Chạy test.** Kết quả mong đợi: FAIL.
- [ ] **Step 3: Hiện thực.**
- [ ] **Step 4: Sinh vectors, chạy toàn bộ test, kiểm tra generator chạy lại không tạo diff.** Kết quả mong đợi: PASS.
- [ ] **Step 5: Commit** `feat(proto): add XChaCha20 server ticket with server_id binding`.

---

### Task 5: ICE pwd và token Retry (Rust)

**Files:**
- Create: `crates/glassy-proto/src/ice.rs`, `src/retry.rs`
- Modify: `tests/vectors.rs`
- Create (generated): `vectors/ice_pwd.json`, `vectors/retry_token.json`
- Tham khảo: `spikes/gw-proto/src/ice.rs`, `spikes/gw-proto/src/quic/retry.rs`, `spikes/vectors/*.json`

**Interfaces:**
- Produces:
  - `pub fn ice_pwd(k_gs: &[u8; 32], ufrag: &str) -> String` (43 ký tự).
  - `pub fn mint_retry_token(key: &[u8; 32], odcid: &[u8], client: SocketAddr, rscid: &[u8], expiry: u64) -> Result<Vec<u8>, Error>`. `odcid` dài ngoài [8, 20] → `BadOdcil`; `rscid` dài hơn 20 → `BadLength`.
  - `pub fn validate_retry_token(key, token: &[u8], client: SocketAddr, packet_dcid: &[u8], now: u64) -> Result<&[u8], Error>` (trả ODCID, mượn từ `token`).
  - `pub fn retry_token_odcid(token: &[u8]) -> Result<&[u8], Error>`: phần C++ cũng có; không kiểm tag.

Thứ tự kiểm tra:
1. token rỗng → `BadLength`
2. bit7 = 1 → `BadTokenType`
3. ODCIL ∉ [8, 20] → `BadOdcil`
4. len ≠ 1 + ODCIL + 8 + 16 → `BadLength`
5. (chỉ khi validate) tag sai → `AuthFailed`
6. (chỉ khi validate) `now > expiry` → `Expired`

Schema:
- `ice_pwd.json`: `{k_gs_hex, ufrag, pwd}`. Có case `spike_evtj`, giữ đúng giá trị của `spikes/vectors/ice_pwd.json`.
- `retry_token.json`: `token_hex, client, dcid_hex, now`, kèm `"mode": "validate" | "parse"`; `expect` = `{odcid_hex}`.

- [ ] **Step 1: Viết test thất bại.**
  - `ice_pwd_known_answer`: dùng hai giá trị của spike (`evtj`, `evtk`).
  - Mỗi bước kiểm tra Retry có một test.
  - `parse_ignores_tag`: token có tag sai vẫn trả ODCID ở mode parse.
  - Generator Retry với các case: `valid_ipv4`, `valid_ipv6`, `expiry_equals_now`, `expired_by_one`, `empty`, `type_bit_set`, `odcil_7`, `odcil_21`, `length_mismatch`, `wrong_client_port`, `wrong_dcid`, `parse_only_bad_tag`.
- [ ] **Step 2: Chạy test.** Kết quả mong đợi: FAIL.
- [ ] **Step 3: Hiện thực.**
- [ ] **Step 4: Sinh vectors và chạy test.** Kết quả mong đợi: PASS.
- [ ] **Step 5: Commit** `feat(proto): add ICE pwd derivation and Retry token codec`.

---

### Task 6: `ConnectInfo` (Rust)

**Files:**
- Create: `crates/glassy-proto/src/connect_info.rs`
- Modify: `tests/vectors.rs`
- Create (generated): `vectors/connect_info.json`

**Interfaces:**
- Produces:
  - `pub struct ConnectInfo { pub session_id: [u8; 8], pub expiry: u32, pub native: Option<NativeInfo>, pub webrtc: Option<WebRtcInfo>, pub webtransport: Option<WtInfo> }`.
  - `NativeInfo { gateways: Vec<String>, routing_ticket: [u8; 60], server_ticket: Vec<u8>, key_c2s: [u8; 32], key_s2c: [u8; 32] }`.
  - `WebRtcInfo { candidates: Vec<String>, ice_ufrag: String, ice_pwd: String, dtls_fingerprint: String, server_ticket: Vec<u8> }`.
  - `WtInfo { url: String, cert_sha256: [u8; 32] }`.
  - `pub fn encode_connect_info(ci: &ConnectInfo) -> Result<String, Error>`: trả base64url của JSON compact. Thứ tự key cố định như ví dụ ở spec §3.5, `"v": 1` đứng đầu, vắng khối `None`.
  - `pub fn decode_connect_info(s: &str) -> Result<ConnectInfo, Error>`.

Quy tắc decode (C++ ở Task 16 làm đúng y như vậy):
1. `s.len()` > 5462 (= ⌈4096·4/3⌉) → `TooLarge`. Base64url hỏng → `BadEncoding`. JSON dài hơn 4096 → `TooLarge`.
2. JSON phải là một object ở top level, không có gì theo sau ngoài whitespace JSON. Độ sâu lồng `{`/`[` > 8 → `BadJson`; kiểm bằng một lượt quét byte riêng (bỏ qua nội dung string) trước khi gọi serde.
3. Key trùng ở bất kỳ object nào đã biết → `BadJson`. Trường lạ được bỏ qua ở mọi cấp, kể cả khi chứa escape hoặc object lồng.
4. String của trường đã biết không được chứa escape `\`. Rust bắt điều này bằng cách deserialize vào `&'a str` mượn (serde_json lỗi khi gặp escape). Lỗi → `BadJson`.
5. `v` là số nguyên = 1, ngược lại `BadVersion`. `expiry` là số nguyên trong u32, không có phần thập phân hay số mũ, nếu không → `BadJson`.
6. `session_id`: đúng 16 ký tự hex **chữ thường**, nếu không → `BadEncoding`.
7. Phải có ít nhất một khối transport, nếu không → `BadJson`. Thiếu trường bắt buộc trong một khối, hoặc sai kiểu → `BadJson`.
8. `gateways` và `candidates`: 1..=4 phần tử, mỗi phần tử 1..=64 byte, nếu không → `TooLarge` (vượt trần) hoặc `BadJson` (rỗng).
9. Độ dài sau decode:
   - `routing_ticket` = 60;
   - `server_ticket` native ∈ [139, 458] và WebRTC ∈ [75, 394];
   - `key_*` = 32, `cert_sha256` = 32;
   - `ice_ufrag` đúng 80 và `ice_pwd` đúng 43 ký tự trong bảng base64 std;
   - `dtls_fingerprint` 1..=128 byte ASCII in được;
   - `url` 1..=1024 byte và bắt đầu bằng `https://`.

   Sai độ dài → `BadLength`; sai ký tự → `BadEncoding`.

Schema `connect_info.json`: `input` (chuỗi base64url), hoặc `json` (chuỗi JSON thô, khi đó test tự encode base64url trước). `expect` = các trường đã decode, bytes viết bằng hex.

- [ ] **Step 1: Viết test thất bại.**
  - `roundtrip_all_blocks`.
  - `max_size_fits`: cả 3 khối, ticket lớn nhất, 4 gateway 64 byte, nên JSON ≤ 4096.
  - Generator với các case:
    - valid: `native_only`, `webrtc_only`, `wt_only`, `all_blocks`, `shuffled_keys`, `whitespace_everywhere`, `unknown_top_field`, `unknown_nested_field`, `escape_in_unknown_field`, `unicode_in_unknown_field`;
    - invalid: `v_2`, `v_string`, `depth_9`, `duplicate_key`, `escape_in_known_field`, `uppercase_session_id`, `no_transport_block`, `missing_key_c2s`, `gateways_empty`, `gateways_5`, `ticket_too_short`, `base64_padding`, `base64_nonzero_trailing_bits`, `json_4097_bytes`, `trailing_garbage`, `expiry_float`, `expiry_negative`, `url_not_https`.
- [ ] **Step 2: Chạy test.** Kết quả mong đợi: FAIL.
- [ ] **Step 3: Hiện thực.**
- [ ] **Step 4: Sinh vectors và chạy test.** Kết quả mong đợi: PASS.
- [ ] **Step 5: Commit** `feat(proto): add ConnectInfo codec with strict, bounded decoding`.

---

### Task 7: Packet number và cửa sổ replay (Rust)

**Files:**
- Create: `crates/glassy-proto/src/packet/mod.rs`, `src/packet/pn.rs`

**Interfaces:**
- Produces:
  - `pub fn decode_pn(largest: u64, low: u32) -> u64`: RFC 9000 Appendix A.3 với `pn_nbits` = 32, giữ đúng điều kiện biên `candidate <= (1 << 62) - pn_win`.
  - `pub struct ReplayWindow` (bitmap 256 bit + `largest: u64`, khởi đầu `largest` = 0, chưa có `pn` nào): `pub fn check(&self, pn: u64) -> Result<(), Error>`, `pub fn commit(&mut self, pn: u64)`, `pub fn largest(&self) -> u64`.

Quy ước cửa sổ (sửa lỗi lệch 1 trong câu của spec §4.1, Task 22 cập nhật spec): cửa sổ chứa đúng 256 giá trị `(largest − 256, largest]`.
- `pn + 256 <= largest` → `TooOld`.
- `pn` đã commit → `Replayed`.
- `pn` = 0 luôn trả `Replayed`, vì 0 dành cho `ACCEPT`/`REJECT` và không bao giờ là `DATA` hợp lệ.

`commit` chỉ được gọi sau khi AEAD hợp lệ.

- [ ] **Step 1: Viết test thất bại.**
  - `decode_pn_small` (largest 0, low 1 → 1).
  - `decode_pn_crosses_32_bit_boundary`: (largest `0xFFFF_FFF0`, low 2) → `0x1_0000_0002`; (largest `0x1_0000_0005`, low `0xFFFF_FFFF`) → `0xFFFF_FFFF`; (largest `0x1_0000_0005`, low 3) → `0x1_0000_0003`.
  - `replay_window_rejects_duplicate`.
  - `replay_window_edge`: largest 1000, pn 745 hợp lệ, pn 744 → `TooOld`.
  - `replay_window_jump_clears_bits`: commit 5, rồi commit 5 + 300; pn 5 → `TooOld`, pn 300 hợp lệ.
  - `pn_zero_is_replayed`.
  - proptest `window_matches_naive_set`: so với một `BTreeSet` làm mô hình.
- [ ] **Step 2: Chạy test.** Kết quả mong đợi: FAIL.
- [ ] **Step 3: Hiện thực.**
- [ ] **Step 4: Chạy test.** Kết quả mong đợi: PASS.
- [ ] **Step 5: Commit** `feat(proto): add packet number reconstruction and replay window`.

---

### Task 8: `CONNECT` và trailer (Rust)

**Files:**
- Create: `crates/glassy-proto/src/packet/connect.rs`, `src/packet/trailer.rs`
- Modify: `tests/vectors.rs`
- Create (generated): `vectors/native_packets.json` (phần `CONNECT`; Task 9 thêm vào)

**Interfaces:**
- Consumes: `open_server`, `ServerKeyRing`, `crypto::xchacha_seal/open`.
- Produces:
  - `pub mod packet_type { pub const CONNECT: u8 = 0x80; ACCEPT = 0x81; DATA = 0x82; DISCONNECT = 0x83; REJECT = 0x84; }`.
  - `pub const CONNECT_MIN: usize = 251; pub const MAX_PACKET: usize = 1200; pub const TRAILER_V4_LEN: usize = 8;`
  - `pub struct ConnectView<'a> { pub session_id: [u8; 8], pub conn_id: [u8; 16], pub connect_seq: u64, pub routing_ticket: &'a [u8; 60], pub server_ticket: &'a [u8], pub proof_tag: &'a [u8; 16], pub padding: &'a [u8], signed: &'a [u8] }`.
  - `pub fn parse_connect(b: &[u8]) -> Result<ConnectView<'_>, Error>`: không cấp phát; gateway dùng.
  - `pub fn build_connect(session_id: &[u8; 8], conn_id: &[u8; 16], connect_seq: u64, routing_ticket: &[u8; 60], server_ticket: &[u8], key_c2s: &[u8; 32], pad_to: usize) -> Result<Vec<u8>, Error>`: `pad_to` = 0 nghĩa là không padding. `pad_to` > 1200 → `TooLarge`; `pad_to` nhỏ hơn độ dài tự nhiên thì bỏ qua.
  - `pub struct VerifiedConnect { pub session_id: [u8; 8], pub conn_id: [u8; 16], pub connect_seq: u64, pub ticket: ServerTicket }`.
  - `pub fn verify_connect(b: &[u8], ring: &ServerKeyRing, now: u32, self_server_id: &[u8; 16]) -> Result<VerifiedConnect, Error>`.
  - `pub struct ClientAddrV4 { pub ip: [u8; 4], pub port: u16 }`, `pub fn split_trailer(b: &[u8]) -> Result<(&[u8], ClientAddrV4), Error>`, `pub fn append_trailer(b: &mut Vec<u8>, a: ClientAddrV4)`.

Thứ tự kiểm tra trong `parse_connect`:
1. len ∉ [251, 1200] → `BadLength`
2. `b[0]` ≠ `0x80` → `BadType`
3. `ver` ≠ 1 → `BadVersion`
4. `server_ticket_len` ∉ [139, 458], hoặc `96 + len + 16 > b.len()` → `BadLength`

`verify_connect` = `parse_connect`, rồi lần lượt:
1. padding không toàn 0 → `BadPadding`
2. `open_server(…, via = NATIVE)` (lỗi của nó giữ nguyên)
3. `ticket.session_id` ≠ header → `SessionMismatch`
4. `proof_tag` sai → `AuthFailed`. Proof = `xchacha_seal(key_c2s, conn_id | 0⁸, aad = signed, plaintext rỗng)`.

`split_trailer`:
1. len < 8 → `BadTrailer`
2. byte cuối ≠ `0x04` → `BadTrailer`
3. byte `len−2` ≠ 0 → `BadTrailer`

Schema `native_packets.json` (dùng chung cho Task 9): mỗi case có `"packet"` ∈ {`connect`, `accept`, `reject`, `data`, `disconnect`, `pn`, `replay`}, kèm `"op"` ∈ {`build`, `parse`, `verify`, `split_trailer`, `open`, `decode_pn`, `window`}. Trường input thay đổi theo `op`; `expect` là trường đã decode hoặc `bytes_hex` khi `op` = `build`.

- [ ] **Step 1: Viết test thất bại.**
  - `build_then_verify` (native ticket tối thiểu → 251 byte).
  - `build_padded_to_1200`.
  - `pad_to_1201_rejected`.
  - Mỗi bước kiểm tra có một test.
  - `trailer_roundtrip`.
  - Generator với các case: `connect_min_251`, `connect_padded_1200`, `connect_with_trailer`, `len_250`, `len_1201`, `bad_type`, `bad_version`, `ticket_len_138`, `ticket_len_overflows_packet`, `nonzero_padding`, `ticket_webrtc_in_connect` (→ `bad_transport`), `session_mismatch`, `bad_proof`, `fake_trailer_without_split` (→ `bad_padding`), `trailer_family_06`, `trailer_reserved_nonzero`.
- [ ] **Step 2: Chạy test.** Kết quả mong đợi: FAIL.
- [ ] **Step 3: Hiện thực.**
- [ ] **Step 4: Sinh vectors và chạy test.** Kết quả mong đợi: PASS.
- [ ] **Step 5: Commit** `feat(proto): add CONNECT codec, proof verification and client_addr trailer`.

---

### Task 9: `ACCEPT`, `REJECT`, `DATA`, `DISCONNECT` (Rust)

**Files:**
- Create: `crates/glassy-proto/src/packet/accept.rs` (`ACCEPT` + `REJECT`), `src/packet/data.rs` (`DATA` + `DISCONNECT`)
- Modify: `tests/vectors.rs` (bổ sung `native_packets.json`)

**Interfaces:**
- Produces:
  - `pub struct Accept { pub session_id: [u8; 8], pub connect_seq: u64, pub server_nonce: [u8; 16], pub resumed: bool, pub server_time_ms: u64 }`.
  - `pub fn build_accept(a: &Accept, conn_id: &[u8; 16], key_s2c: &[u8; 32]) -> [u8; 59]`.
  - `pub fn peek_reply(b: &[u8]) -> Result<(u8, [u8; 8], u64), Error>`: trả (loại, `session_id`, `connect_seq`) của `ACCEPT`/`REJECT`. Client dùng kết quả để tìm `conn_id` đang chờ.
  - `pub fn open_accept(b: &[u8], conn_id: &[u8; 16], key_s2c: &[u8; 32]) -> Result<Accept, Error>`.
  - `pub struct Reject { pub session_id: [u8; 8], pub connect_seq: u64, pub server_nonce: [u8; 16], pub reason: u8, pub last_connect_seq: u64 }`; `pub mod reject_reason { STALE_CONNECT_SEQ = 1; KICKED = 2; SESSION_CLOSED = 3; SERVER_FULL = 4 }`.
  - `build_reject(r: &Reject, conn_id, key_s2c) -> [u8; 58]`, `open_reject(b, conn_id, key_s2c) -> Result<Reject, Error>`. Lý do lạ được giữ nguyên giá trị byte; ánh xạ sang mã lỗi SDK là việc của SP2.
  - `pub struct Header { pub ty: u8, pub session_id: [u8; 8], pub pn_low: u32 }`, `pub fn parse_header(b: &[u8]) -> Result<Header, Error>`: dùng cho `DATA` và `DISCONNECT`.
  - `pub fn seal_data(key: &[u8; 32], server_nonce: &[u8; 16], session_id: &[u8; 8], pn: u64, frames: &[u8]) -> Result<Vec<u8>, Error>`: `frames` > 1171 → `TooLarge`; `pn` = 0 → `Replayed` (cùng quy ước với cửa sổ replay).
  - `pub fn open_data(key, server_nonce, b: &[u8], pn: u64) -> Result<Vec<u8>, Error>`: `pn` đã được caller dựng lại.
  - `pub fn seal_disconnect(key, server_nonce, session_id, pn, reason: u8) -> [u8; 30]`, `pub fn open_disconnect(key, server_nonce, b, pn) -> Result<u8, Error>`.

Kiểm tra:
- `ACCEPT`:
  1. len ≠ 59 → `BadLength`
  2. byte đầu ≠ `0x81` → `BadType`
  3. AEAD sai → `AuthFailed`
  4. `flags` bit 1..7 hoặc byte reserved khác 0 → `ReservedNonzero`
- `REJECT`: tương tự với len 58 và byte đầu `0x84`.
- `parse_header`:
  1. len < 29 hoặc > 1200 → `BadLength`
  2. byte đầu ∉ {`0x82`, `0x83`} → `BadType`
- `DISCONNECT`: len ≠ 30 → `BadLength`.

AAD của `DATA`/`DISCONNECT` = 13 byte header. AAD của `ACCEPT`/`REJECT` = 33 byte đầu | `conn_id`. Nonce của `ACCEPT`/`REJECT` = `packet_nonce(server_nonce, 0)`; nonce của `DATA`/`DISCONNECT` = `packet_nonce(server_nonce, pn)`.

- [ ] **Step 1: Viết test thất bại.**
  - `accept_is_59_bytes`, `reject_is_58_bytes`.
  - `accept_bound_to_conn_id`: mở với `conn_id` khác → `AuthFailed`.
  - `data_keepalive_empty`: frames rỗng → 29 byte.
  - `data_max_1200`, `data_1172_rejected`.
  - `data_wrong_direction_key` → `AuthFailed`.
  - `data_wrong_pn` → `AuthFailed`.
  - `disconnect_unknown_reason_preserved`.
  - proptest `data_roundtrip` và `accept_reject_roundtrip`: trường ngẫu nhiên, seal/build rồi open cho lại đúng giá trị (spec §8.4).
  - Bổ sung generator `native_packets.json` với các case:
    - `accept_fresh`, `accept_resumed`, `accept_wrong_conn_id`, `accept_reserved_flag`, `reject_stale`, `reject_unknown_reason_9`;
    - `data_keepalive`, `data_with_frames`, `data_pn_low_wrap`;
    - `disconnect_normal`, `data_len_28`, `data_type_85`;
    - các case `pn`/`window` lấy từ Task 7, gồm cả 3 case biên 2^32.
- [ ] **Step 2: Chạy test.** Kết quả mong đợi: FAIL.
- [ ] **Step 3: Hiện thực.**
- [ ] **Step 4: Sinh vectors và chạy test.** Kết quả mong đợi: PASS.
- [ ] **Step 5: Commit** `feat(proto): add ACCEPT, REJECT, DATA and DISCONNECT packets`.

---

### Task 10: Frame trong `DATA` (Rust)

**Files:**
- Create: `crates/glassy-proto/src/frame.rs`
- Modify: `tests/vectors.rs`
- Create (generated): `vectors/frames.json`

**Interfaces:**
- Produces:
  - `pub enum Frame<'a> { Ack(AckFrame), Stream { offset: u64, data: &'a [u8] }, Datagram(&'a [u8]) }`.
  - `pub struct AckFrame { pub largest_pn_low: u32, pub ack_delay: u16, pub ack_bits: u64 }`; `pub const ACK_DELAY_UNKNOWN: u16 = 0xFFFF`.
  - `pub fn encode_frame(f: &Frame, out: &mut Vec<u8>) -> Result<(), Error>`: encoder ACK luôn ở dạng canonical.
  - `pub fn decode_frames(plaintext: &[u8]) -> Result<Vec<Frame<'_>>, Error>`: trả lỗi đầu tiên gặp phải; tất cả hoặc không có gì (spec §5.0).
  - `pub fn ack_bit(bits: u64, n: u32) -> bool`: true nếu đã nhận `largest − 1 − n`.

Wire format:
- ACK: `0x01 | largest_pn_low(4) | ack_delay(2) | mask(1) | byte[i]` với mỗi bit `i` = 1 trong `mask`, theo thứ tự `i` tăng dần. `ack_bits` byte `i` = `(bits >> 8i) & 0xFF`; byte vắng mặt = `0xFF`.
- STREAM: `0x02 | offset varint | len varint | data`.
- DATAGRAM: `0x03 | len varint | data`.

Lỗi:
- byte loại ∉ {1, 2, 3} → `BadType`
- ACK thứ hai trong cùng gói → `DuplicateAck`
- byte có mặt bằng `0xFF` → `NonCanonicalAck`
- thiếu byte → `Truncated`
- varint không tối thiểu → `NonCanonicalVarint`
- `offset + len` > 2^62−1 → `ValueTooLarge`
- DATAGRAM `len` > 1100 → `TooLarge`

`len` = 0 hợp lệ cho cả STREAM và DATAGRAM. Payload rỗng hợp lệ (không có frame nào).

Schema `frames.json`: `plaintext_hex`; `expect.frames` = danh sách `{"type": "ack", "largest_pn_low", "ack_delay", "ack_bits_hex"(16 hex)}` / `{"type": "stream", "offset", "data_hex"}` / `{"type": "datagram", "data_hex"}`.

- [ ] **Step 1: Viết test thất bại.**
  - `ack_no_loss_is_8_bytes`.
  - `ack_omits_ff_bytes`: `ack_bits` = `0xFFFF_FFFF_FFFF_FF00` → mask `0x01`, tổng 9 byte.
  - `ack_bit_semantics`.
  - Mỗi lỗi ở trên có một test.
  - proptest `frames_roundtrip`: danh sách frame ngẫu nhiên, tổng ≤ 1171 byte, encode rồi decode cho kết quả bằng nhau, và encode lại cho cùng bytes.
  - Generator với các case: `empty`, `ack_only`, `ack_sparse`, `stream_offset_0`, `stream_big_offset`, `datagram_1100`, `datagram_1101`, `mixed_three_frames`, `two_acks`, `ack_present_ff`, `unknown_type_04`, `stream_truncated_data`, `stream_noncanonical_offset`, `stream_offset_overflow`.
- [ ] **Step 2: Chạy test.** Kết quả mong đợi: FAIL.
- [ ] **Step 3: Hiện thực.**
- [ ] **Step 4: Sinh vectors và chạy test.** Kết quả mong đợi: PASS.
- [ ] **Step 5: Commit** `feat(proto): add ACK, STREAM and DATAGRAM frame codec`.

---

### Task 11: Framing message và path WebTransport (Rust)

**Files:**
- Create: `crates/glassy-proto/src/message.rs`, `src/wt.rs`
- Modify: `tests/vectors.rs`
- Create (generated): `vectors/wt_framing.json`

**Interfaces:**
- Produces:
  - `pub fn encode_message_header(len: usize, out: &mut Vec<u8>) -> Result<(), Error>`: `len` > `MAX_MESSAGE` → `TooLarge`.
  - `pub enum MessageHeader { NeedMore, Ready { len: usize, header_len: usize } }`, `pub fn decode_message_header(buf: &[u8]) -> Result<MessageHeader, Error>`. Varint chưa đủ byte → `NeedMore` (không phải `Truncated`); `len` > `MAX_MESSAGE` → `TooLarge`; không tối thiểu → `NonCanonicalVarint`.
  - `pub fn wt_path(server_ticket: &[u8]) -> Result<String, Error>`: trả `"/glassy?t=" + b64url`; ticket ngoài [75, 394] → `BadLength`.
  - `pub fn parse_wt_path(path: &str) -> Result<Vec<u8>, Error>`: dài hơn 536 → `TooLarge`; không bắt đầu bằng `/glassy?t=` hoặc có thêm `&`/`#` → `BadEncoding`; ticket sau decode ngoài [75, 394] → `BadLength`.

Schema `wt_framing.json`:
- case `kind: "stream"`: `stream_hex` (một byte stream có thể chứa nhiều message); `expect.messages_hex` (danh sách) và `expect.remainder_hex` (byte chưa đủ một message), hoặc `error`.
- case `kind: "path"`: `path`; `expect.ticket_hex`.

- [ ] **Step 1: Viết test thất bại.**
  - `header_need_more_on_partial_varint`.
  - `max_message_accepted`, `max_message_plus_one_rejected`.
  - `wt_path_max_len_536`.
  - Generator với các case: `stream_two_messages`, `stream_partial_tail`, `stream_empty_message`, `stream_len_262145`, `stream_noncanonical_len`, `path_valid`, `path_max`, `path_537`, `path_wrong_prefix`, `path_extra_param`, `path_ticket_too_short`.
- [ ] **Step 2: Chạy test.** Kết quả mong đợi: FAIL.
- [ ] **Step 3: Hiện thực.**
- [ ] **Step 4: Sinh vectors và chạy test.** Kết quả mong đợi: PASS.
- [ ] **Step 5: Commit** `feat(proto): add length-prefixed message framing and WebTransport path codec`.

---

### Task 12: Public API và tài liệu crate (Rust)

**Files:**
- Modify: `crates/glassy-proto/src/lib.rs`
- Create: `crates/glassy-proto/README.md` (tiếng Anh, ngắn: crate này là gì, trỏ tới spec, cách sinh lại vectors)

**Interfaces:**
- Produces: re-export phẳng ở gốc crate mọi tên đã khai báo ở Task 1–11. Doc comment của module trích dẫn mục của spec (ví dụ `//! Spec §4.2: CONNECT layout.`).

- [ ] **Step 1: Viết doctest thất bại** trên `lib.rs`: build `CONNECT` → `verify_connect` → `build_accept` → `open_accept` → `seal_data` chứa một `DATAGRAM` → `open_data` → `decode_frames`, rồi so payload.
- [ ] **Step 2: Chạy `cargo test --doc -p glassy-proto`.** Kết quả mong đợi: FAIL do thiếu re-export.
- [ ] **Step 3: Thêm re-export và `#![deny(missing_docs)]`.**
- [ ] **Step 4: Chạy `cargo test --doc -p glassy-proto && cargo clippy -p glassy-proto --all-targets -- -D warnings && cargo fmt --check`.** Kết quả mong đợi: PASS.
- [ ] **Step 5: Commit** `docs(proto): document public API with an end-to-end doctest`.

---

### Task 13: Test chống cắt ngắn trên mọi vector (Rust)

**Files:**
- Create: `crates/glassy-proto/tests/robustness.rs`

**Interfaces:**
- Consumes: mọi parser từ Task 3–11; mọi file `vectors/*.json`.

- [ ] **Step 1: Viết test `every_prefix_is_rejected`.** Với mỗi case valid trong mọi file vectors có input dạng bytes, gọi đúng parser với từng prefix `input[..k]` (k < n). Kết quả phải là `Err`, ngoại trừ các case mà prefix đó tự nó hợp lệ: frames (ranh giới frame) và stream WT (trả `NeedMore`/remainder). Với các case đó, chỉ assert không panic. Gọi thêm parser với `input + [0x00]` và assert kết quả là `Err` cho các format có độ dài cố định hoặc tự mô tả (ticket, `ACCEPT`, `REJECT`, `DISCONNECT`, token Retry).
- [ ] **Step 2: Chạy `cargo nextest run -p glassy-proto --test robustness`.** Kết quả mong đợi: PASS. Nếu FAIL, sửa parser ở task tương ứng và ghi vào commit.
- [ ] **Step 3: Commit** `test(proto): reject every truncated or extended vector input`.

---

### Task 14: Lib C++: scaffold, Monocypher, varint, lỗi

**Files:**
- Create: `cpp/glassy-proto/CMakeLists.txt`, `.clang-format` (Google, ColumnLimit 100)
- Create: `cpp/glassy-proto/third_party/monocypher/{monocypher.c,monocypher.h,LICENCE.md}`, chép từ tag `4.0.3`, kèm `README.md` ghi nguồn và commit `ab2b16dd619ad5f6979a4fbe69cfa324a6fcc35f`
- Create: `include/glassy/proto/{error.h,result.h,consts.h,varint.h,aead.h}`, `src/{error.cc,varint.cc,aead.cc}`
- Create: `tests/{vectors.h,vectors.cc,kat_test.cc}`

**Interfaces:**
- Produces:
  - `enum class Error : uint8_t { kOk = 0, kTruncated, kBadLength, … }`: cùng 27 giá trị theo đúng thứ tự Task 1. `const char* error_code(Error)` trả chuỗi giống hệt Rust; `kOk` → `"ok"`.
  - `template <class T> class Result { public: Result(T); Result(Error); bool ok() const; Error error() const; const T& value() const; }`; `using Status = Result<std::monostate>`.
  - `consts.h`: `kMaxDatagram`, `kMaxMessage`, `kRecvWindow`, `kMaxStreamGaps`, `kReplayWindow`, `kMaxConnectInfoJson`, `kMaxPacket = 1200`.
  - `varint.h`: `Result<size_t> varint_encode(uint64_t v, std::span<uint8_t> out)` (`out` không đủ → `kBufferTooSmall`), `struct VarintRead { uint64_t value; size_t len; }; Result<VarintRead> varint_decode(std::span<const uint8_t>)`.
  - `aead.h`: `Result<size_t> xchacha_seal(const Key32&, const Nonce24&, std::span<const uint8_t> aad, std::span<const uint8_t> pt, std::span<uint8_t> out)` (ghi `ct | tag`), `Result<size_t> xchacha_open(…, std::span<const uint8_t> sealed, std::span<uint8_t> out)`, `Nonce24 packet_nonce(const std::array<uint8_t,16>&, uint64_t pn)`. Bọc `crypto_aead_lock`/`crypto_aead_unlock` của Monocypher; sau khi dùng xong thì xoá key tạm bằng `crypto_wipe`.
  - `using Key32 = std::array<uint8_t, 32>; using Nonce24 = std::array<uint8_t, 24>;`
  - CMake:
    - target `glassy_proto_core` (STATIC): src + monocypher, compile `-ffunction-sections -fdata-sections`; `-Wall -Wextra -Werror` chỉ áp cho file của mình; `-fno-exceptions -fno-rtti` cho lib.
    - Option `GLASSY_PROTO_SERVER` (mặc định ON khi không phải `EMSCRIPTEN`) và `GLASSY_PROTO_TESTS` (mặc định ON).
    - Test lấy GoogleTest v1.15.2 và nlohmann/json v3.12.0 bằng `FetchContent` qua git (giống `spikes/s2-webrtc-server/CMakeLists.txt`). Test build có exceptions (nlohmann cần).
    - Định nghĩa `GLASSY_VECTORS_DIR` và `GLASSY_FIXTURES_DIR` (= `crates/glassy-proto/tests/fixtures`) bằng đường dẫn tuyệt đối.
  - `tests/vectors.h`: `nlohmann::json load_vectors(std::string_view file)`, `std::vector<uint8_t> hex(std::string_view)`, `std::string to_hex(std::span<const uint8_t>)`, `std::vector<std::pair<std::string, std::vector<uint8_t>>> load_fixture(std::string_view)` (cùng format `.hex` với Rust).

- [ ] **Step 1: Viết test thất bại** trong `kat_test.cc`:
  - `Varint.Rfc9000Examples`: dùng `varint.hex`, `4025` → `kNonCanonicalVarint`.
  - `Varint.ShortestForm`: cùng các biên như Task 1.
  - `Xchacha.DraftA31`: dùng `xchacha20poly1305.hex`; lật bit → `kAuthFailed`.
  - `Errors.CodesMatchRust`: so `error_code` của từng giá trị với danh sách chuỗi chép nguyên từ Task 1.
- [ ] **Step 2: Build và chạy:**
  ```bash
  cmake -S cpp/glassy-proto -B build -DCMAKE_BUILD_TYPE=Debug
  cmake --build build --parallel 2
  ctest --test-dir build -j2 --timeout 120 --output-on-failure
  ```
  Kết quả mong đợi: FAIL (thiếu hiện thực).
- [ ] **Step 3: Hiện thực** `error.cc`, `varint.cc`, `aead.cc`.
- [ ] **Step 4: Chạy lại build và ctest.** Kết quả mong đợi: PASS.
- [ ] **Step 5: Commit** `feat(proto-cpp): scaffold C++ lib with Monocypher, varint and error codes`.

---

### Task 15: C++ target server: server ticket, ICE pwd, token Retry, trailer, path WT

**Files:**
- Create: `include/glassy/proto/{server_ticket.h,ice.h,retry.h,trailer.h,wt.h}`, `src/{server_ticket.cc,ice.cc,retry.cc,trailer.cc,wt.cc,sha256_nettle.cc}`
- Create: `tests/{server_ticket_test.cc,ice_test.cc,retry_test.cc,wt_test.cc}`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: Task 14; `vectors/server_ticket.json`, `ice_pwd.json`, `retry_token.json`, `wt_framing.json` (case `path`), `native_packets.json` (case `split_trailer`).
- Produces (target `glassy_proto_server`, link `glassy_proto_core` + `PkgConfig::NETTLE`):
  - `struct ServerTicket { std::array<char,64> user_id; uint8_t user_id_len; std::array<uint8_t,16> server_id; std::array<uint8_t,8> session_id; uint32_t expiry; uint8_t transport; bool has_native_keys; Key32 key_c2s, key_s2c; std::array<uint8_t,256> metadata; uint16_t metadata_len; }`.
  - `class ServerKeyRing { public: Status insert(uint8_t key_id, const Key32& k_gs); }`: tối đa 16 key, lưu sẵn `K_ticket`; xoá key bằng `crypto_wipe` trong destructor.
  - `Result<ServerTicket> open_server_ticket(std::span<const uint8_t>, const ServerKeyRing&, uint32_t now, const std::array<uint8_t,16>& self_server_id, uint8_t via)`: thứ tự kiểm tra giống hệt Task 4. Kiểm UTF-8 theo RFC 3629: từ chối overlong, surrogate và giá trị > U+10FFFF.
  - `std::array<char,43> ice_pwd(const Key32& k_gs, std::string_view ufrag)`.
  - `Result<std::span<const uint8_t>> retry_token_odcid(std::span<const uint8_t>)`.
  - `struct ClientAddrV4 { std::array<uint8_t,4> ip; uint16_t port; }; struct SplitTrailer { std::span<const uint8_t> payload; ClientAddrV4 addr; }; Result<SplitTrailer> split_trailer(std::span<const uint8_t>)`.
  - `Result<size_t> parse_wt_path(std::string_view path, std::span<uint8_t> ticket_out)`.
  - `sha256_nettle.cc` là nơi duy nhất include nettle: `hkdf_sha256_32(…)`, `hmac_sha256(…)` (nettle `hmac_sha256_*`, `hkdf_extract`/`hkdf_expand`).

- [ ] **Step 1: Viết test thất bại.** Mỗi file test chạy hết các case trong file vectors tương ứng: case valid so từng trường, case invalid so `error_code(…)` với `"error"`. Thêm `ServerTicket.KeyRingCapsAt16`.
- [ ] **Step 2: Build và ctest.** Kết quả mong đợi: FAIL.
- [ ] **Step 3: Hiện thực.** Decoder base64 (std và url) dùng chung nằm ở `src/base64.{h,cc}` thuộc `glassy_proto_core` (client cũng cần, Task 16), không cấp phát, từ chối padding và bit thừa khác 0.
- [ ] **Step 4: Build và ctest.** Kết quả mong đợi: PASS, mọi case khớp.
- [ ] **Step 5: Commit** `feat(proto-cpp): add server ticket, ICE pwd, Retry token, trailer and WT path`.

---

### Task 16: C++ `ConnectInfo` parser (core)

**Files:**
- Create: `include/glassy/proto/connect_info.h`, `src/connect_info.cc`, `src/json_reader.{h,cc}` (pull tokenizer nội bộ)
- Create: `tests/connect_info_test.cc`

**Interfaces:**
- Consumes: `vectors/connect_info.json`; `src/base64.h` (Task 15, thuộc core).
- Produces:
  - `template <size_t N> struct FixedString { std::array<char, N> data; uint16_t len; std::string_view view() const; }`.
  - `struct ConnectInfo` với cùng trường như bản Rust:
    - `gateways`: `std::array<FixedString<64>,4>` + `uint8_t count`; `candidates` tương tự;
    - `server_ticket`: `std::array<uint8_t,458>` + len;
    - `ice_ufrag` `FixedString<80>`, `ice_pwd` `FixedString<43>`, `dtls_fingerprint` `FixedString<128>`, `url` `FixedString<1024>`;
    - cờ `has_native`, `has_webrtc`, `has_webtransport`.
  - `Status decode_connect_info(std::string_view b64, ConnectInfo& out, std::span<uint8_t> scratch)`: `scratch` ≥ 4096 byte để chứa JSON sau decode; nhỏ hơn → `kBufferTooSmall`. Tuân đúng 9 quy tắc decode ở Task 6, cùng mã lỗi.
  - `json_reader`: tokenizer duyệt một lượt, có stack độ sâu cố định 8, bỏ qua giá trị lạ (kể cả string có escape, `\uXXXX` và surrogate), kiểm key trùng trong các object đã biết bằng bitmask trường.

- [ ] **Step 1: Viết test thất bại.**
  - `ConnectInfo.Vectors`: mọi case trong `connect_info.json`.
  - `ConnectInfo.ScratchTooSmall`.
  - `ConnectInfo.NoHeapAllocation`: thay `operator new` trong file test bằng bộ đếm, rồi assert số lần gọi = 0 trong lúc decode.
- [ ] **Step 2: Build và ctest.** Kết quả mong đợi: FAIL.
- [ ] **Step 3: Hiện thực.**
- [ ] **Step 4: Build và ctest.** Kết quả mong đợi: PASS.
- [ ] **Step 5: Commit** `feat(proto-cpp): add allocation-free ConnectInfo decoder`.

---

### Task 17: C++ gói native

**Files:**
- Create: `include/glassy/proto/{packet.h,pn.h}`, `src/{packet_connect.cc,packet_reply.cc,packet_data.cc,pn.cc}`
- Create: `tests/packet_core_test.cc` (case không cần server ticket), `tests/packet_server_test.cc` (`verify`, `build` của `accept`/`reject`)
- Modify: `CMakeLists.txt`. `verify_connect` và `build_accept`/`build_reject` thuộc `glassy_proto_server`; phần còn lại thuộc `glassy_proto_core`.

**Interfaces:**
- Consumes: Task 14–15; `vectors/native_packets.json`.
- Produces (cùng tên và ngữ nghĩa với Task 7–9):
  - `uint64_t decode_pn(uint64_t largest, uint32_t low)`; `class ReplayWindow { Status check(uint64_t) const; void commit(uint64_t); uint64_t largest() const; }`.
  - Core:
    - `Result<size_t> build_connect(const ConnectParams&, std::span<uint8_t> out)`, với `struct ConnectParams { session_id, conn_id, connect_seq, routing_ticket (span 60), server_ticket (span), key_c2s, size_t pad_to; }`;
    - `Result<ReplyHeader> peek_reply(span)`;
    - `Result<Accept> open_accept(span, conn_id, key_s2c)`, `Result<Reject> open_reject(span, conn_id, key_s2c)`;
    - `Result<Header> parse_header(span)`;
    - `Result<size_t> seal_data(key, server_nonce, session_id, pn, span frames, span out)`, `Result<size_t> open_data(key, server_nonce, span packet, uint64_t pn, span out)`;
    - `seal_disconnect` / `open_disconnect`.
  - Server:
    - `Result<VerifiedConnect> verify_connect(span, const ServerKeyRing&, uint32_t now, self_server_id)`;
    - `std::array<uint8_t,59> build_accept(const Accept&, conn_id, key_s2c)`, `std::array<uint8_t,58> build_reject(…)`.

- [ ] **Step 1: Viết test thất bại.**
  - `PacketsCore.Vectors` và `PacketsServer.Vectors`: chạy mọi case trong `native_packets.json` thuộc phần của mình, theo `packet` và `op`. Case `build` so từng byte; case `parse`/`verify`/`open` so trường hoặc mã lỗi.
  - `Packets.SealDataOutTooSmall`.
- [ ] **Step 2: Build và ctest.** Kết quả mong đợi: FAIL.
- [ ] **Step 3: Hiện thực.**
- [ ] **Step 4: Build và ctest.** Kết quả mong đợi: PASS.
- [ ] **Step 5: Commit** `feat(proto-cpp): add native packet codec matching Rust vectors`.

---

### Task 18: C++ frame và framing message (core)

**Files:**
- Create: `include/glassy/proto/{frame.h,message.h}`, `src/{frame.cc,message.cc}`
- Create: `tests/frame_test.cc`, `tests/message_test.cc`

**Interfaces:**
- Consumes: `vectors/frames.json`, `vectors/wt_framing.json` (case `stream`).
- Produces:
  - `struct AckFrame { uint32_t largest_pn_low; uint16_t ack_delay; uint64_t ack_bits; }`; `enum class FrameType : uint8_t { kAck = 1, kStream = 2, kDatagram = 3 }`; `struct Frame { FrameType type; AckFrame ack; uint64_t offset; std::span<const uint8_t> data; }`.
  - `class FrameReader { public: explicit FrameReader(std::span<const uint8_t>); Result<bool> next(Frame& out); }`. `true` = có frame, `false` = hết. Reader tự nhớ đã gặp ACK chưa để trả `kDuplicateAck`. Caller gọi một lượt để validate, rồi lượt thứ hai để áp dụng (spec §5.0).
  - `Result<size_t> encode_ack(const AckFrame&, span out)`, `encode_stream(offset, span data, span out)`, `encode_datagram(span data, span out)`.
  - `Result<MessageHeader> decode_message_header(span)` với `struct MessageHeader { bool need_more; size_t len; size_t header_len; }`; `Result<size_t> encode_message_header(size_t len, span out)`.

- [ ] **Step 1: Viết test thất bại.**
  - `Frames.Vectors`: decode mọi case. Với case valid, encode lại từng frame và so với `plaintext_hex`.
  - `Message.Vectors`: chạy mọi case `stream`, cắt stream thành các message giống cách Rust làm.
- [ ] **Step 2: Build và ctest.** Kết quả mong đợi: FAIL.
- [ ] **Step 3: Hiện thực.**
- [ ] **Step 4: Build và ctest.** Kết quả mong đợi: PASS.
- [ ] **Step 5: Commit** `feat(proto-cpp): add frame codec and message framing`.

---

### Task 19: Chống cắt ngắn (C++), ASan/UBSan, ngân sách kích thước

**Files:**
- Create: `tests/robustness_test.cc`, `tools/size_probe.cc`, `tools/size_baseline.cc`, `tools/check_size.sh`
- Modify: `CMakeLists.txt` (option `GLASSY_PROTO_SANITIZE`, target `size_probe` và `size_baseline`)

**Interfaces:**
- Consumes: mọi API C++ đã có.
- Produces:
  - `tools/check_size.sh <build_dir>`: in `core_bytes=<n>`; exit 1 nếu n > 40960.
  - Cách đo: `size_probe` gọi mọi hàm public của `glassy_proto_core`; `size_baseline` là `main` rỗng. Cả hai build `-Os -ffunction-sections -fdata-sections -Wl,--gc-sections -s`, static. n = `stat -c%s size_probe` − `stat -c%s size_baseline`.

- [ ] **Step 1: Viết test `Robustness.EveryPrefixIsRejected`.** Làm giống Task 13 nhưng cho các parser C++, chạy trên mọi file vectors.
- [ ] **Step 2: Build với sanitizer và chạy:**
  ```bash
  cmake -S cpp/glassy-proto -B build-asan -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_COMPILER=clang -DGLASSY_PROTO_SANITIZE=ON
  cmake --build build-asan --parallel 2
  ctest --test-dir build-asan -j2 --timeout 120 --output-on-failure
  ```
  Kết quả mong đợi: PASS, không có báo cáo nào từ ASan/UBSan.
- [ ] **Step 3: Đo kích thước:**
  ```bash
  cmake -S cpp/glassy-proto -B build-size -DCMAKE_BUILD_TYPE=MinSizeRel -DGLASSY_PROTO_TESTS=OFF
  cmake --build build-size --parallel 2 --target size_probe size_baseline
  bash cpp/glassy-proto/tools/check_size.sh build-size
  ```
  Kết quả mong đợi: `core_bytes=` ≤ 40960, exit 0. Ghi lại con số này vào commit message.
- [ ] **Step 4: Commit** `test(proto-cpp): add truncation sweep under sanitizers and a 40KB size gate`.

---

### Task 20: Build WASM (Emscripten) và chạy vectors dưới Node

**Files:**
- Modify: `cpp/glassy-proto/CMakeLists.txt`: khi `EMSCRIPTEN`, tắt `GLASSY_PROTO_SERVER`, test link `-sNODERAWFS=1 -sALLOW_MEMORY_GROWTH=1 -sEXIT_RUNTIME=1`, đặt `CMAKE_CROSSCOMPILING_EMULATOR` = `node` (nếu `emcmake` chưa đặt).

**Interfaces:**
- Consumes: các test core (`kat_test`, `connect_info_test`, `packet_core_test`, `frame_test`, `message_test`). Test thuộc server không build dưới WASM.

- [ ] **Step 1: Build và chạy:**
  ```bash
  source ~/emsdk/emsdk_env.sh
  emcmake cmake -S cpp/glassy-proto -B build-wasm -DCMAKE_BUILD_TYPE=Release
  cmake --build build-wasm --parallel 2
  ctest --test-dir build-wasm -j2 --timeout 120 --output-on-failure
  ```
  Kết quả mong đợi: PASS. Nếu `gtest_discover_tests` không chạy được dưới emulator, đổi sang `add_test(NAME … COMMAND node $<TARGET_FILE:…>)` cho từng binary và ghi lý do bằng comment.
- [ ] **Step 2: Commit** `chore(proto-cpp): run core vectors under Emscripten and Node`.

---

### Task 21: Fuzz và differential

**Files:**
- Create: `crates/glassy-proto/fuzz/Cargo.toml` (workspace riêng, `cargo fuzz init` rồi sửa), `fuzz/fuzz_targets/{connect.rs,routing_ticket.rs,retry_token.rs,connect_info.rs}`
- Create: `crates/glassy-proto-cli/{Cargo.toml,src/main.rs}` (binary, dùng `anyhow`)
- Create: `cpp/glassy-proto/fuzz/{fuzz_native.cc,fuzz_frames.cc,fuzz_server_ticket.cc,fuzz_connect_info.cc,fuzz_retry.cc,fuzz_wt.cc}`, `cpp/glassy-proto/tools/proto_cli.cc`
- Create: `scripts/differential.sh`, `scripts/fuzz_smoke.sh`, `fuzz/seeds/<kind>/` (seed lấy từ các vectors, do `differential.sh --seed` sinh)

**Interfaces:**
- Produces:
  - CLI ở cả hai ngôn ngữ: `<cli> <kind>` đọc stdin, mỗi dòng một input hex; ghi stdout, mỗi dòng một kết quả, giữ đúng thứ tự.
  - `kind` ∈ {`frames`, `connect`, `server_ticket`, `retry_token`, `connect_info`, `wt_stream`, `wt_path`}. Với `connect_info` và `wt_path`, input là chuỗi viết dạng hex của các byte UTF-8.
  - Format output, không có khoảng trắng: `{"err":"<code>"}` hoặc `{"ok":<object>}`. Object có key theo đúng thứ tự dưới đây, bytes viết hex chữ thường:
    - `frames`: `{"frames":[…]}` như schema `frames.json`;
    - `connect`: `{"session_id","conn_id","connect_seq","server_ticket_len","padding_len"}` từ `parse_connect` (phần gateway);
    - `server_ticket`: `{"user_id","session_id","transport","metadata_len"}`, mở với khoá vectors, `now` = 1900000000, `self_server_id` = `ab`×16, `via` = byte transport trong ticket;
    - `retry_token`: `{"odcid"}` (mode parse);
    - `connect_info`: `{"session_id","expiry","native","webrtc","webtransport"}`, ba khối cuối là `true`/`false`;
    - `wt_stream`: `{"messages":[hex…],"remainder":hex}`;
    - `wt_path`: `{"ticket":hex}`.
  - `scripts/differential.sh <corpus_dir>`: chạy hai CLI trên cùng corpus rồi `diff`; exit khác 0 nếu có dòng khác nhau, và in dòng đó.
  - `scripts/fuzz_smoke.sh <seconds>`: chạy mỗi target Rust và C++ `-max_total_time=<seconds> -jobs=1 -workers=1 -rss_limit_mb=2048`; exit khác 0 nếu có crash.
  - Target C++ build bằng `clang++ -fsanitize=fuzzer,address,undefined`, dùng option CMake `GLASSY_PROTO_FUZZ=ON`.

- [ ] **Step 1: Viết differential thất bại.** Chạy `scripts/differential.sh fuzz/seeds` khi hai CLI chưa có. Kết quả mong đợi: lỗi "cli not found".
- [ ] **Step 2: Hiện thực hai CLI.** Seed corpus = mọi input trong vectors, cả valid lẫn invalid.
- [ ] **Step 3: Chạy `scripts/differential.sh fuzz/seeds`.** Kết quả mong đợi: không có diff.
- [ ] **Step 4: Cài nightly và cargo-fuzz** (`rustup toolchain install nightly --profile minimal && cargo install cargo-fuzz --locked`), hiện thực các fuzz target, rồi chạy `scripts/fuzz_smoke.sh 60`. Kết quả mong đợi: không có crash. Corpus tạo ra khi fuzz không commit (đã có trong `.gitignore`).
- [ ] **Step 5: Gộp corpus fuzz vào differential** (`scripts/differential.sh` nhận nhiều thư mục) và chạy lại. Kết quả mong đợi: không có diff. Diff nào xuất hiện thì sửa ở phía sai so với spec, và thêm input gây diff thành case mới trong file vectors tương ứng.
- [ ] **Step 6: Commit** `test(proto): add fuzz targets and a Rust/C++ differential runner`.

---

### Task 22: CI và cập nhật tài liệu

**Files:**
- Create: `.github/workflows/proto.yml`
- Modify: `docs/superpowers/specs/2026-10-21-glassy-architecture-design.md` (theo bảng §9 của spec)
- Modify: `docs/superpowers/specs/2026-10-23-sp1-glassy-proto-design.md`:
  - Trạng thái → "Đã duyệt".
  - §4.1: sửa câu chống replay thành "`pn` + 256 ≤ `largest` bị drop; `pn` = 0 bị drop".
  - §3.5: thêm 9 quy tắc decode ở Task 6.
  - Thêm bảng mã lỗi ở Task 1.

**Interfaces:**
- Consumes: mọi lệnh ở các task trước.

Các job trong `proto.yml`, chạy trên `push` và `pull_request` khi đổi các path `crates/**`, `cpp/**`, `vectors/**`, `scripts/**`, `.github/workflows/proto.yml`:
1. `rust` (ubuntu-24.04):
   - `cargo fmt --check`;
   - `cargo clippy --workspace --all-targets -- -D warnings`;
   - `cargo nextest run --workspace --profile ci`;
   - `cargo test --doc -p glassy-proto`;
   - chạy lại mọi generator vectors, rồi `git diff --exit-code vectors/`.
2. `cpp` (ubuntu-24.04): cài `nettle-dev`, `clang-18`, `clang-format-18`; kiểm `clang-format --dry-run -Werror`; build Debug; ctest; build ASan; ctest.
3. `size` (matrix `ubuntu-24.04` và `ubuntu-24.04-arm`): build MinSizeRel, chạy `check_size.sh`.
4. `wasm` (ubuntu-24.04): `mymindstorm/setup-emsdk` với emsdk `5.0.4`; Node 20; build và chạy như Task 20.
5. `fuzz-diff` (ubuntu-24.04, chạy sau `rust` và `cpp`): nightly + cargo-fuzz; `scripts/fuzz_smoke.sh 60`; `scripts/differential.sh fuzz/seeds <corpus vừa sinh>`.

Mọi job đặt `CARGO_BUILD_JOBS=2`, `NEXTEST_TEST_THREADS=2`, `CMAKE_BUILD_PARALLEL_LEVEL=2`.

- [ ] **Step 1: Viết workflow.** Chạy local các lệnh của từng job theo đúng thứ tự trong file. Kết quả mong đợi: tất cả PASS. Nếu có `actionlint`, chạy `actionlint .github/workflows/proto.yml`: không có lỗi.
- [ ] **Step 2: Cập nhật hai spec như liệt kê ở mục Files.**
- [ ] **Step 3: Chuyển vectors của spike.** `spikes/vectors/*.json` giữ nguyên (spike throwaway), nhưng các vectors mới ở `vectors/` là nguồn chính. Ghi một dòng vào `spikes/README.md` trỏ sang `vectors/`.
- [ ] **Step 4: Commit** `chore(proto): add CI for Rust, C++, size, WASM and fuzz/differential; sync specs`.
