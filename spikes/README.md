> THROWAWAY: code trong spikes/ chỉ để trả lời các câu hỏi S1–S5 của SP0; không dùng cho production.

# SP0 spikes

Mỗi spike trả lời một câu hỏi khả thi trong §11 của
`docs/superpowers/specs/2026-10-21-glassy-architecture-design.md`. Kết quả được ghi vào
`docs/superpowers/spikes/2026-10-21-sp0-findings.md`.

Quy ước (comment tiếng Anh, test Rust bằng `cargo nextest run`, giới hạn chống OOM): xem `CONVENTIONS.md`.

| Thư mục | Spike | Nội dung |
|---|---|---|
| `gw-proto/` | S1, S2, S4 | Gateway prototype ở userspace (Rust) |
| `s2-webrtc-server/` | S2 | Server WebRTC ICE-lite (C++, libdatachannel) |
| `web/` | S1, S2, S4 | Test Playwright với Chromium thật |

## Chạy

```bash
# Rust (gw-proto)
cargo nextest run -p gw-proto

# S2: build deps một lần, rồi build server
s2-webrtc-server/deps.sh
cmake -S s2-webrtc-server -B s2-webrtc-server/build -DCMAKE_PREFIX_PATH=$PWD/.deps
cmake --build s2-webrtc-server/build --parallel 2
ctest --test-dir s2-webrtc-server/build -j2 --timeout 120 --output-on-failure

# Browser tests (Chromium ở /opt/pw-browsers/chromium, hoặc đặt CHROMIUM_PATH)
cd web && npm ci && npx playwright test
```

Debug server S2: đặt `GLASSY_LOG=debug` để bật log debug của libdatachannel/libjuice.

## Chạy tay trên Firefox và Safari

Môi trường tự động chỉ có Chromium. Trên máy có Firefox/Safari:

1. Chạy các server và relay giống `beforeAll` trong `web/tests/s2.spec.ts` (hoặc chạy `npx playwright test s2` một lần để sinh `web/pages/connect.json`, rồi tự khởi động lại các process).
2. Mở `http://localhost:8080/s2.html`, mở DevTools console, gõ `await runS2(7101)` (kết nối thẳng) và `await runS2(4443)` (qua relay).
3. Kết quả mong đợi: `{ufragLen: 80, reliableEcho: 'hello-reliable', unreliableEcho: 'hello-unreliable'}`.
4. Ghi kết quả vào bảng "Chạy tay" của mục S2 trong `docs/superpowers/spikes/2026-10-21-sp0-findings.md`.
