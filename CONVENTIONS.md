# Quy ước của glassy

Áp dụng cho **toàn bộ repo**, kể cả code throwaway trong `spikes/` và `bench/`.

## 1. Ngôn ngữ

| Nội dung | Ngôn ngữ |
|---|---|
| **Comment trong code** (mọi ngôn ngữ, kể cả doc comment, `TODO`, `FIXME`, `SAFETY`) | **Tiếng Anh** |
| Tên định danh: biến, hàm, type, file, thư mục | Tiếng Anh |
| Log, thông báo lỗi, output của CLI | Tiếng Anh |
| Tên test | Tiếng Anh, `snake_case`, mô tả hành vi (`expired_ticket_dropped_silently`) |
| Commit message | Tiếng Anh |
| Tài liệu trong `docs/` (spec, plan, findings) và file này | Tiếng Việt, giữ thuật ngữ kỹ thuật bằng tiếng Anh |

Cách viết comment:
- Giải thích **vì sao**, không lặp lại code đang **làm gì**.
- Code hiện thực protocol phải ghi nguồn, ví dụ `// RFC 9001 §5.2: initial secrets are derived from the client DCID.`

## 2. Test

### 2.1 Rust: chỉ dùng cargo-nextest

- Chạy test bằng **`cargo nextest run`**, **không** dùng `cargo test`. Ngoại lệ duy nhất là doctest: `cargo test --doc`.
- Cài đặt: tải bản build sẵn từ GitHub release (`get.nexte.st` có thể bị proxy chặn):
  ```bash
  V=0.9.149
  curl -sSfL "https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-$V/cargo-nextest-$V-x86_64-unknown-linux-gnu.tar.gz" \
    | tar zxf - -C "${CARGO_HOME:-$HOME/.cargo}/bin"
  ```
- Mỗi Rust workspace phải có `.config/nextest.toml` và `.cargo/config.toml` theo mẫu ở §3.2.

| Mục đích | Lệnh |
|---|---|
| Chạy toàn bộ workspace | `cargo nextest run --workspace` |
| Một crate | `cargo nextest run -p <crate>` |
| Lọc theo tên | `cargo nextest run -p <crate> <filter>…` |
| Một integration test binary | `cargo nextest run -p <crate> --test <name>` |
| Xem output khi debug | thêm `--no-capture` |
| Test `#[ignore]` (ví dụ sinh vector) | `cargo nextest run -p <crate> --run-ignored only -E 'test(<name>)'` |
| CI | `cargo nextest run --workspace --profile ci` |

### 2.2 Ngôn ngữ khác

| Ngôn ngữ | Framework | Lệnh |
|---|---|---|
| C++ | GoogleTest + CTest | `ctest --test-dir build -j2 --timeout 120 --output-on-failure` |
| Go | `testing` | `go test -p 2 ./...` |
| Browser | Playwright (`workers: 1`) | `npx playwright test` |
| Shell | script tự kiểm tra, in `PASS` | `bash <test>.sh` |

### 2.3 Viết test

- **Known-answer lấy từ RFC:** chép nguyên văn vào `tests/fixtures/*.hex`; comment đầu test ghi rõ RFC và mục.
- **Vector chéo ngôn ngữ** (Rust → C++/Go): file JSON trong thư mục `vectors/`, do một test Rust `#[ignore]` sinh ra, và được commit vào repo.
- **Test mạng:** bind `127.0.0.1:0`. Mọi thao tác chờ trên mạng phải có `timeout` (≤ 2s). Chỉ test e2e của Playwright mới dùng port cố định.
- Test không phụ thuộc thứ tự chạy và không dùng state toàn cục.

## 3. Chống OOM

Các nguyên nhân thường gặp:
- quá nhiều `rustc` và linker chạy song song;
- debug info lớn làm linker tốn RAM;
- quá nhiều test chạy cùng lúc;
- test bị treo mà vẫn giữ bộ nhớ.

### 3.1 Giới hạn mặc định

| Biện pháp | Cấu hình | Override |
|---|---|---|
| Giới hạn số `rustc` chạy song song | `.cargo/config.toml`: `[build] jobs = 2` | `CARGO_BUILD_JOBS` |
| Giảm debug info (để linker bớt RAM) | `[profile.dev]` trong `Cargo.toml` của workspace (mẫu ở §3.2) | — |
| Giới hạn số test chạy song song | nextest: `test-threads = 2` | `NEXTEST_TEST_THREADS` |
| Integration test chạy tuần tự | nextest: test-group `integration` (`max-threads = 1`) cho `kind(test)` | — |
| Giết test treo | nextest: `slow-timeout = { period = "30s", terminate-after = 2 }` | — |
| Build C/C++ | `cmake --build build --parallel 2`, hoặc `CMAKE_BUILD_PARALLEL_LEVEL=2` | env |
| Go | `go test -p 2` | — |
| Playwright | `workers: 1` | — |

Máy ≤ 8GB RAM: đặt thêm `CARGO_BUILD_JOBS=1 NEXTEST_TEST_THREADS=1`.

**Trong code:**
- Mọi buffer và hàng đợi nhận dữ liệu từ mạng phải **có giới hạn** (capacity cố định, kích thước tối đa).
- Parser phải kiểm tra độ dài trước khi cấp phát.
- Không để `Vec` hay map tăng vô hạn theo input.

### 3.2 File cấu hình mẫu

`.config/nextest.toml`:
```toml
# Shared nextest settings; keep in sync with CONVENTIONS.md §3.

[profile.default]
# Cap parallelism so peak memory stays predictable on 4-vCPU / 8-16 GB machines.
test-threads = 2
# Kill hung tests (e.g. waiting on a socket) instead of letting them pile up.
slow-timeout = { period = "30s", terminate-after = 2 }
leak-timeout = "500ms"
fail-fast = false
status-level = "fail"
final-status-level = "slow"

[test-groups]
# Integration tests spin up sockets and tasks; run them one at a time.
integration = { max-threads = 1 }

[[profile.default.overrides]]
filter = "kind(test)"
test-group = "integration"

[profile.ci]
fail-fast = false

[profile.ci.junit]
path = "junit.xml"
```

`.cargo/config.toml`:
```toml
[build]
# rustc and the linker are the main OOM risks; override with CARGO_BUILD_JOBS.
jobs = 2
```

Trong `Cargo.toml` của workspace:
```toml
[profile.dev]
# Line tables are enough for backtraces and cut linker memory substantially.
debug = "line-tables-only"
split-debuginfo = "unpacked"

[profile.dev.package."*"]
# Dependencies do not need debug info.
debug = false
```

## 4. Style theo ngôn ngữ

| Ngôn ngữ | Quy ước |
|---|---|
| Rust | edition 2024; `cargo fmt`; `cargo clippy --all-targets -- -D warnings`. Lib dùng enum lỗi riêng; binary dùng `anyhow`. **Không** `unwrap`/`expect`/index không kiểm tra trên dữ liệu từ mạng (trả lỗi). `unsafe` chỉ nằm trong module riêng, mỗi block có `// SAFETY:`. |
| C++ | C++20; `clang-format` (`BasedOnStyle: Google`, `ColumnLimit: 100`); `-Wall -Wextra -Werror` cho code của mình (không áp cho dependency). Namespace `glassy`; hàm `snake_case`, type `PascalCase`, hằng số `kPascalCase`. Không ném exception qua ranh giới C ABI. |
| Go | `gofmt`, `go vet`; test dạng table-driven. |
| TS/JS | ES module, `const`/`let`, không dùng framework. |
| Shell | `#!/usr/bin/env bash`, `set -euo pipefail`, `trap` để dọn dẹp, sạch lỗi `shellcheck`. |

## 5. Commit

- Viết bằng tiếng Anh, dạng `<type>(<scope>): <summary>`. `type` là một trong `feat`, `fix`, `test`, `docs`, `refactor`, `chore`, `spike`.
- Mỗi commit phải build được và pass test của phần đã thay đổi.

## 6. Spike

- Code trong `spikes/` và `bench/aws/` là **throwaway**: code production không được phụ thuộc vào nó.
- Code spike **vẫn phải tuân theo toàn bộ quy ước trong file này.**
