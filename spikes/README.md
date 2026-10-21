> THROWAWAY: code trong spikes/ chỉ để trả lời các câu hỏi S1–S5 của SP0; không dùng cho production.

# SP0 spikes

Mỗi spike trả lời một câu hỏi khả thi trong §11 của
`docs/superpowers/specs/2026-10-21-glassy-architecture-design.md`. Kết quả được ghi vào
`docs/superpowers/spikes/2026-10-21-sp0-findings.md`.

Quy ước (comment tiếng Anh, test Rust bằng `cargo nextest run`, giới hạn chống OOM): xem `CONVENTIONS.md`.

| Thư mục | Spike | Nội dung |
|---|---|---|
| `gw-proto/` | S1, S2, S4 | Gateway prototype ở userspace (Rust) |
