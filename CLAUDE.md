# glassy

Read `CONVENTIONS.md` before writing any code. The rules that matter most:

- All code comments, identifiers, log/error messages, test names and commit messages are in **English**. Documents under `docs/` are written in Vietnamese with English technical terms.
- Rust tests run with **`cargo nextest run`**, never `cargo test` (the only exception is `cargo test --doc`).
- Stay within the OOM limits in `CONVENTIONS.md` §3: 2 build jobs, 2 nextest threads, integration tests serialized, bounded buffers.
- Design spec: `docs/superpowers/specs/`. Implementation plans: `docs/superpowers/plans/`.
- `spikes/` and `bench/aws/` are throwaway; production code must not depend on them.
