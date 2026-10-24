# glassy-proto

Reference implementation of the glassy byte-level wire format (SP1): tickets, connect-info,
native UDP packets (`CONNECT`, `ACCEPT`, `REJECT`, `DATA`, `DISCONNECT`), frames, message
framing and the WebTransport path codec. The C++ library in `cpp/glassy-proto` must match this
crate byte for byte and error code for error code, checked through the golden vectors in
`vectors/*.json`.

Spec: [`docs/superpowers/specs/2026-10-23-sp1-glassy-proto-design.md`](../../docs/superpowers/specs/2026-10-23-sp1-glassy-proto-design.md).

Every public item is re-exported at the crate root (`glassy_proto::build_connect`) and stays
reachable through its module (`glassy_proto::packet::build_connect`). The `varint` helpers are
only available as `glassy_proto::varint::{encode, decode, encoded_len}`.

## Tests

```sh
cargo nextest run -p glassy-proto
cargo test --doc -p glassy-proto
```

## Regenerating the golden vectors

The generators are `#[ignore]`d tests named `write_*`. Re-running them must leave `git diff`
clean unless the wire format changed on purpose.

```sh
cargo nextest run -p glassy-proto --run-ignored only -E 'test(/^write_/)'
```
