# SOVA network mediator 0.1

This crate builds the separately pinned, fail-closed network mediator required by
the SOVA Firecracker worker. It is intentionally not a general-purpose proxy.
Protocol 0.1 accepts only HTTP forward proxy traffic, HTTPS `CONNECT` with an
exact matching TLS SNI, WebSocket handshakes, and MCP-over-HTTP.

The mediator:

- accepts only the three compiler-owned arguments expected by the worker;
- verifies canonical policy JSON and its SHA-256 content binding;
- enforces exact hostname, TCP port, complete DNS-pin set, selected address,
  private-address policy, expiry, connection count, and aggregate byte budget;
- connects to the selected IP literal so a second DNS lookup cannot redirect the
  socket;
- rejects raw TCP/UDP, request smuggling shapes, proxy credentials, mismatched
  authorities, and `CONNECT` traffic whose ClientHello SNI does not match;
- writes canonical, content-addressed, contiguous receipts with create-new and
  durable rename semantics; and
- exits after any receipt-integrity failure so the controller rejects the job.

## Reproducible Linux build

Use a reviewed Linux builder with the Rust toolchain pinned by the release
ledger. The production artifact is the musl target, not a developer-host binary:

```sh
rustup toolchain install 1.88.0 --profile minimal --component clippy,rustfmt --target x86_64-unknown-linux-musl
cargo +1.88.0 test --locked
cargo +1.88.0 build --locked --release --target x86_64-unknown-linux-musl
sha256sum target/x86_64-unknown-linux-musl/release/sova-network-mediator
```

The release-candidate workflow additionally emits a deterministic Cargo-lock
CycloneDX SBOM, includes the binary in the exact release-tree checksum manifest,
and keyless-signs both files. `scripts/smoke-wsl.sh` is a developer-only denied
flow/receipt interop check; it does not substitute for the exact-host matrix.

Install the root-owned mode-0755 binary at the exact path and digest declared in
the worker policy. The dedicated-host acceptance matrix remains mandatory; a
successful developer build does not approve a production mediator.

## Architectural provenance

The exact destination grant, immutable SSRF floor, resolve-then-dial snapshot,
and proxy-only topology adapt community-source Pipelock design ideas reviewed at
revision `1876e2326908ee57d764adf6a62f27a851c1d92a` (Apache-2.0 core). No
Pipelock code is copied or vendored. Pipelock's standalone proxy is not used
because its direct CLI/config does not implement SOVA's complete immutable
DNS-pin and receipt contract.
