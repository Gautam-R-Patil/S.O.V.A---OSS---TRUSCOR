<!-- status: implemented -->

# P5 production-isolation research refresh

- **Date:** 2026-08-27
- **Decision:** Firecracker is the primary hostile-job worker; Kata remains
  disabled by default; gVisor remains a lower-assurance compatibility lane.
- **Adoption mode:** architecture and security controls were adapted behind SOVA
  contracts. No third-party source code was copied into the worker package.

## Firecracker

Firecracker's production-host guidance and jailer design match SOVA's need for a
small per-job VM boundary: KVM, one VMM process per microVM, jailer chroot and
privilege drop, cgroups, namespaces, and seccomp. The guidance also makes clear
that the operator still owns host hardening, patching, swap policy, output
control, network filtering, and per-tenant process isolation.

SOVA therefore adopts the architecture but adds its own immutable job authority,
mTLS plus DSSE protocol, CAS, endpoint/secret brokers, controller-side evidence
validation, and receipt model. Host egress is deny-by-default because Firecracker
does not itself supply the destination policy SOVA needs.

The implementation follows the jailer's documented details rather than a generic
VM wrapper: the jail root is `<base>/<exec-name>/<id>/root`; the jailer forwards
the VM ID and writes `<exec-name>.pid`; its integration tests verify that jailed
`/dev/kvm` is a character device owned by the instance UID/GID; cgroup-v2 values are repeated
`--cgroup key=value` arguments; and Firecracker is configured and started with
`204`-checked PUT requests over a Unix-domain API socket. The resulting lifecycle
receipt remains non-authorizing until the exact-host matrix and independent review
exist.

The protocol pins `1.16.1`, the current supported v1.16 patch at research time.
The release policy supports the v1.16 line through at least 2026-12-03. Two recent
advisories materially influenced the design:

- GHSA-36j2-f825-qvgc described a jailer symlink host-file overwrite and was fixed
  in 1.13.2 and 1.14.1. SOVA requires root-controlled, non-symlink host paths and
  exact binary pins.
- GHSA-776c-mpj7-jm3r described a PCI virtio out-of-bounds write and was fixed in
  1.14.4 and 1.15.1. Firecracker's default MMIO transport was not affected; SOVA
  explicitly disables PCI rather than treating a version pin as the only control.

Primary sources:

- [Firecracker production host setup](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md)
- [Firecracker jailer documentation](https://github.com/firecracker-microvm/firecracker/blob/main/docs/jailer.md)
- [Firecracker jailer integration test](https://github.com/firecracker-microvm/firecracker/blob/main/tests/integration_tests/security/test_jail.py)
- [Firecracker release policy](https://github.com/firecracker-microvm/firecracker/blob/main/docs/RELEASE_POLICY.md)
- [Firecracker releases](https://github.com/firecracker-microvm/firecracker/releases)
- [Firecracker API actions](https://github.com/firecracker-microvm/firecracker/blob/main/docs/api_requests/actions.md)
- [Firecracker OpenAPI contract](https://github.com/firecracker-microvm/firecracker/blob/main/src/firecracker/swagger/firecracker.yaml)
- [GHSA-36j2-f825-qvgc](https://github.com/firecracker-microvm/firecracker/security/advisories/GHSA-36j2-f825-qvgc)
- [GHSA-776c-mpj7-jm3r](https://github.com/firecracker-microvm/firecracker/security/advisories/GHSA-776c-mpj7-jm3r)

## Kata Containers

Kata's VM-backed OCI ergonomics are attractive for a future compatibility lane,
but its official advisory set contained multiple 2026 critical/high host-impact
issues at research time, including unsafe host bind mounts from annotations,
policy path subversion, configuration-path loading, block-device hotplug,
virtiofs/virtiofsd issues, and a Dragonball virtio-blk escape class. This is why
`assess_kata_backend` fails closed on version, digest, advisory, annotations,
mounts, and root-owned configuration paths. SOVA does not make a generic “Kata is
safe” statement.

Primary source: [Kata Containers security advisories](https://github.com/kata-containers/kata-containers/security/advisories).

## gVisor

gVisor interposes a user-space application kernel and has a useful two-layer
sandbox model, but its own security documentation states the boundary is not a VM
and does not cover hardware side channels or higher-level runtime mistakes. It is
therefore useful for compatibility testing, not the primary arbitrary-hostile-code
claim.

Primary sources:

- [gVisor security model](https://gvisor.dev/docs/architecture_guide/security/)
- [gVisor architecture introduction](https://gvisor.dev/docs/architecture_guide/intro/)

## Rejected shortcuts

- Docker/Desktop presence is not proof of a dedicated hostile-code boundary.
- WSL2 with `/dev/kvm` is a development environment, not a dedicated reviewed
  worker.
- A generated jailer command is not a passed containment test.
- Self-issued attestation is integrity evidence, not independent assurance.
- “No escape observed” does not mean escape is impossible.

## 2026-08-28 network-plane refresh

Firecracker's design and production-host guidance explicitly place guest egress
filtering on the host: the guest VirtIO device terminates at a TAP device and
Firecracker does not enforce destination policy. SOVA therefore added an exact
per-job namespace/TAP/veth/nftables compiler instead of copying the permissive
global NAT example from Firecracker's getting-started guide.

[Pipelock](https://github.com/luckyPipewrench/pipelock) was reviewed as the
strongest current open-source mediator candidate. Its deployment guidance states
the same core rule SOVA needs: the agent can reach only the proxy, while the proxy
alone can reach the Internet. It also explicitly warns that `HTTP_PROXY` alone is
not a security boundary and that raw sockets bypass cooperative proxy settings.
SOVA adapted that topology to a Firecracker TAP namespace, separating the guest
segment from the mediator uplink and filtering namespace output by an exact per-job
mediator UID.

Pipelock is not vendored, copied, or silently treated as compatible. A second
source review pinned revision `1876e2326908ee57d764adf6a62f27a851c1d92a` and
confirmed that the Apache-2.0 community source contains exact network/host/port
grants and scan-to-dial DNS snapshots. Those grants are wired into Pipelock
Guard's workload wrapper, not its standalone `run` proxy. The repository also
contains separately licensed ELv2 enterprise files, so prebuilt mixed-tier
artifacts are not an acceptable shortcut. Pipelock's direct proxy CLI/config
still does not implement SOVA's immutable initial-pin equality, selected-address,
canonical SOVA receipt, or worker-job binding contract.

SOVA therefore implements `deploy/worker/network-mediator` as a small separately
pinned Rust binary. It adapts the exact-grant, immutable address floor,
resolve-then-connect, proxy-only, and fail-closed evidence ideas without copying
Pipelock code. The binary rejects noncanonical/tampered policies, UDP/raw TCP,
authority confusion, transfer-encoding ambiguity, proxy credentials, DNS-set
drift, prohibited addresses, budget expiry/exhaustion, and HTTPS CONNECT whose TLS
ClientHello SNI differs from the authorized hostname. It connects to the selected
IP literal and emits canonical contiguous content-addressed receipts through the
controller-owned evidence contract. Eleven Rust unit tests, strict Clippy, a
Python-made wire fixture, the Python schema, exact dependency lock, CI release
build, licence ledger, and RustSec gate are implemented. A stripped static PIE
musl build (`sha256:6a4609267a8a0606227dcf883a97d8a8d912a5894afa085dfd137ef4847b98b7`)
was byte-identical across two isolated Cargo target directories and passed a WSL
developer smoke: it denied an unauthorized `example.com:80` flow,
persisted a canonical receipt, and that receipt passed the Python controller's
schema, digest, sequence, and job-binding checks. This is cross-language
implementation evidence only. The artifact has not run the dedicated-host
matrix, so no production approval is claimed.

The integration review found two controls that neither upstream project supplies
for SOVA: crash-persistent exclusivity for the UID/GID/address slot, and a
controller-verifiable return path for mediator receipts. SOVA therefore uses
root-controlled `O_EXCL` lease files that survive process restarts, disjoint
policy-pinned job and mediator identity ranges, and a bounded per-job
mediator-owned receipt directory. Host preflight requires the complete configured
ranges to be absent from passwd/group allocation. Leases are released only after
complete cleanup and evidence; receipt capture rejects links, wrong owners, malformed or
noncanonical documents, invalid digests, cross-job bindings, and sequence gaps.
The network receipt also records successful state removal. These are SOVA-specific
adaptations, not claims about Firecracker or Pipelock.

Additional primary sources:

- [Firecracker design and TAP integration](https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md)
- [Firecracker production host egress filtering](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md#filtering-guest-egress-network-traffic)
- [Pipelock deployment enforcement tiers](https://github.com/luckyPipewrench/pipelock/blob/main/docs/guides/deployment-recipes.md)
- [Pipelock configuration and forward-proxy limitations](https://github.com/luckyPipewrench/pipelock/blob/main/docs/configuration.md)
- [Pipelock TLS-interception limitations](https://github.com/luckyPipewrench/pipelock/blob/main/docs/guides/tls-interception.md)
- [Pipelock Apache-2.0 licence](https://github.com/luckyPipewrench/pipelock/blob/main/LICENSE)
- [Pipelock Guard exact service grants](https://github.com/luckyPipewrench/pipelock/blob/main/internal/config/schema.go)
- [Pipelock resolve-to-dial enforcement](https://github.com/luckyPipewrench/pipelock/blob/main/internal/proxy/ssrf_dial_block.go)
- [Pipelock security and edition boundary](https://github.com/luckyPipewrench/pipelock/blob/main/SECURITY.md)
