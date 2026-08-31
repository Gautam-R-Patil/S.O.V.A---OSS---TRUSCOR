<!-- status: implemented -->

# P5 production-isolation worker validation

- **Date:** 2026-08-27
- **Branch:** `codex/universal-target-foundation`
- **Gate:** P5-01 through P5-10
- **Result:** local implementation complete; production-isolation exit gate remains open

## Delivered boundary

P5 adds an immutable controller/worker job contract, TLS 1.3 mutual-authentication
contexts, certificate-bound DSSE messages, replay and expiry enforcement, an
immutable content-addressed store, exact network and secret brokers, a Firecracker
1.16.1 jailer/MMIO/cgroup launch compiler plus executable lifecycle state machine,
hostile-output validation, controller-signed evidence, cleanup and lifecycle
receipts, a mediator-only per-job TAP/veth/nftables plane, strict deployment-policy
loader, disjoint per-job job and mediator identity ranges, persistent exclusive
identity-slot leases, canonical mediator-receipt capture, check-only host preflight,
an eleven-case exact-host receipt compiler,
worker attestation, and explicit Kata/gVisor compatibility policies.

The normative behavior is in the
[controller/worker specification](../specifications/controller-worker-production-isolation-0.1.md),
and the source selection, advisories, machine probe, and non-adoptions are in the
[P5 research record](../research/p5-production-isolation-research-2026-08-27.md).

## Checklist evidence

| ID | State | Evidence |
|---|---|---|
| P5-01 | Open | Windows remains the controller, but no dedicated patched Linux/KVM worker has been provisioned or attested in this evidence set. The local WSL2 environment is developer-only. |
| P5-02 | Implemented | Versioned manifests, content references, TLS 1.3 mutual-authentication contexts, certificate-bound DSSE messages, expiry, replay defense, and immutable CAS verification pass focused tests. |
| P5-03 | Partially implemented | The Firecracker 1.16.1 plan is compiled, command-drift checked, staged with a unique job UID/GID, executed by a root-only Unix-socket/API/pidfd/watchdog lifecycle backend, and schema-receipted. Persistent `O_EXCL` leases prevent concurrent or post-crash identity/address-slot reuse and release only after complete cleanup/evidence. The online guest now receives its deterministic `/30` and proxy endpoint. It has not executed a live microVM on the exact worker. |
| P5-04 | Implemented locally | Network rules, exact endpoint and DNS revalidation, address selection, global/private policy, budgets, and receipts pass positive and adverse tests. The host compiler creates separate TAP and mediator-uplink segments, deny-all namespace forwarding, output restricted to the exact per-job mediator UID, mediator-only `/32` NAT, and evidence-bound cleanup. The Rust mediator verifies canonical policy, exact DNS set and selected literal address, HTTP authority, TLS SNI, budgets, and receipts. Its static musl build passed a real WSL denied-flow/receipt interop smoke; no production artifact has run inside the exact worker namespace. |
| P5-05 | Implemented | Opaque scalar secret capabilities enforce job, audience, expiry, and use limits; receipts omit token and value; revocation and redaction checks pass. |
| P5-06 | Implemented | ZIPs are processed in memory with path, file type, encryption, member, ratio, and byte checks; guest signatures, manifests, digests, schemas, authority, and redaction are verified before controller signing. |
| P5-07 | Implemented policy | Kata remains disabled unless an exact reviewed version and advisory snapshot are approved. It is not granted generic equivalence. |
| P5-08 | Implemented policy | gVisor is represented as a lower-assurance compatibility backend and never as Firecracker-equivalent production isolation. |
| P5-09 | Partially implemented | All ten attack classes have local policy/adverse coverage. A strict receipt requires one positive control plus all ten cases and binds execution, network, raw-evidence, and cleanup digests. The cases requiring actual kernel, VMM, network namespace, cgroup, and cleanup behavior remain unexecuted on the exact host. |
| P5-10 | Open | No independent reviewer has signed an exact-image/kernel/microcode/VMM/policy receipt. No escape-impossibility claim is made. |

## Deterministic acceptance

Two consecutive executions of `scripts/validate_p5_worker.py` produced the same
receipt digest:
`sha256:966eab33cfe77257be63d67f8e515bc19b1bbb8d83d051b4fec7555bf2e2cfee`.
The receipt reports `localImplementationAcceptancePassed=true`, while retaining
`p5ExitGatePassed=false`, `productionIsolationClaimAllowed=false`,
`liveFirecrackerExecuted=false`, `exactHostContainmentTested=false`, and
`independentlyReviewed=false`. Its compiled network-plan digest is
`sha256:919acc724769e38a96bdf242109e7fad4b4d03b15cbf498e7736b801cd5b5393`.

## 2026-08-28 continuation

The network-plane continuation adds four immutable artifact families:
`sova.firecracker-network-plan`, `sova.worker-network-plane-receipt`,
`sova.worker-host-preflight-receipt`, and
`sova.worker-exact-host-acceptance-receipt`. `WorkerAdmissionService` can compile
the network plan from the admitted manifest and refuses live execution without an
exact backend binding, a persistent exclusive identity lease, and a returned complete
network receipt. Failed prepare paths now always attempt cleanup, and incomplete
cleanup/evidence intentionally retains the lease. `deploy/worker/provision-host.sh`
is check-only by default; its explicit apply mode creates only root-controlled
directories and downloads nothing. It does not create fixed service identities.
`scripts/check_worker_host.py` measures but never mutates the host, while
`scripts/compile_p5_exact_host_receipt.py` compiles already observed cases and
does not execute or sign them.

The mediator policy is root-owned and read-only, while a bounded per-job receipt
directory is owned only by that job's numeric unprivileged mediator identity.
The job and mediator UIDs/GIDs are derived from disjoint policy-pinned bases plus
the leased identity slot. Cleanup stops the
mediator first, rejects links, non-files, wrong owners, noncanonical JSON, wrong
jobs, invalid digests, and noncontiguous sequences, binds the valid set digest, and
only then removes state. The network receipt records `stateRemoved`; missing state
removal fails cleanup and retains the lease. Host preflight rejects configured job
or mediator ranges that overlap an allocated passwd/group identity and also checks
exact directory modes, root ownership, and binary pins.

The design adapts Pipelock's separate-proxy, exact-grant, and resolve-to-dial
patterns but does not vendor or claim drop-in compatibility with Pipelock. The
SOVA-specific mediator source, lockfile, cross-language policy schema/fixture,
eleven Rust unit tests, strict Clippy gate, licence record, CI/RustSec job, separate
Cargo SBOM, release-tree checksum, Sigstore input, and provenance-attested
release-candidate build are implemented. The 953,392-byte stripped static PIE
developer build has SHA-256
`6a4609267a8a0606227dcf883a97d8a8d912a5894afa085dfd137ef4847b98b7`.
An isolated clean-target rebuild produced the same digest.
Its WSL smoke emitted this
[463-byte `endpoint-not-authorized` receipt](../../tests/fixtures/worker/network-mediator-wsl-denied-receipt.json)
for `example.com:80`; the Python controller accepted the canonical receipt and its
`sha256:15f82ae1d024ee904bb3f46a8ce59eed54fd56c67ff819e8c31d6c5f322f2302`
content binding. Building and pinning the production artifact on the reviewed
builder, executing it inside the exact namespace, and independently reviewing
that measured host remain external P5 gates.

## Validation receipts

| Gate | Result |
|---|---|
| Focused privileged-worker boundary | `79 passed`; selected combined statement/branch coverage `96.20%` |
| Focused Ruff and strict mypy | passed |
| Full repository suite | `2,646 passed, 30 skipped in 492.88s`; zero failed |
| Combined statement/branch coverage | `95.11%`; mandatory 95% gate passed |
| Full Ruff format and lint | `734 files already formatted`; all checks passed |
| Full strict mypy | no issues in 534 source files |
| CLI parser-to-handler execution audit | `149/149`; no unexecuted command |
| Wheel and source distribution | built `sova_oss-0.1.0a0`; all 61 schemas, including all 14 P5 worker/Firecracker schemas, are present in both artifacts |
| Rust mediator unit/lint gate | `11 passed`; Rust 1.88.0 format and strict Clippy passed |
| Rust mediator advisory gate | `cargo-audit 0.22.2` scanned 58 locked dependencies against 1,233 loaded RustSec advisories; zero findings and no ignores |
| Rust mediator artifact gate | 953,392-byte stripped static PIE; isolated builds were byte-identical; WSL denied-flow receipt passed the Python controller validator |
| Candidate release tree | Python wheel/sdist, both CycloneDX SBOMs, and mediator binary passed exact five-file SHA-256 membership verification; signing/attestation remains a CI/publication-time gate |
| Repository policy | passed |
| Public-boundary scan | passed |

## Evidence interpretation

These receipts establish the local contract, parser, broker, launch-plan,
admission-to-lifecycle integration, API/watchdog/pidfd state machine, attestation,
evidence-validation, cleanup, and fail-closed backend-policy behavior.
They do not establish that a hostile process was contained by a production
Firecracker host. P5 can be locally implementation-complete while its production
exit gate remains open; advertising production-grade isolation requires the exact
dedicated-host and independent-review receipts above.
