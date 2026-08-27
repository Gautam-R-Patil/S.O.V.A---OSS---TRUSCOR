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
receipts, worker attestation, and explicit Kata/gVisor compatibility policies.

The normative behavior is in the
[controller/worker specification](../specifications/controller-worker-production-isolation-0.1.md),
and the source selection, advisories, machine probe, and non-adoptions are in the
[P5 research record](../research/p5-production-isolation-research-2026-08-27.md).

## Checklist evidence

| ID | State | Evidence |
|---|---|---|
| P5-01 | Open | Windows remains the controller, but no dedicated patched Linux/KVM worker has been provisioned or attested in this evidence set. The local WSL2 environment is developer-only. |
| P5-02 | Implemented | Versioned manifests, content references, TLS 1.3 mutual-authentication contexts, certificate-bound DSSE messages, expiry, replay defense, and immutable CAS verification pass focused tests. |
| P5-03 | Partially implemented | The Firecracker 1.16.1 plan is compiled, command-drift checked, staged with guest-UID ownership, executed by a root-only Unix-socket/API/pidfd/watchdog lifecycle backend, and schema-receipted. It has not executed a live microVM on the exact worker. |
| P5-04 | Implemented | Network rules, exact endpoint and DNS revalidation, address selection, global/private policy, budgets, and receipts pass positive and adverse tests. Loopback, link-local, and metadata endpoints remain denied. |
| P5-05 | Implemented | Opaque scalar secret capabilities enforce job, audience, expiry, and use limits; receipts omit token and value; revocation and redaction checks pass. |
| P5-06 | Implemented | ZIPs are processed in memory with path, file type, encryption, member, ratio, and byte checks; guest signatures, manifests, digests, schemas, authority, and redaction are verified before controller signing. |
| P5-07 | Implemented policy | Kata remains disabled unless an exact reviewed version and advisory snapshot are approved. It is not granted generic equivalence. |
| P5-08 | Implemented policy | gVisor is represented as a lower-assurance compatibility backend and never as Firecracker-equivalent production isolation. |
| P5-09 | Partially implemented | All ten attack classes have local policy/adverse coverage. The cases requiring actual kernel, VMM, network namespace, cgroup, and cleanup behavior remain unexecuted on the exact host. |
| P5-10 | Open | No independent reviewer has signed an exact-image/kernel/microcode/VMM/policy receipt. No escape-impossibility claim is made. |

## Deterministic acceptance

Two consecutive executions of `scripts/validate_p5_worker.py` produced the same
receipt digest:
`sha256:f64aee7eff04f7686ee3263a56fb3cdbbeb58551b099063dde58fd98d1e9cbb5`.
The receipt reports `localImplementationAcceptancePassed=true`, while retaining
`p5ExitGatePassed=false`, `productionIsolationClaimAllowed=false`,
`liveFirecrackerExecuted=false`, `exactHostContainmentTested=false`, and
`independentlyReviewed=false`.

## Validation receipts

| Gate | Result |
|---|---|
| Focused worker tests | `114 passed`; combined statement/branch worker coverage `95.73%`; lifecycle module `96.79%` |
| Focused Ruff and strict mypy | passed; no issues in 15 focused source/test files |
| Full repository suite | `2,574 passed, 30 skipped in 936.72s` |
| Combined statement/branch coverage | `95.14%`; mandatory 95% gate passed |
| Full Ruff format and lint | `714 files already formatted`; all checks passed |
| Full strict mypy | no issues in 516 source files |
| CLI parser-to-handler execution audit | `148/148`; no unexecuted command |
| Wheel and source distribution | built `sova_oss-0.1.0a0`; all nine P5 schemas are present in both artifacts |
| Repository policy | passed; 864 tracked or unignored files scanned |
| Public-boundary scan | passed; 864 tracked or unignored files scanned |

## Evidence interpretation

These receipts establish the local contract, parser, broker, launch-plan,
admission-to-lifecycle integration, API/watchdog/pidfd state machine, attestation,
evidence-validation, cleanup, and fail-closed backend-policy behavior.
They do not establish that a hostile process was contained by a production
Firecracker host. P5 can be locally implementation-complete while its production
exit gate remains open; advertising production-grade isolation requires the exact
dedicated-host and independent-review receipts above.
