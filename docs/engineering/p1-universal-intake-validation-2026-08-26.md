<!-- status: implemented -->

# P1 universal intake validation

- **Date:** 2026-08-26
- **Branch:** `codex/universal-target-foundation`
- **Gate:** P1-01 through P1-17
- **Result:** complete for the P1 contract and intake boundary

## Delivered

P1 adds a SOVA-owned, versioned universal-intake layer without replacing or
bypassing the existing authority, executor, trace, capsule, and evidence systems:

- secret-free composite `TargetProfile` library and JSON Schema contract;
- bounded materials readers and front ends for web, API, source/package, OCI,
  network/TLS, desktop/accessibility, agent, MCP, A2A, and declared third parties;
- deterministic provenance-separated workflow and attack-surface graphs;
- explicit declared/discovered/exercised/reproduced/blocked/unsupported/unknown
  coverage states and false-by-default completeness claims;
- start/end material fingerprinting, fail-closed drift, explicit failure nodes,
  and inconclusive results for malformed or missing required evidence;
- transactional report, signed `.sova-trace`, and offline-verifiable `.sova`
  capsule output; and
- the same Python contracts behind `target profile-create`, `profile-validate`,
  and `intake`.

The normative behavior is documented in the
[universal target intake specification](../specifications/universal-target-intake-0.1.md).

## Checklist evidence

| IDs | Evidence |
|---|---|
| P1-01–P1-04 | `contracts.py` enforces versioned composite identity, exact material digests, inert entry points, opaque `sova-secret:` references, non-secret constraints, and optional exact legacy authority binding. Intake executes no target code and imports active observations only with an explicit flag. |
| P1-05–P1-11 | `frontends.py` and `materials.py` implement the bounded content readers and projections for every listed target class. Source trees are bounded; archives are inspected without extraction and reject traversal, links, devices, and limit violations. |
| P1-12–P1-16 | `model.py` and `pipeline.py` implement deterministic graph IDs, evidence class and source digests, decimal-string confidence, non-interchangeable coverage states, explicit failures, start/end fingerprints, and drift/inconclusive status. |
| P1-17 | The pipeline writes a validated report, signed existing-schema trace, and existing-schema capsule transactionally. The integration test independently verifies trace and package signatures/digests through `TraceReader` and `PackageReader`. |

## Owned and adverse fixtures

The deterministic composite fixture declares every `ProfileTargetKind` and binds
HTML, web inventory, HAR, OpenAPI, GraphQL, gRPC, Postman, source tree, SBOM,
lockfile, OCI manifest/config/runtime inventory, network/TLS inventory,
process/accessibility inventory, agent manifest, MCP manifest, and A2A card. It
asserts that all materials parse, graphs are populated, every target kind is
accounted for, and the deliberately unsupported third-party boundary remains
`unknown` rather than being counted as covered.

Adverse tests verify:

- raw secret-shaped profile values are rejected;
- arbitrary active-observation labels and values cannot leak into artifacts;
- active observations are blocked without explicit import authorization;
- changed material and tampered reports fail closed;
- malformed required material is inconclusive, never clean;
- unsafe archive traversal is rejected without extraction; and
- CLI creation, validation, material rebinding, intake, trace, and capsule paths
  use the same contracts as the library.

This is the P1 blind-inflation review: incomplete, unknown, blocked, malformed,
drifted, and unobserved surfaces are not silently converted to success. It is not
an external penetration-test validation or evidence that all surfaces were found.

## Validation receipts

| Gate | Result |
|---|---|
| Focused P1, CLI audit, and cross-validator schema suite | `23 passed in 27.99s` |
| Secret-fixture remediation rerun | `9 passed in 2.92s` |
| Ruff check | pass |
| Ruff format check | `11 files already formatted` |
| Mypy intake package | `Success: no issues found in 6 source files` |
| Full mandatory repository suite after final production-code change | `2108 passed, 30 skipped in 178.12s` |
| Repository policy | `REPOSITORY_POLICY_CHECK=PASS`, 729 files scanned |
| Public boundary | `PUBLIC_BOUNDARY_CHECK=PASS`, 729 files scanned |
| Patch whitespace | `git diff --check` pass |

The first full-suite run had one Windows `WinError 10053` socket abort in an
unmodified replay HTTP test after 2,107 other passes. That exact test passed three
consecutive isolated reruns, and the complete clean rerun above then passed. The
public-boundary scanner also initially rejected an intentionally fake provider-key
shape in a secret-rejection test; the fixture was changed to a provider-neutral
secret marker and the test and scanner both passed.

The 30 skips are existing explicitly optional live-browser, provider, Docker,
gVisor, MELRA/CUA, and Windows-symlink lanes. They are not counted as P1 evidence.

## Research and reuse result

The same-day second pass is recorded in the
[OSS architecture adoption ledger](../research/oss-architecture-adoption-ledger-2026-08-26.md).
No third-party source code was copied into P1. Mature upstream systems remain
future adapters or architectural references; SOVA retains the trusted authority,
coverage, evidence, reproduction, replay, and claim boundary.

## Limits and next gate

P1 accepts and maps content-bound materials and approved observation outputs. It
does not yet provide the P2 methodology compiler/playbook library, P3 executable
scanner adapters, P4 oracle calibration, P5 Linux/KVM hostile-agent worker, or P6
blinded cross-provider public-release evidence. It cannot guarantee that every
workflow, surface, or vulnerability was found.
