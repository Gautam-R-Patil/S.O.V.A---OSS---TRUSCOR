<!-- status: decision -->

# ADR-0028: Universal-security extension boundary

- **Status:** Accepted
- **Date:** 2026-08-26
- **Owner:** SOVA OSS maintainers
- **Scope:** universal target intake, methodology, external tools, agent runtimes,
  benchmarks, isolation workers, and community playbooks

## Context

SOVA already owns authorization, heterogeneous execution, evidence, reproduction,
replay, and community artifact contracts. Mature open-source scanners, agent
frameworks, benchmarks, and isolation runtimes can accelerate the remaining work,
but replacing SOVA's core with any one of them would discard the product's strongest
implemented invariants and create licence, safety, provenance, and compatibility
risk.

## Decision

Universal-security work extends the existing architecture. It does not introduce a
second trusted runtime or a second evidence truth model.

The following seams are load-bearing and remain authoritative through the `0.1`
line:

1. `sova.executors.contract.Executor`, `Capability`, `ActionRequest`,
   `ActionOutcome`, `ExecutionContext`, and `CancellationToken` are the execution
   boundary. External tools and workers are executors or are invoked by executors.
2. `AuthorizationKernel`, `AuthorityEnvelope`, effect budgets, proof of control,
   approval challenges, target/session generations, and target fingerprints remain
   mandatory for consequential execution. A planner, playbook, tool, benchmark, or
   guest cannot grant authority.
3. `TargetManifest`, `TargetInstance`, `SessionEnvelope`, and capability generations
   bind observations and effects to one admitted target generation. Universal intake
   adds typed profile extensions; it does not loosen target identity.
4. `RoleModel` and `ProviderAdapter` keep models proposal-only. Models never receive
   executor objects, unrestricted secret providers, host paths, daemon sockets, or
   signing keys.
5. `TraceWriter` and the accepted `.sova-trace` model are the event evidence path.
   Adapter output is an observation or attachment, never a trusted trace or verdict.
6. `build_capsule` and the accepted `.sova` model remain the portable packaging
   path. Unknown required behavior fails compatibility; extensions cannot silently
   change execution semantics.
7. Replay keeps inert playback, controlled re-execution, and fresh reproduction
   distinct. Importing third-party logs or videos cannot establish reproduction.
8. `RegistryEntry`, `RegistryIndex`, contribution screening, provenance, licence,
   verification tier, and disclosed operator control remain the community boundary.

### Adapter rule

Third-party projects enter through one of four explicit classes:

- **External adapter:** execute a pinned operator-installed tool and normalize its
  output. No source vendoring and no tool verdict promoted without SOVA evidence.
- **Benchmark adapter:** translate licensed task inputs/results while preserving the
  upstream task identifier, commit, licence, scorer, and failure states.
- **Reference data:** keep standards, taxonomies, and playbooks in a separately
  attributed data layer whose licence may differ from SOVA code.
- **File-level adaptation:** allowed only after an exact upstream commit and file,
  licence/NOTICE, authorship, security posture, tests, local redesign, and attribution
  are recorded. A repository-level licence does not clear bundled third-party prose,
  payloads, datasets, templates, or binaries.

Every promoted adapter is version/digest pinned, authority-routed, bounded, trace-
recorded, failure-tested, provenance-recorded, and independently reproduced on an
owned fixture. Telemetry, uploads, implicit pulls, auto-update, and remote generation
are disabled by default.

### Isolation rule

The Windows application is a controller, not the final hostile-code security
boundary. Production execution of completely untrusted agents requires a dedicated,
patched Linux/KVM worker and one independently contained VM-grade guest per job. The
guest cannot sign or adjudicate SOVA evidence. Docker Desktop and gVisor remain
compatibility/lower-assurance backends. Kata and Firecracker integrations inherit
their exact-version advisories and do not create an unconditional “safe” claim.

## Compatibility promise

P1–P6 may add optional fields, typed extension objects, adapters, and worker protocols
under ADR-0002. They may not reinterpret existing artifact types, weaken mandatory
authority/evidence checks, accept an unsupported required feature, or silently
discard unknown values. A needed breaking change requires a superseding ADR,
migration report, conformance fixtures, and an explicit compatibility result before
implementation.

## Alternatives rejected

- Fork PentAGI, PentestGPT, AutoPentest, CAI, HexStrike, or PentestAgent as the new
  SOVA core: each solves only part of the problem and would create a competing trust
  and evidence architecture.
- Treat MCP tool servers as the safety/evidence boundary: tool schemas and responses
  are untrusted target-side inputs.
- Vendor every scanner and template set: increases licence, update, supply-chain,
  platform, and distribution risk.
- Let model reasoning create authority or final vulnerability verdicts: neither model
  strength nor a harness establishes control, truth, or completeness.
- Promise exhaustive vulnerability discovery or universal reliable oracles: those
  claims are not technically supportable.

## Consequences

The architecture can move quickly by reusing maintained scanners and benchmarks
without rebuilding their algorithms, while SOVA keeps one authorization and evidence
kernel. Integration work must include provenance and negative-path tests. Some tools
will remain optional or legally isolated, and completely hostile workloads require a
Linux/KVM worker rather than an unsupported Windows-only production claim.
