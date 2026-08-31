<!-- status: planned -->

# SOVA OSS universal-security launch checklist

**Controlling date:** 2026-08-26

**Tracking rule:** every implementation update cites the exact checklist ID below.

**Authority:** this checklist supersedes dates and completion claims in earlier
last-mile plans. Earlier plans remain useful implementation history.

## 1. What completion means

The launch target is a defensible security-assessment platform that can accept
multiple target classes, map observed workflows and attack surfaces, compile a
bounded methodology, execute approved tools and agents, calibrate evidence-backed
oracles, reproduce findings, and report measured coverage. SOVA's authorization,
containment, signed trace, capsule, replay, Registry, and disclosure contracts
remain the product core.

Completion does **not** mean that SOVA can prove every workflow was understood,
guarantee every vulnerability was found, create a reliable oracle for every
possible system, turn every weak model into an expert, or make untrusted code safe
without a maintained isolation boundary. Those are impossible or evidence-dependent
claims. The product must expose unknown, unsupported, unobserved, inconclusive, and
infrastructure-failure states instead of translating them into success.

## 2. Status summary

| Phase | Gate | Status | Exit evidence |
|---|---|---|---|
| P0 | Preserve and freeze the foundation | **COMPLETE** | [P0 baseline](./p0-foundation-baseline-2026-08-26.md), [ADR-0028](../decisions/0028-universal-security-extension-boundary.md), preservation commit |
| P1 | Universal intake and workflow/surface model | **COMPLETE** | [P1 validation](./p1-universal-intake-validation-2026-08-26.md), target-profile fixtures, measured discovery reports, compatibility tests |
| P2 | Methodology compiler and native playbook library | **COMPLETE** | [P2 validation](./p2-methodology-compiler-validation-2026-08-26.md), 74 versioned playbooks, deterministic compiler and replanning conformance, signed contribution tests |
| P3 | Tool adapters and evidence normalization | **COMPLETE** | [P3 validation](./p3-security-adapter-validation-2026-08-27.md), 21-entry admission catalog, 12 promoted normalizers, authority-routed runner and failure matrix |
| P4 | Oracle laboratory, reproduction, and coverage accounting | **COMPLETE** | [P4 validation](./p4-oracle-laboratory-validation-2026-08-27.md), blinded positive/adverse study, fresh reproduction, eight-dimensional coverage contract |
| P5 | Production isolation and untrusted-agent worker | **LOCAL IMPLEMENTATION COMPLETE; EXIT GATE OPEN** | [P5 validation](./p5-production-isolation-validation-2026-08-27.md); exact Linux/KVM execution and independent review remain open |
| P6 | Blinded validation, Registry beta, and public launch | **LOCAL IMPLEMENTATION COMPLETE; EXIT GATE OPEN** | [P6 validation](./p6-validation-and-launch-readiness-2026-08-27.md); live benchmark, production Registry, reviews, and publication remain open |

The table measures roadmap gates, not a marketing readiness percentage. A phase is
complete only when every mandatory item and its exit gate are complete.

## 3. P0 — preserve and freeze the foundation

- [x] **P0-01** Create `codex/universal-target-foundation` before changing the
  inherited working tree.
- [x] **P0-02** Inventory and classify all inherited changes; preserve the complete
  public implementation rather than selecting files from an uncommitted session.
- [x] **P0-03** Scan public/staged paths for secrets and prohibited material. The
  operator reports the previously disclosed provider credential revoked; no
  provider secret is present in the repository baseline.
- [x] **P0-04** Create one local preservation commit containing the inherited
  implementation and P0 control records. Do not push as part of P0.
- [x] **P0-05** Record source, package, and focused compatibility evidence in the
  P0 baseline record.
- [x] **P0-06** Establish this exact checklist as the single launch tracker.
- [x] **P0-07** Freeze the extension boundary around current executor, authority,
  target, trace, capsule, replay, Registry, and provider contracts in ADR-0028.

**P0 exit gate:** branch exists; inherited public files are classified; staged
boundary and secret scans are clean; focused compatibility tests pass; ADR-0028 and
the research adoption ledger exist; the preservation commit succeeds.

## 4. P1 — universal intake and workflow/surface model

### Target-profile contract

- [x] **P1-01** Add a versioned `TargetProfile` contract with target identity,
  authorization scope, provenance, target kinds, supplied artifacts, observed
  interfaces, credentials-by-reference, environments, constraints, and explicit
  unknowns.
- [x] **P1-02** Support composite profiles spanning web/UI, API, host/network,
  source/package, OCI/image, desktop software, AI model/agent, MCP/A2A, and declared
  third-party-service boundaries.
- [x] **P1-03** Never embed a raw credential, browser profile, sensitive target, or
  unrestricted secret resolver in a portable profile.
- [x] **P1-04** Bind every effectful run to existing proof-of-control, authority,
  approval, budget, containment, and evidence requirements.

### Intake front ends

- [x] **P1-05** URL/web intake: inert crawl seed and content-bound robots/policy,
  DOM and client
  route inventory, forms, upload/download, service workers, WebSockets, browser
  storage, and authentication transitions.
- [x] **P1-06** API intake: OpenAPI/Swagger, GraphQL, gRPC reflection/descriptors,
  Postman/HAR, captured traffic, undocumented endpoint observation, and stateful
  operation links.
- [x] **P1-07** Source/package intake: repository/archive, build metadata, lockfiles,
  SBOM, dependency graph, secrets/config, static entry points, binaries, and test
  fixtures without executing package-controlled setup by default.
- [x] **P1-08** OCI/container intake: manifest/config/layers, entrypoint, SBOM,
  vulnerabilities, capabilities, mounts, ports, image provenance, and runtime
  requirements.
- [x] **P1-09** Network intake: explicitly authorized host/CIDR inventory, services,
  protocol/TLS observations, DNS relationships, and segmentation evidence.
- [x] **P1-10** Agent/MCP/A2A intake: model/provider declarations, tools/resources,
  prompts/policies when supplied, memory, identities, trust boundaries, skills,
  handoffs, protocols, and observed consequential actions.
- [x] **P1-11** Desktop intake: process generation, window/control graph,
  accessibility/automation surfaces, filesystem/process/network side effects, and
  elevated or cross-process boundaries.

### Workflow and surface discovery

- [x] **P1-12** Emit a provenance-separated workflow graph containing states,
  transitions, actors, preconditions, effects, observations, failures, and confidence.
- [x] **P1-13** Emit an attack-surface graph containing inputs, trust boundaries,
  identities, privileges, data stores, dependencies, protocols, tool calls, and
  externally controlled resources.
- [x] **P1-14** Combine supplied specification, static discovery, passive runtime
  observation, and approved active exploration without treating inference as
  execution evidence.
- [x] **P1-15** Add a coverage contract listing declared, discovered, exercised,
  reproduced, blocked, unsupported, and unknown nodes/edges.
- [x] **P1-16** Add change/fingerprint detection so a target that drifts during
  discovery becomes inconclusive or starts a new generation.
- [x] **P1-17** Package intake outputs as offline-verifiable SOVA artifacts and
  traces using existing schemas and extension rules.

**P1 exit gate:** deterministic owned fixtures exist for every target kind; the
same composite contract drives CLI and library use; incomplete discovery is visible;
no target preparation is required beyond authorization and any credentials genuinely
needed by the target; blind fixture review finds no silent coverage inflation.

## 5. P2 — methodology compiler and native playbook library

### Compiler

- [x] **P2-01** Define a versioned playbook contract: objective, target predicates,
  prerequisites, discovery inputs, technique, allowed effects, tool requirements,
  variants, oracle proposal, required evidence, stop rules, cleanup, and mappings.
- [x] **P2-02** Compile a `TargetProfile` plus policy into a dependency-aware,
  budgeted test plan with preconditions and explicit exclusions.
- [x] **P2-03** Use risk, reachability, novelty, state coverage, dependency exposure,
  and evidence gaps for scheduling; retain deterministic baseline schedulers.
- [x] **P2-04** Re-plan from new observations without granting new authority or
  allowing model output to mutate trusted contracts.
- [x] **P2-05** Separate discovery, hypothesis, confirmation, reproduction,
  remediation validation, and reporting phases.

### Reference methodology and library

- [x] **P2-06** Map the library to NIST SP 800-115, OWASP WSTG/ASVS/API Security,
  OWASP AISVS/AI Testing Guide/Agentic guidance, MITRE ATLAS, CWE, CAPEC, and PTES
  where licences and citation terms permit.
- [x] **P2-07** Web playbooks: authentication/session, authorization, input handling,
  business logic, browser/client, file handling, SSRF, deserialization, race/state,
  cache/proxy, cryptography/TLS, privacy, and resilience.
- [x] **P2-08** API playbooks: object/function/property authorization, authentication,
  resource consumption, workflow/business logic, inventory, unsafe consumption,
  GraphQL, gRPC, WebSocket, webhook, OAuth/OIDC/SAML, and mTLS.
- [x] **P2-09** Network/host/cloud playbooks: service/configuration, credentials,
  trust/segmentation, privilege paths, cloud/IAM, Kubernetes, containers, secrets,
  exposed management surfaces, and supply chain.
- [x] **P2-10** Source/package/binary playbooks: dependency, SBOM, secret, SAST,
  build/release, unsafe configuration, fuzzing, binary hardening, and malicious
  package behavior under isolation.
- [x] **P2-11** AI/model playbooks: prompt injection, data leakage, unsafe output,
  excessive agency, model/tool abuse, poisoning, denial of service, evasion,
  hallucination/grounding, privacy, and model supply chain.
- [x] **P2-12** Agentic playbooks: tool authorization, MCP/A2A identity and consent,
  memory poisoning, skill/plugin supply chain, cross-agent trust, delegation,
  confused deputy, goal manipulation, hidden-state transitions, and audit bypass.
- [x] **P2-13** Every playbook names its evidence limits and false-positive risks;
  copied prose or third-party datasets remain separated by licence/provenance.
- [x] **P2-14** Provide signed, versioned community playbook contribution and
  review flow through the existing Registry contracts.

**P2 exit gate:** compiler produces deterministic plans from owned profiles;
playbooks validate against the contract; taxonomy and reference links are pinned;
each initial target class has positive, negative, and inconclusive fixtures.

## 6. P3 — tool adapters and evidence normalization

- [x] **P3-01** Define an adapter descriptor for executable/version/digest, licence,
  supported platforms, target predicates, capabilities, network/effect requirements,
  output schemas, time/resource bounds, and provenance.
- [x] **P3-02** Run adapters through the existing executor and authority kernel; a
  scanner exit code or model assertion is never itself a SOVA finding.
- [x] **P3-03** Normalize raw results into observations with raw-artifact digests,
  parser version, confidence, target binding, and infrastructure-failure separation.
- [x] **P3-04** Pin versions/templates/rules and record configuration hashes in traces.
- [x] **P3-05** Implement first-class adapters for ZAP, Nuclei, Schemathesis,
  PyRIT, garak, promptfoo, Trivy, Syft, Grype, OSV-Scanner, Gitleaks, and Semgrep.
- [x] **P3-06** Implement constrained external-tool descriptors for ffuf, httpx,
  testssl.sh, sqlmap, mitmproxy, and selected protocol tools after per-tool licence
  and safety review.
- [x] **P3-07** Keep Nmap user-installed and legally isolated until its NPSL
  designed-wrapper/redistribution implications receive qualified review.
- [x] **P3-08** Add generic MCP/stdio/HTTP adapter compatibility without trusting
  tool-provided schemas, summaries, or evidence.
- [x] **P3-09** Disable remote test generation, telemetry, uploads, implicit pulls,
  auto-update, and unreviewed templates by default; require a disclosure gate to
  enable any external data transfer.
- [x] **P3-10** Add parser corruption, timeout, partial-output, nondeterminism,
  version drift, false-positive, and cleanup tests for every promoted adapter.

**P3 exit gate:** every promoted adapter is reproducibly installed or operator-
supplied, policy-routed, trace-recorded, failure-tested, and independently
reproduced on at least one owned fixture.

**P3 exit evidence:** the [P3 validation record](./p3-security-adapter-validation-2026-08-27.md)
records exact operator-supplied version and runtime-digest requirements, policy and
trace routing, positive/adverse owned-fixture runs for all 12 promoted adapters,
semantic reproduction, package-resource inspection, and repository-wide release
gates. Live upstream binaries and real targets remain deployment evidence and are
not inferred from synthetic fixtures.

## 7. P4 — oracle laboratory, reproduction, and coverage accounting

- [x] **P4-01** Add typed oracle proposals derived from target contracts,
  specifications, invariants, differentials, metamorphic relations, state effects,
  logs, and human-supplied acceptance criteria.
- [x] **P4-02** Calibrate proposals on known-positive, known-negative, ambiguous,
  and infrastructure-failure cases before promotion.
- [x] **P4-03** Require independent fresh reproduction for confirmed findings,
  including new target generation, environment fingerprint, and causal evidence.
- [x] **P4-04** Add differential and metamorphic comparisons across identities,
  roles, states, providers, versions, configurations, and intervention pairs.
- [x] **P4-05** Record sensitivity, specificity/false-positive evidence, known blind
  spots, confidence, and validity window for promoted oracles.
- [x] **P4-06** Permit `no-reliable-oracle` and `human-review-required`; never force
  a verdict for every target.
- [x] **P4-07** Produce a coverage report over workflow, surface, playbook, state,
  identity/role, adapter, oracle, and reproduction dimensions.
- [x] **P4-08** Keep `not observed`, `unsupported`, `blocked`, `inconclusive`, and
  `infrastructure failure` distinct from `passed` or `safe`.
- [x] **P4-09** Bind decisive cues, raw evidence, replay media, traces, and capsules
  by digest using the existing evidence/replay contracts.

**P4 exit gate:** a blinded seeded study measures false positives and misses;
confirmed findings reproduce from fresh state; coverage reports cannot claim an
exhaustive absence of vulnerabilities.

**P4 exit evidence:** the [P4 validation record](./p4-oracle-laboratory-validation-2026-08-27.md)
records typed proposals, task/prediction/key commitments, injected false-positive
and miss rejection, promoted-oracle metrics and validity, fresh independent
reproduction, digest-bound decisive evidence, eight-dimensional coverage, package
resources, and the repository-wide 95% quality gate. The seeded fixture validates
the machinery; it is not presented as arbitrary-target field accuracy.

## 8. P5 — production isolation and untrusted-agent worker

- [ ] **P5-01** Keep the Windows product as controller; provision a dedicated,
  patched Linux/KVM worker. Docker Desktop remains a compatibility backend, not the
  production claim for hostile workloads.
- [x] **P5-02** Implement a mutually authenticated, versioned controller/worker
  protocol carrying immutable job manifests and content-addressed inputs/outputs.
- [ ] **P5-03** Use one Firecracker microVM per hostile job, launched through the
  jailer with unique UID/GID, namespaces, cgroups, seccomp, read-only base image,
  disposable writable layer, bounded serial/log output, watchdog, and no host mounts.
- [x] **P5-04** Broker network access through explicit destination/protocol policy,
  DNS pinning/revalidation, rate/byte/time budgets, and full flow receipts.
- [x] **P5-05** Broker secrets as scoped, short-lived capabilities; never place host
  credentials, daemon sockets, browser profiles, or signing keys in a guest image.
- [x] **P5-06** Separate evidence extraction from guest verdicts; verify manifests,
  digests, sizes, schemas, signatures, and redaction on the controller side.
- [x] **P5-07** Treat Kata Containers as an optional OCI-compatible backend only
  after version/advisory pinning and annotation/mount-policy hardening; recent escape
  advisories prohibit a generic “Kata is safe” claim.
- [x] **P5-08** Treat gVisor as a lower-assurance compatibility backend, not a VM
  substitute for arbitrary hostile code.
- [ ] **P5-09** Add malicious-guest tests for resource exhaustion, output bombs,
  symlink/path abuse, device/mount access, metadata service access, DNS rebinding,
  secret theft, daemon-socket access, persistence, and cleanup.
- [ ] **P5-10** Obtain independent isolation review and run escape/containment tests
  on the exact production image, kernel, microcode, VMM, and policy versions.

**P5 exit gate:** the exact Linux/KVM worker configuration passes positive and
negative containment tests, emits attestation and cleanup receipts, and has an
independent review. Until then SOVA must not advertise production-grade isolation
for completely untrusted agents on the Windows host.

**P5 implementation evidence:** the
[controller/worker specification](../specifications/controller-worker-production-isolation-0.1.md)
and [P5 research record](../research/p5-production-isolation-research-2026-08-27.md)
and [P5 validation record](./p5-production-isolation-validation-2026-08-27.md)
cover the completed P5-02 and P5-04 through P5-08 controls. The local acceptance
suite also exercises the executable lifecycle side of P5-03 and all P5-09 classes,
including exact jailer arguments, Unix-socket API sequencing, pidfd watchdog
control, persistent exclusive identity slots, cleanup receipts, canonical mediator
flow-receipt capture, deterministic disjoint per-job job/mediator UID/GID ranges,
state-removal proof, and the deterministic per-job TAP/veth/nftables plan. The
exact SOVA mediator source now implements canonical policy verification, exact
hostname/port/DNS-set and selected-address enforcement, HTTP authority and TLS-SNI
binding, aggregate budgets, and durable controller-compatible receipts. Its locked
Rust dependency graph, eleven unit/interop tests, strict Clippy, licence ledger,
Dependabot lane, CI build, RustSec gate, Cargo SBOM, release checksum, Sigstore
input, and provenance-attestation path are included. A stripped static musl build
was byte-identical across isolated target directories, and its cross-language
denied-flow receipt passed in WSL, but no production Linux artifact or exact-host
execution receipt exists yet.
The check-only host preflight and eleven-case exact-host receipt contracts are now
implemented; preflight rejects reserved ranges already allocated in passwd/group,
but these controls create no live receipt. The deterministic local P5 receipt is
`sha256:966eab33cfe77257be63d67f8e515bc19b1bbb8d83d051b4fec7555bf2e2cfee`
and explicitly keeps production claims false. P5-01, P5-03, P5-09, and P5-10
remain open until the exact dedicated Linux/KVM worker
executes the live matrix and an independent reviewer signs the same measured
configuration; a WSL development probe is not that receipt.

## 9. P6 — blinded validation, Registry beta, and launch

- [ ] **P6-01** Freeze a predeclared evaluation protocol, budgets, providers,
  targets, baselines, scoring, exclusions, and failure rules before results exist.
- [ ] **P6-02** Run multiple provider/model families plus scripted and weak-model
  lanes; report the harness contribution separately from model capability.
- [ ] **P6-03** Run blinded owned and licensed targets spanning web, API, package,
  OCI, network, desktop, AI model/agent, and MCP/A2A classes.
- [x] **P6-04** Add benchmark adapters for Inspect AI/Inspect Evals cybersecurity
  tasks, AgentDojo, OASB, PentestGPT/XBOW-compatible cases, EthiBench, and other
  datasets that pass licence, provenance, safety, and ground-truth review.
- [ ] **P6-05** Compare against named scanner/tool and agent baselines under equal
  access and budgets; retain failures and negative results.
- [x] **P6-06** Measure workflow/surface coverage, confirmed findings, reproduction,
  precision/false positives, infrastructure failures, cost, latency, and containment.
- [ ] **P6-07** Deploy the hardened reference Registry beta with authentication,
  moderation, malware/secret screening, rate limits, backups, rollback, and incident
  response; contribution remains disclosed and operator-controlled.
- [ ] **P6-08** Rerun full tests, static checks, dependency/licence/secret audits,
  deterministic builds, isolated-wheel smoke, SBOM, checksums, provenance, and
  staged public-boundary review from the final release commit. Bind the exact
  outputs through a signed `deterministic-release-checks` receipt and recompute the
  candidate with `sova release dossier` using an out-of-band trust-policy pin.
- [ ] **P6-09** Obtain founder acceptance, independent technical validation,
  independent isolation review, legal/licence/public-disclosure review, and security
  sign-off as separate named gates.
- [ ] **P6-10** Reconcile README, docs, demos, website, paper, Registry, and release
  notes to the claims register; prohibit universal, exhaustive, expert-equivalence,
  or perfect-isolation claims not established by evidence.
- [ ] **P6-11** Tag and publish only after every mandatory P6 receipt is linked from
  the release record. Publishing/pushing is a separate explicit action.

**P6 exit gate:** every mandatory receipt exists for the exact release commit and
artifact digests; blinded results and limitations are public; all review gates are
green; rollback and incident procedures are tested.

**P6 implementation evidence:** the
[P6 specification](../specifications/blinded-validation-registry-and-launch-0.1.md)
and [research record](../research/p6-blinded-validation-and-launch-research-2026-08-27.md)
and [P6 validation record](./p6-validation-and-launch-readiness-2026-08-27.md)
cover the frozen-protocol machinery, deterministic non-executing complete-matrix
work orders, strict observation-ledger evaluation, five provenance/loss-reporting
adapter boundaries, complete metric ledger, ten-control Registry readiness policy, local
backup/restore rehearsal, and five-review release ledger. P6-04 and P6-06 are
implemented. Signed role-scoped receipt ingestion and the exact-candidate launch
dossier are also implemented, together with distinct-role/independent-review trust
separation and deterministic bundle assembly; they close the local
aggregation/trust-verification gap but create no external receipt. Repository README, release-note,
claims-register, and founder-matrix
language has been reconciled. The
[P6 public-claims reconciliation packet](./p6-public-claims-reconciliation-2026-08-31.md)
now supplies exact replacement copy, and the release candidate/dossier binds a
canonical seven-surface claims snapshot so drift or an unreviewed surface blocks
publication. P6-10 remains open because the separately hosted TRUSCOR website has
not been changed or approved and no release-controlled paper or public Registry
surface exists in this checkout. P6-01 through P6-03, P6-05, and
P6-07 through P6-11 remain open where
they require the exact real preregistration, live providers/targets/baselines,
production operator receipts, final-commit artifacts, independent/legal/security
review, public results, or an explicitly authorized publication action.
The recomputed dossier exposes those remaining states as sorted machine-readable
hold reasons mapped to evaluation, Registry, review, and external-gate summaries.
Current-tree validation passes `2,646` tests with `30` declared capability-gated
skips and `95.11%` combined statement/branch coverage; all `149` CLI handlers,
strict types, formatting, lint, dependency audit, acceptance, package-resource,
reproducible-build, isolated-wheel, checksum, repository-policy, and public-boundary
checks pass. The deterministic P6 acceptance receipt is
`sha256:88f2b6c3aa1186cff26da44243a3f2727f6d111924d92d85dfb08262ceba9e70`
and correctly keeps the P6 exit and publication gates false. These local receipts
do not satisfy the unchecked real-provider, blinded-target, production Registry,
independent-review, exact-release-provenance, or publication items above.

## 10. Change-control rule

New work must reference one or more checklist IDs. An item may be checked only with
a repository evidence link or an external receipt identifier. If scope changes, edit
this file first and preserve the reason in Git history. “Code exists,” “tests pass,”
and “launch claim is cleared” remain separate states.
