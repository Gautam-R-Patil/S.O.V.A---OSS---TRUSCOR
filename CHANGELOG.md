# Changelog

All notable public changes to SOVA OSS are recorded here.

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and will use [Semantic Versioning](https://semver.org/spec/v2.0.0.html) for the
CLI package. Artifact specifications, methodologies, adapters, and taxonomies
have independent version ledgers.

## [Unreleased]

### Security

- Upgraded the runtime dependency to `cryptography 50.x` after the fixed stable
  release became available, retired the temporary PKCS#7 advisory exception,
  and restored a strict no-ignored-advisory dependency audit.

### Added

- An evidence-native replay application with play/pause, speed controls,
  sensor-family lanes, search, causal/correlation navigation, synchronized
  comparison, hostile-content-safe rendering, integrity-validated live trace
  prefixes, and a bounded loopback SSE service.
- A strict three-phase blinded causal-validation protocol with separate
  label-free tasks and committed answer keys, DSSE reviewer-key pinning,
  stochastic CPU-only fixtures, abstention-aware metrics and confidence
  intervals, explicit external-review limits, and four pinned JSON Schemas.
- A loopback-only self-hosted community reference service with secret-safe token
  initialization, bounded staged uploads, pinned evidence signers, asynchronous
  verification, restart recovery, atomic content-addressed promotion, a
  DSSE-signed live index, service-key and sequence verification, SSE updates,
  standard-profile-only leaderboard rows, duplicate-evidence defenses, and no
  submitted-content execution. The standard-library transport is explicitly
  not presented as an Internet-production server.
- A durable foreground `sova monitor serve` scheduler with exact non-executable
  job documents, workspace-bound snapshot paths, kernel-backed overlap
  exclusion, interrupted-run recovery, cooperative cancellation, bounded
  retention for reports and history, and signed drift-result traces.
- An executor-backed `sova arena swarm-web` lane in which bounded scripted or
  provider-capable roles take sequential turns over one exclusively leased,
  target-bound browser profile; select only operator-authored candidate grants;
  share redacted observations rather than credentials; receive fresh human
  approval for browser subruns; and emit signed coordinator and participant
  traces, exact live-channel parity, and an offline-verifiable aggregate
  capsule. An opt-in installed-Chrome two-role fixture test passes across MCP
  restarts.
- A live-attested Docker Desktop OCI executor for digest-pinned cached images,
  with no network, host mounts, Docker socket, or image pull; read-only rootfs,
  non-root zero-capability execution, no-new-privileges, CPU/memory/PID/output/
  runtime bounds, forced cleanup, a `sova safety attest-docker` command, and an
  opt-in real-runtime conformance test. It is explicitly a container sharing
  the Docker VM kernel, not a per-workload microVM.
- Target-digest-bound opaque browser profiles with atomic cross-process leases,
  bounded stale-lock recovery, graceful MCP/Chromium shutdown, a manual headful
  login/CAPTCHA handoff, opt-in reuse across browser/agent/Arena campaigns, and
  a signed installed-Chrome two-process persistence proof that excludes profile
  handles, paths, and cookie material from evidence.
- An inert `sova target browser-kit` authoring workflow that normalizes one
  controlled origin, generates a strict target/campaign/assessment-plan bundle,
  explains external proof-of-control and human approval, and performs no
  network access or authorization inference.
- Digest-and-size screenshot sensor evidence in owned and bounded browser
  campaigns; raw screenshot pixels remain outside durable SOVA traces.
- Offline `sova probe issue` and `sova probe verify` round trips with strict
  secret-free issuance requests, ephemeral Ed25519 signatures, nonce/scope/TTL
  binding, and explicit included-key-integrity-only trust semantics.
- A direct `sova trace command` front door with shell-free exact executable
  resolution, credential-shaped argument refusal, canonical digest-bound TTY
  review, restricted environment inheritance, signed evidence, and an explicit
  ordinary-host-authority limitation.
- Cross-platform extension launch hardening that rejects inline code flags for
  version-suffixed Python, PyPy, and Node executables plus common POSIX shells.
- Fully applicable environment, target, code, dependency, registry, and model
  fingerprint states plus pinned methodology/taxonomy in the bundled sleeper
  demo, allowing its installed-wheel output to enter the strict case workspace
  without weakening verification.
- A provider-assisted `sova rehearse agent-run` path with bounded sanitized
  workspace disclosure, exact pre-call and pre-execution approvals, a tool-free
  strict-JSON planner, fail-closed budgets, signed planning/execution traces,
  and a portable evidence capsule while preserving substitute-only effects.
- Authorization-gated local-software detonation that executes finite
  process-only capsules against two credential-stripped disposable workspace
  copies, observes bounded process/output/file-delta evidence, signs and
  compares primary/reproduction traces, and packages a verified capsule without
  claiming host isolation or legal-authority verification.
- An offline `sova case build` workflow that verifies exact capsule-to-trace
  binding and produces forensic reconstruction, inert timeline, payload-free
  replay media, evidence/SARIF reports, behavior snapshot, selective disclosure,
  and a contribution preview whose human gates remain closed.
- Authorization-gated dynamic `sova check` execution for controlled browser
  targets, with non-offensive campaign enforcement, signed evidence,
  controlled reproduction, and explicit not-observed/inconclusive semantics.
- Repeated real-browser counterfactual pairs that remove one declared message,
  verify signed baseline/intervention/reproduction evidence, reject fingerprint
  drift, and package uncertainty-aware attribution in a `.sova` capsule.
- An authorization-gated `sova detonate owned-web-fixture` path that drives a
  real loopback website through pinned Playwright MCP and Chrome, records signed
  primary/reproduction traces, compares observable outcomes, and packages a
  `.sova` evidence capsule.
- An external browser-target workflow with short-lived HTTPS well-known control
  challenges, certificate and exact-origin binding, redirect refusal,
  pre-dispatch URL checks, and final observed-origin drift detection.
- Closed exact-batch terminal authorization that lets a person review a bounded
  run once while preserving distinct signed, scope-bound, one-use tokens for
  every individual action.
- A real-browser `sova hunt` campaign that evaluates an exact reviewed
  candidate set, records snapshot/console/network sensors, detects observable
  near misses, performs fresh controlled reproduction, and emits signed traces
  plus an offline-verifiable discovery capsule.
- A provider-assisted `sova hunt agent-browser` path with isolated recon,
  explorer, strategist, attacker, and advisory judge roles; strict JSON and
  model budgets; redacted role records; explicit provider-call permission; and
  unchanged proof-of-control plus exact browser-action approval boundaries.
- A provider-capable `sova arena agent-run` path with separate challenger,
  defender, and advisory-judge contexts; bounded multi-round message exchange;
  capture-time-redacted prompt/model/inter-agent/environment/oracle sensors;
  deterministic scoring; signed per-match traces and capsules; and mandatory
  custom non-comparable profiles without participant tools.
- Buildable `sova-oss` Python package and typed, tested `sova` command-line interface.
- A fail-visible dependency-advisory register and source guard for the current
  `cryptography` PKCS#7 advisory, with an automatic removal condition when a
  compatible fixed release becomes available.
- Reproducible `uv` development lockfile and cross-platform CI.
- Formatting, linting, strict typing, tests, coverage, security, provenance,
  compatibility, performance-budget, and failure-injection controls.
- Repository governance, documentation states, glossary generation, research
  artifact indexing, methodology versioning, issue routing, and release rules.
- Experimental `sova.domain` contract primitives for strict versions,
  SHA-256 fingerprints, UUIDv7 logical identities, and explicit context.
- Five-axis non-destructive finding lifecycle and stable failure codes.
- Versioned twelve-class `sova.attack` taxonomy with standard/custom profile
  rules and version-pinned OWASP, MITRE ATLAS, CWE, and CAPEC mappings.
- Six-dimensional frozen-denominator observed coverage, exploration budgets,
  stopping rules, and source-example reconciliation.
- Experimental `.sova` capsule/scenario schemas, deterministic packaging,
  content-addressed attachments, authoring, inspection, validation, linting,
  canonical hashing, and explicit chained migrations.
- Streaming `.sova-trace` capture with four profiles, chunking, recovery,
  indexed inspection, inert playback, capture-time redaction, optional
  DSSE-compatible Ed25519 signatures, and offline verification.
- Pinned OpenTelemetry/OpenInference import/export mappings with explicit
  fidelity-loss reports.
- Privacy-minimizing OpenInference `0.1.30` import with explicit content
  opt-in, sensitive-field accounting, bounded hostile-input handling, and a
  corrected span-kind mapping that never emits the nonexistent `MEMORY` kind.
- Deterministic scripted-model and scripted-executor lanes plus a restricted
  local host-process executor with exact capability negotiation.
- Observable deterministic oracles, integrity-checked declared-outcome
  comparison, and a complete safe no-Atlas vertical-slice fixture.
- Explicit observer producer identity for reference oracle conclusions so
  executor output and SOVA-owned judging remain distinguishable in evidence.
- Optional DSSE/Ed25519 and required-key verification in the independently
  implemented offline verifier, without importing the SOVA package.
- A dependency-free Node.js verifier and cross-language agreement tests for
  package, canonical manifest, event chain, redaction, and DSSE evidence.
- Strict opaque `sova-secret:` references, just-in-time child-environment
  resolution, supervised process lifecycle, explicit unsupported resource
  limits, and provider-crash normalization.
- An experimental authority-containment-evidence kernel with exact per-action
  scope, expiring single-use authority, proof-of-control checks, consequence
  classes, monotone effect budgets, containment binding, and single-use
  out-of-band human approvals.
- Containment capability descriptors and admission decisions for the
  no-native-code synthetic world, restricted local developer execution, OCI,
  gVisor, Firecracker, and Kata candidates without mislabelling unvalidated
  host or container execution as a security sandbox.
- A seedable event-sourced synthetic detonation world with inert run-unique
  canaries, sink-only egress, substitute services, explicit reset evidence, a
  normalized sensor mesh, claim-conditioned evidence closure, and nine
  deterministic ground-truth target families.
- Deterministic file, process, network, canary, tool, authorization, browser,
  database, inter-agent, state, trigger, and composite oracles.
- A safe `sova demo sleeper` path that emits an offline-verifiable
  `.sova-trace`, `.sova` capsule, and human-readable summary without a model,
  provider key, network, container runtime, or MELRA installation.
- A pinned MELRA adapter with strict internal task-state normalization,
  status/cancel handling, and a permanent no-MELRA fallback path.
- Air-gapped `sova map` collection, provenance-separated capability closures,
  schema-validated map reports, and immutable tool-definition drift snapshots.
- Provider-neutral role orchestration, standard/custom run profiles, an
  evidence-firewalled judging path, model fallback budgets, local minimized
  experience records, opaque session leases, and verified executor fallback.
- A complete `sova check`/`sova demo` no-MELRA path with named bounded
  baselines, two-dimensional trigger search, signed discovery and reproduction
  traces, independent verification, honest exit states, and performance gates.
- Three non-interchangeable replay modes, four-state offline verification,
  fresh linked re-execution, uncertainty-aware semantic studies, calibrated
  optional judging, and an inert side-by-side timeline viewer.
- A bounded MCP 2025-11-25 stdio client, Microsoft Playwright MCP and
  restricted Windows-MCP mappings, pinned launch recipes, capability routing,
  conservative verification/fallback, and cross-adapter conformance tests.
- A typed 13-dimension trigger-search model with measurable signature, random,
  grid, coverage, human, and adaptive evolutionary baselines; sequence
  minimization; digest-only local experience; and an owned-target Phantom
  Fuzzer contract with secret-free attempt and browser-confirmation trace
  events.
- Evidence-linked forensic reconstruction with causal partial-ordering,
  uncertain-order and missing-sensor markers, paired-intervention attribution,
  explicit confounding/abstention, Wilson intervals, and a five-case
  deterministic calibration fixture.
- Watermarked self-assessment evidence bundles, SARIF 2.1.0 projection/import,
  four-state execution-bounded scanner adjudication, local-only disclosure
  preparation, bounded local maintainer-contact discovery, approved default
  disclosure clocks, and technical, executive, reproduction, and methodology
  views.
- Typed metadata-only composition graphs, pairwise/t-wise/risk/trigger-aware
  bounded search, fresh-observation minimization, element-removal attribution,
  portable `.sova` composition fragments, and a ground-truth composition-only
  failure fixture.
- Credential-stripped substitute-only rehearsal with pluggable preparation,
  separate user/attacker evidence, signed success/failure traces, clean diffs,
  material-step captures, capability reach, and digest-bound selective export.
- Shell-free allowlisted process tracing, multi-axis behavior/environment/
  methodology drift, local sentinel history, deterministic CI/SARIF policy, a
  reusable GitHub workflow, and protected-baseline SOVA self-checks.
- An offline repository-of-files registry with content-addressed objects,
  DSSE-compatible signed indexes, explicit key-pinning trust, pull-only atomic
  mirror caching, verification tiers, consent-firewalled contribution staging,
  and provenance-preserving external adapters.
- An account-free local MCP `2025-11-25` stdio server with a pinned tool
  manifest, explicit side-effect declarations, separate-terminal exact
  invocation approval, expiry, single-use replay protection, and signed
  authorization evidence.
- A fail-closed extension protocol, metadata-only PyPA discovery, shell-free
  subprocess conformance runner, provider-neutral OpenAI/Anthropic/OpenRouter/
  Ollama adapters with injected no-network tests, eight target declarations,
  and an inert provenance-preserving Inspect AI bridge.
- A human-operated extension workflow with strict manifests, absolute paths,
  executable and script digest pins, post-approval drift checks, protocol-bound
  responses, capture-time redaction, signed traces, and explicit non-sandbox
  limitations, plus an executable safe example.
- Signed nonce-bound probe evidence, a deterministic trace-per-attempt local
  Arena, signature-pinned static leaderboard, inert CTF catalog, and bounded
  redaction-first replay clip renderer with strict public CLI documents.
- Account-free `sova init`, non-secret `sova doctor`, identity-bound managed
  data deletion, a first-five-minutes path, user-path guides, governance, and
  maintainer documentation.
- Deterministic CycloneDX 1.6 SBOM generation, exact release checksums, hostile
  bundle verification, and a reproducible neutral conformance ZIP containing
  canonical schema, event, extension, and manifest vectors.
- Secret-free authorized-target manifests and inert plans plus signed,
  deterministic website and software fixtures that prove target planning,
  observable execution, trace capture, capsule packaging, controlled
  reproduction, comparison, and offline verification without contacting a
  live target.
- A machine-audited 83-command CLI surface whose registered handlers must all
  execute in mandatory offline CI.

### Fixed

- Standardized test invocation on `python -m pytest`, avoiding a Windows
  console-entry-point import-path failure for the public `scripts` package.
- Current-to-current `.sova` migration now performs an exact, no-overwrite
  byte-preserving copy when the destination differs from the source.
- Local MCP control-key creation now forces binary mode on Windows so random
  newline bytes cannot be translated to CRLF and alter the generated key.
- Windows foreground/background cancellation now detects failed or timed-out
  `taskkill /T` attempts, falls back immediately to the owned root process, and
  retries transient temporary-I/O cleanup. Arbitrary descendant-tree
  containment still requires a stronger operating-system backend.

### Security

- Full-SHA pinning for GitHub Actions.
- Dedicated public-boundary, secret, dependency, and CodeQL checks.
- Synthetic-fixture provenance and raw-trace location enforcement.
- Malformed archive, parser differential, corruption, truncation, reordering,
  substitution, signature-confusion, redaction, and hostile-extension tests.
- Secret values and provider exception messages are excluded from durable
  capsules and normal trace outcomes by tested boundaries.
- Keyed redaction commitments reject missing or sub-32-byte key material before
  capture; operators must still supply genuinely high-entropy keys.
- Encrypted redaction can use authenticated power-of-two length buckets;
  decryption rejects padding metadata that disagrees with the authenticated
  associated data. Bucket, presence, path, and surrounding-structure leakage
  remain explicit limitations.
- The threat model explicitly records that standalone offline verification
  cannot detect byte-identical replay or valid-signer equivocation without
  trusted external freshness or transparency state.
- External MCP transport success is never treated as action success when the
  provider's embedded task is blocked, partial, waiting, cancelled, failed,
  nonterminal, unknown, or substituted.
- Windows-MCP telemetry is disabled by the pinned recipe and dangerous host
  tools are excluded from the SOVA mapping by default.
- MCP stdio reads, unrelated-response deferral, and request deadlines are
  bounded before allocation or retry; backend environment additions fail
  closed unless allowlisted.
- Phantom payload/evidence sizes are bounded, and ephemeral token zeroization
  runs on success, validation failure, or harness failure.

## [0.1.0a0] - Unreleased

Pre-alpha engineering-foundation version. It has not been published to PyPI
and does not implement the security capability commands described in the
project vision.

[Unreleased]: https://github.com/Gautam-R-Patil/S.O.V.A---OSS---TRUSCOR/compare/v0.1.0a0...HEAD
[0.1.0a0]: https://github.com/Gautam-R-Patil/S.O.V.A---OSS---TRUSCOR/releases/tag/v0.1.0a0
