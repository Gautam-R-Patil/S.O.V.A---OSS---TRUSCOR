# Changelog

All notable public changes to SOVA OSS are recorded here.

This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and will use [Semantic Versioning](https://semver.org/spec/v2.0.0.html) for the
CLI package. Artifact specifications, methodologies, adapters, and taxonomies
have independent version ledgers.

## [Unreleased]

### Added

- Buildable `sova-oss` Python package and dependency-free `sova` placeholder CLI.
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

### Fixed

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

## [0.1.0a0] - Unreleased

Pre-alpha engineering-foundation version. It has not been published to PyPI
and does not implement the security capability commands described in the
project vision.

[Unreleased]: https://github.com/Gautam-R-Patil/S.O.V.A---OSS---TRUSCOR/compare/v0.1.0a0...HEAD
[0.1.0a0]: https://github.com/Gautam-R-Patil/S.O.V.A---OSS---TRUSCOR/releases/tag/v0.1.0a0
