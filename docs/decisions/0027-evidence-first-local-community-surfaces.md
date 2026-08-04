<!-- status: decision -->

# ADR-0027: Evidence-first local community surfaces

- **Status:** Accepted
- **Date:** 2026-08-04
- **Owner:** Gautam R. Patil
- **Scope:** Topic 23 probe, Arena, leaderboard, CTF, and replay media

## Decision

`sova probe` verifies a nonce-, scope-, freshness-, key-, and revocation-bound
DSSE response and performs only limited signed-response conformance in the
reference implementation. Third-party self-assertions and SOVA observations
are separate evidence classes. An included key establishes integrity only;
identity requires an operator-pinned key. Unsupported and inconclusive remain
valid results. MCP probe use is gated even when the local reference path makes
no network call.

The first Arena is local, deterministic, scripted, and fully traced. Every
attempt creates a signed `.sova-trace` embedded in a `.sova` capsule. Standard
and custom profiles have different comparability classes. No execution or
submission creates telemetry or uploads.

The leaderboard is generated as static JSON and HTML. It accepts only one
standard-profile digest per snapshot, technical components rather than people
or victims, a verified capsule containing the submitted signed trace, explicit
component versions, reproducible methodology, Wilson uncertainty, and
duplicate-evidence checks.

The CTF catalog copies no third-party assets and runs no setup commands; it
records project URL, licence, setup mode, explanation, verified artifact, and a
reviewed registry contribution path. Replay clips use bounded metadata-only
captions, capture-time redaction, an artifact/verification sidecar, and explicit
classification and disclosure gates.

## Alternatives rejected

- “Instant trust” from one probe: conformance and assertions cannot establish broad trust.
- Hosted mandatory Arena: violates local-first operation and creates corpus/telemetry risk.
- Organization or victim rankings: incentivize unsafe and ethically misleading comparisons.
- Accept screenshots without artifacts: public ranks would not be independently falsifiable.
- Auto-clone and auto-run CTF targets: imports third-party code and licences without review.

## Consequences

The present Arena validates the evidence workflow, not real-agent superiority.
Public comparisons require independent artifact review, larger samples, and
controlled real-runtime experiments before any comparative claim is allowed.
