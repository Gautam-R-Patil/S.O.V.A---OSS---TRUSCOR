<!-- status: decision -->

# ADR-0013: Provenance-separated capability mapping

- **Status:** Accepted
- **Date:** 2026-08-02
- **Owner:** Gautam R. Patil
- **Scope:** Topic 09 public mapping architecture

## Decision

SOVA will represent capability reach as a typed graph whose edges retain
declared, observed, inferred, or refuted evidence class, redacted provenance,
conditions, and runtime witnesses. Reports expose declared, witness-linked,
possible, and conflict closures separately. No mixed closure is called “actual
reach.” The machine artifact is `sova.map`, not `.sova` or `.sova-trace`.

Static local discovery is air-gapped and secret-value-blind. Active/runtime
discovery requires explicit authorization. Tool definitions are immutable
canonical snapshots whose changes are classified conservatively.

## Alternatives rejected

- One graph with unlabeled edges: hides uncertainty and contradicting evidence.
- Treat runtime observation as universal permission: an observation is bounded
  by conditions and collection scope.
- Package the map as `.sova`: conflates a derived report with the shareable
  behavior capsule.
- Read environment values for “accuracy”: creates an unnecessary secret leak.

## Consequences

The result is inspectable and supports later denominators, but it is larger than
a flat inventory. Collectors must retain provenance and partial-result state.
Capability graphs, transitive access, and hashes are established prior art;
only measured properties of the separated closures remain a research question.
