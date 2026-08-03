<!-- status: decision -->

# ADR-0021: Bounded composition-only failure search and intervention evidence

- **Status:** Accepted
- **Date:** 2026-08-03
- **Owner:** Gautam R. Patil
- **Scope:** Topic 17 emergent-chain testing

## Decision

SOVA represents components and metadata-only interaction edges in a typed graph.
Credential values are forbidden. Pairwise, bounded t-wise, risk-guided path,
and trigger-aware sequence strategies produce deterministic, content-addressed
candidates under candidate, attempt, duration, path-length, and combination
budgets.

A chain is confirmed only by a fresh evidence-complete observation. Reduction
removes an edge or node and re-observes the outcome; node removal also removes
all incident edges. Element attribution reports whether the tested effect was
prevented, persisted, or remained inconclusive. “Composition-only” additionally
requires an explicit isolated negative outcome for every participating node.
The portable `.sova` fragment contains component identities, interactions, and
order, but no executor-specific mechanics or credential values.

## Alternatives rejected

- Exhaustive unbounded enumeration: unsafe and combinatorially intractable.
- Infer composition-only from one complex failure: does not test constituents.
- Store shared credentials in the graph: creates a portable secret leak.
- Treat element-removal evidence as universal innocence or causation: overclaim.

## Consequences

The shipped deterministic fixture establishes a bounded engineering result: an
ordered memory-to-agent-to-tool chain fails while its constituents do not. It
does not show that risk guidance outperforms random or pairwise search in the
field. Research Gate 17-A and Paper Gate 17-B remain open for the post-build
benchmark and prior-art phase.
