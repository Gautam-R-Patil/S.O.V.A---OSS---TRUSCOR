<!-- status: decision -->

# ADR-0016: Three non-interchangeable replay modes

- **Status:** Accepted
- **Date:** 2026-08-03
- **Owner:** Gautam R. Patil
- **Scope:** Topic 12 replay and reproduction

## Decision

SOVA names and implements three separate operations:

1. **Trace playback** is deterministic, inert inspection of recorded bytes.
2. **Controlled re-execution** is a fresh authorized run linked to an immutable
   source trace with explicit condition drift.
3. **Semantic reproduction** is a repeated-trial study of declared observable
   outcomes, with numerator, denominator, inconclusive trials, condition labels,
   and uncertainty.

Deterministic oracles take precedence over an optional model judge. A model
judge is isolated, calibrated against labeled cases, and never presented as
deterministic execution evidence. SOVA does not claim to reproduce hidden
chain-of-thought or bit-for-bit hosted inference.

## Alternatives rejected

- Call every operation replay: hides whether an action was executed.
- Compare exact tokens: confuses stochastic variation with security outcome.
- Let a model judge decide every trial: creates an unmeasured circular oracle.
- Replace the source trace: destroys the evidence needed to compare conditions.

## Consequences

Outputs carry a mode identifier. Controlled re-execution requires a new
destination and fresh authority. Semantic claims are limited to declared
conditions and observed trials. A valid but incomplete trace remains partial,
not invalid and not verified as complete.
