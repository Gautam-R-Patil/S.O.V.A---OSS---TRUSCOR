<!-- status: decision -->

# ADR-0019: Evidence-linked, uncertainty-preserving counterfactual forensics

- **Status:** Accepted
- **Date:** 2026-08-03
- **Owner:** Gautam R. Patil
- **Scope:** Topic 15 forensics and fault attribution

## Decision

SOVA reconstructs a causal partial order before it attempts attribution. Every
material reconstruction statement cites an event identity and, when present,
its evidence digest. Missing parents, redactions, dropped events, untrusted
clocks, and cross-clock ambiguity remain visible instead of being guessed away.

Attribution is a separate paired-intervention operation. A trial changes one
declared causal layer, requires a reproduced baseline and complete evidence,
links original and counterfactual traces, and records context equivalence.
Multi-layer changes are confounded. Impossible interventions and incomplete
sensors produce explicit abstentions. A layer is supported only after at least
three eligible trials and a Wilson 95% lower bound above 0.5; this is a
conservative engineering rule, not proof of causation.

## Alternatives rejected

- One LLM-written root-cause narrative: hides evidence gaps and confounding.
- Wall-clock sorting alone: invalid across unsynchronized clock domains.
- One successful rerun as causal proof: ignores stochasticity and common causes.
- An authoritative blame label: exceeds technical evidence and SOVA's role.

## Consequences

Reconstruction remains useful when attribution abstains. The public synthetic
benchmark measures implementation behavior and compares a transparent passive
frequency baseline; it does not establish real-system accuracy or novelty.
Paper Gate 15-A and stronger claims remain open until predeclared real and
ground-truth studies are completed in the later research phase.
