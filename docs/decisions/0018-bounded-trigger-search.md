<!-- status: decision -->

# ADR-0018: Bounded, measurable trigger search

- **Status:** Accepted
- **Date:** 2026-08-03
- **Owner:** Gautam R. Patil
- **Scope:** Topic 14 trigger discovery

## Decision

Trigger discovery uses a typed finite search space, explicit condition
dimensions, hard budgets, deterministic seeds, observable near-miss scores,
and separately measurable signature, random, grid, coverage-guided, human, and
adaptive evolutionary strategies. A successful condition is rechecked and
minimized into portable intent without executor mechanics.

The public adaptive method is deliberately an established generic baseline.
It carries no novelty claim. Local experience stores only digests and effort
metadata, not raw prompts, tokens, or a hosted/private corpus.

Phantom Fuzzer operation is limited to a target whose control was independently
verified. Session material is kept in an erasable in-memory buffer, attempts
are bounded, and confirmation returns through a browser observation. Third-party
targets fail closed.

## Alternatives rejected

- One strategy reported as a universal search score: prevents baseline audits.
- An unbounded agent loop: makes cost, safety, and falsification undefined.
- Persist browser session tokens for convenience: creates credential exposure.
- Publish an unresearched novelty claim: violates the project evidence policy.

## Consequences

A miss means only “not found under this declared space, oracle, and budget.”
Before any genuinely novel search mechanism or tuning is disclosed, the
research and IP gates must be reopened. Paper and patent work remains on hold
until the user-approved post-build phase.
