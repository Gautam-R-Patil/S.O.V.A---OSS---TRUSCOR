<!-- status: decision -->

# ADR-0015: Bounded check and no-MELRA proof

- **Status:** Accepted
- **Date:** 2026-08-02
- **Owner:** Gautam R. Patil
- **Scope:** Topic 11 user workflow

## Decision

`sova demo sleeper` will be the zero-configuration acceptance proof for mapping,
bounded two-dimensional search, SOVA-owned sensors/oracles, signed evidence,
capsule packaging, fresh controlled reproduction, comparison, and independent
offline verification. It uses only synthetic owned state and performs no native
target or real-network action.

`sova check` defaults to the standard profile and reports confirmed behavior,
no confirmed result, inconclusive, or invalid execution through distinct exit
codes. Until a safe adapter exists, arbitrary local directories receive a
static map and signed blocked/inconclusive trace rather than host execution.

## Alternatives rejected

- Return `safe` after a short run: absence of detection is not absence of a
  dormant behavior.
- Exercise arbitrary components to improve the demo: breaks the authorization
  and containment boundary.
- Depend on MELRA/Atlas: makes the first proof unavailable and transfers trust
  to an optional executor.
- Delete failed output: loses flakiness and diagnostic evidence.

## Consequences

The demo is a measurement-system fixture, not a real-agent benchmark. Its three
baselines are narrow and must not support a superiority headline. External
targets and trigger-hunting research remain later work. SOVA self-assessment is
never TRUSCOR attestation.
