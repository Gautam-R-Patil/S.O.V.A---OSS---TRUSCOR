<!-- status: decision -->

# ADR-0014: Evidence-firewalled public runtime

- **Status:** Accepted
- **Date:** 2026-08-02
- **Owner:** Gautam R. Patil
- **Scope:** Topic 10 orchestration, judging, sessions, and reliability

## Decision

The public SOVA Runtime uses typed phases and isolated roles behind a
provider-neutral model router. The Attacker and Judge do not share a factual
context. Target traces pass through an integrity check and a one-way allowlisted
evidence projection before judging. Deterministic oracles and policy rules take
precedence; model interpretations must cite admitted evidence; unsupported or
disagreeing results become inconclusive and may require human review.

Standard and custom profiles are cryptographically distinguishable. Local
attempt experience stores only privacy-minimized digests and effort. Authorized
identities use scoped opaque leases. Executor fallback depends on independent
post-action verification and never silently retries an unverified
non-idempotent effect.

## Alternatives rejected

- Give the judge the full attack transcript: preserves an avoidable injection
  channel and unsupported attacker assertions.
- Let executor success flags decide findings: makes adapters self-attesting.
- Majority vote away disagreement: agreement does not establish ground truth.
- Share raw cookies or credentials between swarm agents: violates least
  privilege and durable-evidence privacy.
- Connect public experience to a hidden corpus: compromises OSS completeness
  and reproducibility.

## Consequences

Some semantic evidence may be omitted and produce more inconclusive outcomes.
An evidence-ID citation proves only linkage; it does not prove semantic support,
sensor truth, or causality. Multi-role orchestration, retries, and credential
leases are established engineering patterns. The typed one-way evidence
firewall remains an experimental paper/IP candidate until comparative,
adversarial, ablation, calibration, and independent validation evidence exists.
