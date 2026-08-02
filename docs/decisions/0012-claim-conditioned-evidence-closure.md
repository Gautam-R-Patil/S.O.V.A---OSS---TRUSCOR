<!-- status: accepted -->

# ADR 0012: Judge claims against explicit sensor-coverage obligations

- **Date:** 2026-08-02
- **Owner:** Gautam R. Patil
- **Scope:** Topic 08 synthetic detonation and deterministic judging
- **Status:** Accepted, experimental implementation

## Decision

SOVA does not treat “a trace exists” as sufficient evidence. Every material
claim may declare a required sensor set and alternative sufficient sets. The
sensor mesh reports one of:

- `sufficient`: every selected sensor is healthy and observed;
- `insufficient`: required coverage is missing or degraded; or
- `conflict`: observations make contradictory verdicts for the same claim.

Coverage is claim-conditioned. Missing internal state cannot silently become a
negative finding, and an LLM judge cannot override absent deterministic
evidence. Model judgment is reserved for questions deterministic observations
cannot answer and must remain visibly probabilistic.

The reference synthetic world couples this rule with event-sourced fake state,
run-unique inert canaries, sink-only egress, deterministic oracles, and
ground-truth targets whose trigger and responsible layer are known.

## Why

AgentDojo, ToolSandbox, OSWorld, tau-bench, and related systems demonstrate the
value of stateful environments and execution-based evaluation. ToolEmu shows
the scale benefits and limits of model-emulated sandboxes. SOVA additionally
needs portable forensic evidence that states what could and could not be
observed for each claim.

## Alternatives rejected

- Prompt/output-only judging: misses effects and cannot distinguish absence
  from lack of observation.
- Treating degraded sensors as healthy: produces false confidence.
- One global coverage percentage: different claims require different sensors.
- Real services in the default laboratory: creates third-party and cleanup
  risk without being necessary for deterministic ground truth.

## Consequences and limitations

- Strong claims require more sensors and storage.
- A dishonest or compromised sensor may emit internally consistent false data.
- Synthetic worlds cannot expose every real kernel, browser, timing, or
  anti-sandbox behavior.
- Evidence closure is a falsifiable research candidate, not an established
  claim of superior attribution. The paper gate remains on hold until measured
  gains survive stronger baselines and independent replication.
