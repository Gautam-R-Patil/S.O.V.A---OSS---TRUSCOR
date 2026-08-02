<!-- status: accepted -->

# ADR 0011: Bind authority, containment, effect budgets, and evidence per action

- **Date:** 2026-08-02
- **Owner:** Gautam R. Patil
- **Scope:** Topic 07 executable safety boundary
- **Status:** Accepted, experimental implementation

## Decision

SOVA uses an Authority-Containment-Evidence (ACE) contract for every effectful
action. An executable intent is allowed only when all of these independently
pass:

1. a non-agent issuer grants fresh authority to a named subject;
2. exact target, action, path, tool, identity, and domain scope permits it;
3. a current proof establishes control of the exact target;
4. the requested consequence class does not exceed the authority ceiling;
5. a multi-dimensional monotone budget can cover the action;
6. the selected containment descriptor matches the digest bound into authority;
7. a fresh, single-use, out-of-band human approval exists when required; and
8. the action declares the evidence that must be captured afterward.

Offensive operations and destructive effects require the destructive approval
level. Agents and services cannot approve their own operations. A URL is never
proof of control. Caller-supplied `{"decision":"allowed"}` assertions remain
valid only for the deterministic `ScriptedExecutor` and genuinely read-only
executor paths; effectful executors require a live authorization session.

Every decision, including denial reasons and budget state, is a trace event.
The trace manifest carries only a compact scope digest and decision authority.

## Why

OAuth rich authorization, proof-of-possession, zero-trust per-request decisions,
object capabilities, and approval gates provide important prior art. SOVA's
problem is narrower and operational: an AI-generated action must not detach
authority from containment, consequence budgets, or its evidence obligation as
it crosses executor adapters. A single Boolean loses those bindings.

## Alternatives rejected

- A one-time session checkbox: too broad and replayable.
- Agent-generated approval: the actor cannot be its own human authority.
- URL possession: redirects, hosting, and public reachability do not prove
  control.
- Executor-owned policy: adapters are replaceable and must not become SOVA's
  policy authority.
- A scalar “risk score”: it cannot represent independent file, process,
  network, time, token, mutation, or transaction ceilings.

## Consequences and limitations

- High-consequence execution needs more operator interaction.
- The reference HMAC approval channel proves possession of its channel key; it
  does not prove that a human understood the prompt. Production channels should
  use hardware-backed or separately authenticated approval where appropriate.
- Captured DNS, well-known, manifest, and legal-control evidence can be false if
  the verifier or trusted host is compromised.
- This architecture is a research candidate, not a novelty or patentability
  claim. The private gate compares it with authorization and capability prior
  art before any disclosure decision.
