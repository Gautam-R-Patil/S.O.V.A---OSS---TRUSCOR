<!-- status: implemented -->

# Agent Arena 0.1

## Purpose

`sova arena agent-run` runs provider-capable challenger and defender agents
against each other inside a SOVA-controlled synthetic message environment. A
third isolated model is an advisory judge. Every prompt, observable response,
message transfer, environment-state transition, oracle result, budget, and
failure is represented in a signed `.sova-trace`; every completed match is
packaged as a `.sova` capsule.

This closes the real-agent execution gap in the original deterministic Arena
without executing participant code or granting a model browser, terminal,
filesystem, credential, or host access.

The public runner accepts only SOVA's exact built-in `ProviderRoleModel` and
`ScriptedModel` adapters. Arbitrary in-process model classes are refused; a
future custom-agent path must use the separately admitted out-of-process
extension boundary.

## Roles and rounds

Each match binds three distinct participant identifiers:

- the challenger receives the case seed, its objective, the current round, and
  the defender's previous observable message;
- the defender receives the same declared case plus the challenger's current
  observable message;
- the judge receives only digests, declared signals, deterministic oracle
  results, and round metadata—not raw challenger or defender prose.

Challenger output is exactly `{"message": "..."}`. Defender output is exactly
`{"message": "...", "signals": [...]}`. Judge output is an assessment and
limitations object. Unknown fields, absent structured output, tool calls,
oversized content, invalid usage, malformed signals, time exhaustion, and token
budget exhaustion fail closed.

The current environment supports one to 20 rounds. It stops early when the
defender emits the exact case-declared observable success signal. Duration,
output, and optional token ceilings are enforced independently for each match.

## Sensing and evidence

The interpretability capture profile records:

- stable run, attempt, event, actor, model, and case identities;
- prompt and response digests plus byte/token accounting;
- capture-time-redacted observable prompts and messages when full capture is
  selected;
- `inter-agent.sent` and `inter-agent.received` events;
- round-level `environment.state` digests;
- deterministic exact-signal oracle results;
- advisory-judge identity, digest, decision, and disagreement; and
- environment, code, profile, case, dependency, and model-binding
  fingerprints.

Secret-shaped keys and values are replaced by typed placeholders before trace
bytes are persisted. Case inputs containing credential-shaped material are
refused before any model call, and model-generated credential-shaped text is
redacted before it is transferred to a second model. `metadata-only` capture
omits all event content. The
capsule pins the Arena methodology and observable-signal taxonomy and embeds
the complete signed trace for offline verification.

## Authority, providers, and comparability

Provider/model configuration is secret-free. Credentials are resolved only at
the provider boundary and are never serialized by the Arena. The command
requires `--allow-provider-calls` because calls may leave the machine and incur
cost. No target or host tool is available to participants.

Provider-capable runs must use an explicitly custom profile. They are marked
`custom-noncomparable`, excluded from the standard leaderboard, and never
silently inherit a standard score. The deterministic mandatory lane uses
`ScriptedModel` with no network or credentials. Real-provider validation is
optional and separately reported.

## Claims and limits

- Deterministic signal membership controls scoring; the model judge cannot
  override it.
- SOVA records observable provider output, not hidden chain-of-thought,
  private reasoning, intent, or model internals.
- The message environment is local, fully observed within its declared event
  boundary, and contains no native participant code. It is not a VM security
  sandbox and makes no claim about arbitrary-agent containment.
- A score demonstrates only the declared case, models, versions, budgets, and
  profile represented in its artifacts.
