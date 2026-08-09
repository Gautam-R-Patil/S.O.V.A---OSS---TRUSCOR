<!-- status: experiment -->

# Arena chamber validation — 2026-08-09

## Scope

This validation covers the real-time multi-agent Arena chamber, propagation of
canonical live events through browser and trusted-process workflows, the
provider-backed authorized website Arena CLI route, and release compatibility.
It does not claim universal target support, native host isolation, hidden-state
observability, or external-provider quality.

## Implemented inventory

- strict `sova.arena-chamber` document parser;
- agent-vs-environment, agent-vs-agent, and multi-agent topologies;
- finite participant action grants and a typed synthetic action catalogue;
- event-sourced filesystem, database, inert API, sink-only network, and
  inter-agent sensors;
- deterministic canonical-event oracle and non-overriding advisory judge;
- capture-time-redacted live observer after validation, chain linking, and
  staging persistence;
- flushed `live-events.jsonl` with exact finalized-trace parity check;
- signed `.sova-trace`, portable `.sova`, and bounded report;
- browser campaign, provider-role campaign, and trusted-process observer
  channels;
- `sova arena chamber` and `sova arena web`; and
- `arena.chamber/0.1` capsule compatibility support.

## Mandatory deterministic results

On Windows with Python 3.11.15:

- complete repository: **1,017 passed, 6 optional skips**;
- branch coverage: **95.20%** over 16,314 statements and 4,658 branches;
- CLI audit: **88/88 leaf handlers executed**;
- Arena-focused suites: **70 passed, 5 optional browser skips** before the
  installed-browser lane;
- chamber implementation coverage: 98% for both runtime and parser in the
  complete suite;
- Ruff formatting/lint: pass;
- strict mypy: pass;
- repository policy: pass; and
- public-boundary policy: pass;
- wheel and source-distribution build: pass, with Arena modules in the wheel and
  the guide, specification, validation report, and safe example in the source
  distribution; and
- dependency audit: no known vulnerabilities found, with the repository's one
  documented scoped advisory exception applied.

The six default skips were one official Codex subscription test (`codex login
status` reported not logged in) and five intentionally opt-in installed-browser
tests. No required test used network access or provider credentials.

## Installed-browser result

With `SOVA_RUN_REAL_BROWSER=1`, all **9/9** live-browser integration tests passed
in 131.61 seconds against SOVA's self-owned loopback fixture using installed
Chrome and the admitted Playwright MCP process. The lane exercised real browser
detonation, campaign search, dynamic check, repeated counterfactual execution,
and agent-role orchestration with deterministic model-role outputs.

This validates the browser execution and sensor/evidence path on this machine.
It is not evidence that an arbitrary website, login flow, browser version,
provider model, or operating system will behave equivalently.

## Security and failure results

Tests verified:

- wrong fixture authority and omitted provider permission fail before calls;
- model tool calls, undeclared actions, cross-grant action selection, unsafe
  references, routable network destinations, and escaped filesystem paths fail;
- token, output, round, action, and duration budgets are independent;
- credential-shaped observable material is redacted before live observation;
- observer failure is visible and the failed/partial trace remains sealable;
- participant signals and judge output cannot override deterministic evidence;
- live journal substitution/mismatch fails the report path;
- signature, event order, causal links, chain, redaction structure, and capsule
  content digests verify offline; and
- sensor absence remains explicit in the report.

## Artifact acceptance

The public example completed with status `pass`, produced 36 canonical events,
reported a valid Ed25519 signature, and byte-matched its live journal to its
final trace. `sova verify` passed schema, object-digest, ordering, chain,
causality, redaction, required-feature, and signature checks. Overall trust
remained correctly `partial` because included-key integrity does not establish
external signer identity and the example does not pin all environment/model
fingerprints.

Capsule verification accepted `arena.chamber/0.1`. Its overall state remained
correctly `partial` because the generic example methodology/taxonomy names are
not content-digest pinned. Playback completed offline.

## External-only validation

Not performed:

- paid or credentialed hosted-provider calls;
- a founder-selected non-fixture website with current proof of control;
- authenticated session testing;
- native VM/container isolation of arbitrary participant binaries;
- independent third-party security review; or
- cross-platform installed-browser execution.

These are reported as external/optional boundaries, not converted into passing
claims. SOVA does not create accounts, solve CAPTCHA, collect credentials, or
evade third-party controls.
