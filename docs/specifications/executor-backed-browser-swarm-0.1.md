<!-- status: implemented -->

# Executor-backed browser swarm 0.1

## Purpose

The browser swarm is SOVA's bounded multi-role Arena lane for an exactly
authorized website. Several scripted or provider-backed roles take turns over
one target-bound persistent browser identity. Each role may select only an
operator-authored candidate sequence from its explicit grant. SOVA, not the
model, owns browser execution, authorization, judging, sensors, evidence, and
the final verdict.

This lane exists for cooperative testing where roles need the same signed-in
browser state without copying cookies or credentials between models. It is not
an unrestricted autonomous swarm and does not bypass authentication controls.

## Configuration contract

An exact `sova.browser-swarm/0.1.0` document declares:

- case identity and title;
- two through eight unique participants;
- each participant's objective, finite campaign-candidate grant, and model;
- round, per-agent turn, total-turn, duration, output, and optional token
  ceilings; and
- whether the scheduler stops after a behavior is reproduced.

Unknown fields and versions fail closed. Participant identifiers are restricted
to path-safe ASCII IDs. Configured models must be SOVA's built-in deterministic
or credential-late provider adapters. Provider use requires the explicit CLI
permission flag.

Participant output has exactly two fields:

```json
{"candidateIndex":3,"message":"short observable note"}
```

Direct model tool calls, new browser arguments, candidates outside the role's
grant, duplicate candidate execution, malformed output, and missing usage data
under a token budget are refused.

## Shared-session and scheduler model

One opaque browser-profile handle is provisioned outside the capsule and bound
to the exact target-manifest digest. The CLI acquires one cross-process
exclusive lease for the full swarm. Turns are deliberately sequential because
Chromium profile directories are not safe concurrent-writer databases.

For each accepted turn, SOVA creates a one-candidate browser campaign and
starts the admitted Playwright MCP executor with the same leased profile.
Browser actions receive a fresh digest-bound human approval. A successful
candidate is rerun under a separate fresh approval before it is confirmed.

Models receive only operator-authored candidate data and a redacted observable
result ledger. They never receive the profile handle, path, cookie database,
credential values, or direct browser tools. A human may prepare the profile
through the separate headful handoff command; SOVA neither automates account
creation nor defeats CAPTCHA.

## Evidence model

The coordinator records signed canonical events for:

- run and containment state;
- each model prompt request and response digest;
- redacted inter-agent messages;
- participant, round, and candidate causal links;
- subrun report and trace digests;
- deterministic reproduction outcomes; and
- final budget and ledger state.

Every browser attempt and reproduction remains a separately signed
`.sova-trace`. The live journal carries a trace channel with each already
redacted durable event. Completion requires exact event parity between the
live channels and every finalized signed trace. The aggregate `.sova` capsule
contains the coordinator trace, uniquely named participant traces, target,
campaign, and swarm summary for offline verification.

Declared browser sensors include SOVA actions, outcomes, authorization, oracles,
and adapter-observed snapshots, console, network requests, and screenshot
digests. This is not hidden-thought capture, total host observability, or proof
that an uninstrumented effect did not occur.

## Command

```text
sova arena swarm-web target.json campaign.json browser-swarm.json output \
  --control-proof control-proof.json \
  --browser-profile-vault .sova/browser-profiles \
  --browser-profile-handle profile:0123456789abcdef0123456789abcdef \
  --allow-provider-calls --stream-jsonl
```

`--allow-provider-calls` is needed only when the document contains provider
models. The command always requires a human-operated terminal, an explicit
target-bound profile, valid proof-of-control where required, and per-subrun
approval.

## Validated properties

Mandatory offline tests cover strict parsing, role and candidate grants,
path-traversal identifiers, budgets, cancellation, direct-tool refusal,
redaction-before-transfer, signed subtraces, unique capsule trace paths, live
stream parity, malformed documents, and CLI delegation. An opt-in installed
Chrome test executes two roles against the self-owned loopback fixture across
separate Playwright MCP processes, reuses one leased profile, observes and
reproduces the planted conditional behavior, and verifies the aggregate trace
and capsule offline.

## Limits

- Scheduler turns are sequential, not parallel.
- Models select reviewed recipes; they do not freely navigate or invent tools.
- Browser confinement is not a security sandbox.
- The public real-runtime proof uses deterministic model roles and one owned
  loopback fixture; provider quality and arbitrary-site compatibility remain
  optional external validation.
- Signature and hash-chain checks establish bounded integrity and provenance,
  not truth, legal authority, non-repudiation, or unforgeability.
