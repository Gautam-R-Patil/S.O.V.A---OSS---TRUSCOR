<!-- status: implemented -->

# Real-time Arena chamber 0.1

## Purpose

The Arena chamber is SOVA's controlled, sensor-instrumented environment for
studying observable AI behavior while it happens. It supports:

- one agent against a declared environment;
- two agents against each other through a shared environment;
- several agents with distinct objectives and capability grants; and
- provider-backed SOVA roles against one exactly authorized website through a
  separate live-browser Arena lane.

The chamber is a real execution and evidence system, not merely a transcript.
Participants select from an operator-declared capability catalogue. SOVA
validates and executes each selected action, observes its declared effects,
updates the shared state, evaluates deterministic evidence, and exposes the
same canonical events in real time that it later seals in `.sova-trace`.

## Core contract

An `sova.arena-chamber` document declares:

- topology, case identity, objective, deterministic success-event kinds, and
  advisory judge;
- participants, models, role objectives, and exact action-ID grants;
- a finite action catalogue with typed operation and static inputs;
- the contained environment and explicit operator authorization; and
- independent round, action, duration, output, token, and capture budgets.

Unknown document fields, model types, action kinds, references, capabilities,
or versions fail closed. Provider credentials are resolved only at the
provider boundary. The mandatory lane is `ScriptedModel`, offline and
deterministic.

Participant output is untrusted strict JSON:

```json
{"message":"observable text","actions":["read-decoy"],"signals":[]}
```

A participant cannot pass arbitrary tool arguments. It may select only exact
action IDs from its grant. A bounded `$ref` can copy a previous observable
action result into a later predeclared action; it is not an expression
language. Direct model tool calls and undeclared actions fail the run.

## Built-in synthetic environment

The built-in world is inert and event sourced. It implements these action and
sensor families:

| Family | Actions | Canonical observations |
|---|---|---|
| Filesystem | confined read/write | `filesystem.read`, `filesystem.write` |
| Database | local read/update | `database.query`, `database.mutation` |
| API | inert email, messaging, storage, and payment preparation/release | typed `api.*` events |
| Network | sink-only `.invalid` send | `network.egress-attempt` |
| Agent communication | observable messages | `inter-agent.sent`, `inter-agent.received` |

Paths are confined to `/home/researcher/`; writes are restricted to the
declared notes/workspace trees. Network destinations must end in `.invalid`.
No native participant code, routable network, real credential, account, or
payment exists. This is a controlled synthetic environment, not a security
sandbox.

Every report includes both `healthySensors` and `missingSensors`. A missing
sensor is never silently converted into evidence of absence.

## Website Arena lane

`sova arena web` binds the existing provider-role browser campaign to the Arena
front door. It can exercise a loopback self-owned fixture or one HTTPS origin
with a current SOVA well-known control proof. The lane requires:

- a human-operated terminal;
- `--allow-provider-calls`;
- target, campaign, and provider-runtime documents;
- exact fresh approval for each generated action batch; and
- exact-origin browser confinement with credential, CAPTCHA, account-creation,
  download, upload, and destructive-action rejection.

Planning agents never receive browser tools. They propose bounded candidates;
SOVA validates them; a human approves the exact batch; and the admitted browser
executor performs it. Deterministic evidence, not model prose, controls the
verdict. Browser coverage is limited to the events exposed by the admitted MCP
adapter and the SOVA action/outcome/oracle stream. It is not total browser,
OS, kernel, or network observability.

## Live event guarantee

`TraceWriter` invokes a live observer only after an event has passed:

1. capture-time redaction;
2. schema validation;
3. canonical ordering and identifier assignment;
4. hash-chain linking; and
5. durable staging persistence.

The observer receives a detached canonical event. An observer failure disables
the observer and fails the run visibly; the staged trace can still be sealed as
partial/failed evidence. The synthetic chamber also appends and flushes the
events to `live-events.jsonl`, then byte-compares that journal with the event
stream in the finalized trace.

For multi-trace browser and software workflows, the observer receives a
channel plus the canonical event. Channels distinguish orchestration, attempts,
primary execution, and reproduction. `--stream-jsonl` emits channel envelopes
to stdout for a local UI, recorder, or websocket bridge.

The stream is therefore “`.sova-trace` in real time” within the declared
sensor boundary. It is not a claim that SOVA observes hidden model thoughts or
every physical effect.

## Verdict and judge

Declared success event kinds are evaluated by a deterministic membership
oracle over canonical observed events. Participant-declared signals are
untrusted. The advisory judge receives bounded evidence summaries and may
describe disagreement or limitations, but cannot override the oracle.

The final trace is Ed25519 signed and the `.sova` capsule contains the portable
case, participant/action contract, replay recipe, environment declaration, and
exact trace. Offline verification checks schema, content digests, ordering,
hash-chain integrity, signature, and capsule binding. A valid signature proves
integrity under the verified key; it does not independently establish legal
authority, signer identity, truth of unobserved facts, or non-repudiation.

## Artifacts

One contained chamber run produces:

- `live-events.jsonl` — the flushed canonical real-time stream;
- `arena.sova-trace` — finalized signed event/evidence stream;
- `arena.sova` — portable behavior capsule and replay recipe; and
- `arena-report.json` — verdict, sensor health, topology, claims, limitations,
  and artifact digests.

The browser lane produces an orchestration trace, one trace per candidate,
optional reproduction trace, discovery capsule when observed, and bounded
reports. All are suitable for offline inspection and replay; none is TRUSCOR
attestation.

## Commands

```text
sova arena chamber chamber.json arena-output \
  --authorize-contained-fixture --stream-jsonl

sova arena web target.json campaign.json provider-runtime.json arena-output \
  --control-proof control-proof.json \
  --allow-provider-calls --stream-jsonl
```

## Tested properties

Mandatory no-network tests cover all three topologies, action and model grants,
every built-in sensor family, live/final byte parity, capture-time redaction,
signature verification, capsule verification, action/token/output/time budgets,
malformed and hostile model output, direct tool-call refusal, observer failure,
unknown versions, wrong authority, reference safety, and deterministic
reproduction. Browser and trusted-process integration tests prove that observed
channels exactly match finalized traces. The installed-browser lane is optional
and separately reported because host availability is not a format invariant.

## Non-claims and remaining boundaries

- The chamber does not capture hidden chain-of-thought or private model state.
- “Fully sensed” means complete for the declared healthy sensor families, not
  complete knowledge of reality.
- Ordinary host-process execution is not a native security sandbox.
- Arbitrary participant binaries are not admitted in-process.
- External-provider quality, availability, nondeterministic reproducibility,
  and superiority require separately reported experiments.
- Authentication journeys may use operator-provided, explicitly authorized
  session fixtures in future adapters; SOVA does not create accounts, defeat
  CAPTCHA, harvest credentials, or evade platform controls.
