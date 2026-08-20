<!-- status: implemented -->

# Semantic browser workflow 0.1

## Purpose

`sova arena explore-web` lets a tool-isolated planning model explore a multi-page
website that the operator has proved they control. The model sees a bounded,
secret-redacted accessibility snapshot and may propose only typed actions from
the mission's allowlist. SOVA, not the model, validates scope and budgets,
requests exact approval for every generated batch, executes through the pinned
Playwright MCP adapter, records signed traces, evaluates a deterministic
observable oracle, and performs a fresh controlled reproduction before a pass.

This is autonomous UI exploration inside a declared policy. It is not
unrestricted Internet roaming and does not let a model invent tools, execute
JavaScript, enter credentials, create accounts, bypass CAPTCHA, or expand the
target origin. The Playwright launch applies an allowed-origin request filter,
and SOVA rejects a signed post-action observation whose page URL drifts outside
the admitted origin. Those controls are not a process-level network egress
sandbox: page, browser, DNS, proxy, extension, and browser-process behavior
remain outside that narrower claim.

## Mission contract

A `sova.semantic-browser-mission` declares:

- one credential-free HTTP(S) entry URL;
- an operator-authored objective and optional seed inputs;
- an allowlist drawn from `navigate`, `back`, `click`, `type`, `select`,
  `press`, `hover`, `drag`, `dialog`, `tab-new`, `tab-close`, and `wait`;
- optional exact setup and reset recipes;
- a deterministic `field-contains` oracle;
- planner-turn, action, mutation, page, duration, text, failure, and token
  budgets; and
- the exact disclosure class `redacted-accessibility-snapshot`.

Unknown fields, cross-origin navigation, malformed locators, arbitrary script
actions, credential-shaped inputs, and unavailable token accounting fail
closed. A provider receives no browser tool and cannot approve its own plan or
declare a finding.

`tab-new` requires a complete URL on the exact admitted origin and is rejected
before browser execution when the origin differs. `tab-close` can close only
the current tab; the model cannot select an arbitrary pre-existing tab.
`dialog` accepts or dismisses only the currently visible browser modal, with
bounded secret-screened prompt text. `drag` requires human-readable source and
destination descriptions plus exact snapshot targets. File paths, arbitrary
JavaScript, browser-profile data, and unrestricted tab selection are outside
this action algebra.

Each generated plan may contain at most one observable UI boundary (`click`,
`select`, `press`, `drag`, `dialog`, submitted `type`, `navigate`, `back`,
`tab-new`, or `tab-close`), and that action must be last in the batch. SOVA also
admits one atomic exception: a final click that opens a browser modal may be
followed immediately by its `dialog` handler. SOVA inserts a signed accessibility
snapshot after every other generated action and after the complete modal pair. This
keeps intermediate page URLs in the page budget and evidence record and leaves
the planner a fresh state after a failed action instead of hiding the failure
inside a long preplanned sequence.

Malformed, denied, over-budget, or over-batched provider plans are never
executed. SOVA records only their bounded validation code and path, asks the
planner to try again from the unchanged signed observation, and stops after the
mission's consecutive-failure budget. Provider output therefore cannot turn a
recoverable planning mistake into unbounded retries or a policy bypass.

`maxDurationSeconds` is one end-to-end monotonic deadline beginning before the
initial reset/setup observation. It includes provider latency, human review,
browser execution, evidence capture, and reproduction. SOVA checks the deadline
after every blocking boundary. A provider response, batch, or reproduction that
returns after it cannot authorize further work or produce a pass. The browser
driver also reduces each executor request timeout to the then-remaining mission
budget and marks an executor result that nevertheless returns late as timed out.
Provider transports retain their own per-call cancellation behavior, so a late
provider call may finish, but its result is evidence only and is never acted
upon.

Within an approved batch, every action is followed by a signed snapshot. If an
action fails, times out, or is cancelled, SOVA permits only the immediately
following failure snapshot; later planned actions are refused rather than run
against an unknown prerequisite state. A fresh planner turn may recover from the
new signed observation if the remaining failure and duration budgets permit it.

## Execution and evidence

Each generated batch becomes an exact `.sova` scenario. The authorization
kernel derives intents from the real executor capabilities and requires fresh
human review before dispatch. Every batch ends with an explicit accessibility
snapshot, producing one independently signed `.sova-trace`.

When the oracle first passes, SOVA replays the complete discovered action
sequence after the mission's reset/setup recipe. Confirmation requires the
reproduction oracle to pass and the portable oracle outcomes to compare as
equivalent. The output includes:

- the canonical target and mission documents;
- every generated batch capsule and signed trace;
- a machine-readable report with action and trace digests;
- a portable discovery `.sova` when confirmed, containing the complete signed
  start/exploration/reproduction trace history plus `trace-history.json` in
  execution order; the discovery and reproduction traces retain the two
  unambiguous replay roles while earlier traces are content-addressed evidence
  attachments; and
- optional WebM video plus monotonic-clock replay cues at each persisted
  passing oracle event.

## Command

```console
sova arena explore-web target.json semantic-browser-mission.json \
  provider-runtime.json output \
  --allow-provider-calls \
  --allow-target-observation-disclosure \
  --headed --record-video --stream-jsonl
```

External targets additionally require a current well-known control proof.
Provider calls and target-observation disclosure are separate opt-ins because
the latter sends redacted target text to the configured provider.

## Assurance boundary

A passing mission proves only that the declared marker appeared in the signed
observable browser output and recurred under the recorded reproduction
conditions. Accessibility snapshots can miss visual-only state. Allowed-origin
request filtering and post-action page-origin drift detection are not browser-
process network confinement or a microVM. Included-key signatures need an
external trust policy for identity, and independent security review remains an
external gate.
