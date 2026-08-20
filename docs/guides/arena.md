<!-- status: implemented -->

# Run an Arena experiment

Arena has six deliberately different lanes. Choose the narrowest lane that
matches the experiment.

| Need | Command | Executes |
|---|---|---|
| Standard reproducible benchmark fixture | `arena run` | deterministic scripted case |
| Provider, scripted, or attested OCI agents exchanging observable messages | `arena agent-run` | models, no environment tools |
| Agents acting in a shared sensed environment | `arena chamber` | exact declared synthetic actions |
| Provider roles testing an authorized website | `arena web` | human-approved exact-origin browser batches |
| One adaptive planner autonomously exploring an authorized website | `arena explore-web` | semantic same-origin UI actions with per-batch approval |
| Multiple roles sharing one authorized browser identity | `arena swarm-web` | sequential human-approved browser subruns with signed channel evidence |

## Try the real-time chamber offline

The public example uses two scripted agents. The red agent reads a synthetic
canary and sends it only to a non-routable `.invalid` sink. The blue agent reads
the shared fixture. No provider, credential, browser, network service, or native
participant code is used.

```powershell
sova arena chamber examples\arena\chamber.json .\arena-output `
  --authorize-contained-fixture --stream-jsonl
```

While the run is active, stdout contains canonical events. The destination then
contains:

- `live-events.jsonl` for a real-time UI or recorder;
- `arena.sova-trace` for signed low-level evidence;
- `arena.sova` for sharing, replay, comparison, and citation; and
- `arena-report.json` for the verdict and honest sensor-coverage declaration.

Verify and inspect without running the Arena again:

```powershell
sova verify .\arena-output\arena.sova-trace --require-signature
sova verify .\arena-output\arena.sova
sova playback .\arena-output\arena.sova-trace
sova query .\arena-output\arena.sova-trace --kind-prefix network.
```

## Author a chamber

Start from `examples/arena/chamber.json` and change only declared data:

1. select `agent-vs-environment`, `agent-vs-agent`, or `multi-agent`;
2. define exact canonical event kinds that count as success;
3. declare a finite action catalogue;
4. grant every participant only the action IDs it needs;
5. set independent round, action, time, output, token, and capture budgets; and
6. choose scripted models first, then credential-late providers only for an
   explicitly authorized optional experiment.

The synthetic environment does not run arbitrary participant code. Adding a
new environment family requires an admitted executor adapter, normalized
events, explicit sensor-health reporting, conformance tests, and a new format
version when semantics change.

On a registered, ready, attested live gVisor host, `arena agent-run` can
conditionally include third-party native agents through a separate OCI adapter.
Each agent must implement the strict SOVA JSON protocol, use an exact
digest-pinned image, and pass signed conformance through the `runsc` runtime. It
receives messages, not environment tools, and runs with no network, credentials,
host mounts, writable root, capabilities, or container-engine socket. Use
`ociParticipants` plus
`--allow-sandboxed-agent-code --docker ...`; provider participants retain the
separate `--allow-provider-calls` gate. There is no fallback to a weaker
container runtime. Mandatory contract and failure-path tests pass, but this
checkout has no recorded live `runsc` execution.

## Test an authorized website

Prepare the target, campaign, provider runtime, and control proof using the
[authorized-target guide](authorized-target-testing.md). Then run:

```powershell
sova arena web website-target.json browser-campaign.json provider-runtime.json `
  .\arena-web-output --control-proof control-proof.json `
  --allow-provider-calls --stream-jsonl --headed --record-video `
  --playwright-browser-cache .\.cache\playwright-browsers
```

SOVA keeps planning roles away from browser tools. It validates their proposed
candidate set and displays the complete action batch. Nothing executes until a
human types the fresh digest-bound phrase. The browser executor remains pinned
to the exact authorized origin.

With `--headed`, the same admitted campaign is visible in the installed
browser while it runs. With `--record-video`, SOVA records that campaign and
its fresh reproduction, adds an `EXPLOIT CONFIRMED` chapter when the persisted
deterministic oracle passes, and packages `replay-cues.json` with the WebM and
signed traces. Render the proof directly:

```powershell
sova replay .\arena-web-output\browser\discovery.sova
```

The one-step command writes `discovery-replay.html` beside the capsule and asks
the operating system to open only that local file. Add `--no-open` for
automation, or retain the explicit `sova replay capsule CAPSULE OUTPUT` form
when a fixed output path is required.
The replay defaults to the decisive cue belonging to the selected primary trace.
Selection is deterministic: `run.sova-trace`, then `reproduction.sova-trace`,
then the lexically first remaining trace. Arena campaign and semantic-discovery
capsules do not package a conventional `run.sova-trace`, so their controlled
reproduction is primary by default; an exact internal path can override it.
It opens two seconds before that oracle and plays only through its three-second
post-roll when **Play decisive moment** is selected. It also selects the exact
`oracle.completed` trace event and displays the channel, sequence, oracle
status, video offset, and synchronization uncertainty. The cue uses the
same-host monotonic clock bounded by the successful recorder start RPC. Video
frames are not independently cryptographically timestamped.

This path can navigate and evaluate only the operations supported by the
declared campaign and admitted browser adapter. It does not bypass login,
CAPTCHA, anti-bot controls, or platform terms; create accounts; collect
credentials; or silently escalate scope. For an authenticated run, provision
an operator-prepared disposable session with `sova session browser-create`,
complete login through `sova session browser-handoff`, and pass the paired
`--browser-profile-vault` and `--browser-profile-handle` flags. Both `arena web`
and `arena explore-web` accept this pair. The opaque handle is bound to the
exact target; authentication material must never enter a `.sova`, trace,
report, or live stream.

`arena web` is a provider-assisted, bounded candidate campaign: provider roles
select from operator-authored candidates and SOVA executes the exact reviewed
browser actions. Use it when reproducibility requires a fixed candidate set.

## Autonomously explore a multi-page UI

Use a strict semantic mission when the workflow is not known in advance:

```powershell
sova arena explore-web website-target.json semantic-browser-mission.json `
  provider-runtime.json .\arena-explore-output `
  --control-proof control-proof.json --allow-provider-calls `
  --allow-target-observation-disclosure --headed --record-video `
  --playwright-browser-cache .\.cache\playwright-browsers
```

On every turn, the planner receives only a bounded, secret-redacted
accessibility snapshot and prior observable outcomes. It can invent a new plan
from the typed browser vocabulary, navigate successive same-origin pages,
interact with controls, traverse history, create or close a same-origin tab,
drag between visible targets, handle a visible modal, and adapt after failures.
It cannot create a new tool,
leave the exact authorized origin, read credentials, bypass authentication,
silently expand scope, or declare its own success. SOVA enforces page, action,
mutation, failure, stagnation, turn, time, text, and token limits and shows each
complete generated batch for a fresh digest-bound approval.

Only one observable UI boundary is admitted per generated batch, and it must be
last. A final modal-trigger click plus its immediate dialog handler is the sole
atomic exception. SOVA inserts a signed accessibility snapshot after every
other action and after the modal pair, so the planner receives fresh state after
navigation, visible UI effects, and bounded failures instead of acting through
an unobserved sequence.

The mission supplies deterministic setup, reset, and persisted-oracle rules. A
finding is confirmed only when those rules pass during discovery and then pass
again from a clean reset. The capsule identifies the decisive discovery and
reproduction traces, binds the single recording that spans both phases, and
includes media-bound replay cues. Render it:

```powershell
sova replay .\arena-explore-output\discovery.sova
```

The HTML opens on the reproduced oracle event and its bounded pre/post-roll, so
the proof selects the trace-linked action and event recorded when the
deterministic oracle passed instead of presenting an unexplained full-session
video. This trace relationship does not by itself prove that the action caused
the finding. For a third-party planning agent, replace the
provider runtime with a conforming OCI runtime and use
`--allow-sandboxed-agent-code --docker ...`; target-bound batch approval and all
browser policy remain enforced by SOVA.

The tab contract deliberately excludes arbitrary tab selection, and the
semantic algebra excludes filesystem paths and JavaScript evaluation. File
effects, mail, messages, and settings tests use separately declared contained
Arena/action-lab capabilities rather than giving the browser planner host
authority.

## Run several roles over one prepared browser identity

Provision a profile with `sova session browser-create`, complete any required
login through `sova session browser-handoff`, then use the strict example at
`examples/arena/browser-swarm.json`:

```powershell
sova arena swarm-web website-target.json browser-campaign.json `
  examples\arena\browser-swarm.json .\arena-swarm-output `
  --control-proof control-proof.json `
  --browser-profile-vault .\.sova\browser-profiles `
  --browser-profile-handle profile:0123456789abcdef0123456789abcdef `
  --stream-jsonl
```

Each role can select only its granted operator-authored candidates. Turns use
one exclusive profile lease and are sequential. The agents share redacted
observable results, not cookies, credentials, profile paths, or browser tools.
Add `--allow-provider-calls` only when the swarm document selects provider
models.

## Connect a live viewer

`--stream-jsonl` is intentionally renderer-neutral. A viewer reads one JSON
document per line and groups events by `channel`. It must treat event content as
untrusted text and must not render it as HTML. The live stream can be lost
without invalidating the run: the finalized signed trace remains canonical.
Conversely, a live line is not trustworthy by itself; verify it against the
final trace and signature.

## Understand “fully sensed”

Within the synthetic chamber, every admitted action emits its expected
canonical sensor event or fails. That is full coverage of the configured
adapter boundary. The report also lists every missing sensor family.

For website Arena runs, SOVA sees the browser and MCP observations the admitted
adapter provides plus its own prompts, approvals, actions, outcomes, state, and
oracles. It does not see hidden chain-of-thought, browser/kernel internals, or
effects outside those sensors. Absence of an observation is not absence of an
effect when the relevant sensor is missing.
