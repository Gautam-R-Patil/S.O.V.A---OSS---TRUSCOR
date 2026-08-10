<!-- status: implemented -->

# Run an Arena experiment

Arena has five deliberately different lanes. Choose the narrowest lane that
matches the experiment.

| Need | Command | Executes |
|---|---|---|
| Standard reproducible benchmark fixture | `arena run` | deterministic scripted case |
| Provider or scripted agents exchanging observable messages | `arena agent-run` | models, no environment tools |
| Agents acting in a shared sensed environment | `arena chamber` | exact declared synthetic actions |
| Provider roles testing an authorized website | `arena web` | human-approved exact-origin browser batches |
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

## Test an authorized website

Prepare the target, campaign, provider runtime, and control proof using the
[authorized-target guide](authorized-target-testing.md). Then run:

```powershell
sova arena web website-target.json browser-campaign.json provider-runtime.json `
  .\arena-web-output --control-proof control-proof.json `
  --allow-provider-calls --stream-jsonl
```

SOVA keeps planning roles away from browser tools. It validates their proposed
candidate set and displays the complete action batch. Nothing executes until a
human types the fresh digest-bound phrase. The browser executor remains pinned
to the exact authorized origin.

This path can navigate and evaluate only the operations supported by the
declared campaign and admitted browser adapter. It does not bypass login,
CAPTCHA, anti-bot controls, or platform terms; create accounts; collect
credentials; or silently escalate scope. An authenticated testing adapter may
in future consume an operator-prepared disposable session, but authentication
material must never enter a `.sova`, trace, report, or live stream.

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
