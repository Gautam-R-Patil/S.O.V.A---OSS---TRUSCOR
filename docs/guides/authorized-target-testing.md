<!-- status: implemented -->

# Authorized website and software testing

SOVA tests only a target you own or are explicitly authorized to assess. A URL,
login, or command line is not proof of authorization.

## Prepare the portable target contract

The quickest safe starting point for a browser target is an inert kit:

```console
sova target browser-kit https://owned.example ./owned-browser-kit
```

The command writes `target.json`, `campaign.json`, an assessment plan, and exact
operator instructions. It does not contact the origin, prove control, authorize
execution, or make the template ready to run. Replace the target version,
authorization reference, UI selectors, finite candidates, and observable oracle
before validation. External HTTP is refused; HTTP is allowed only for loopback.

For other target kinds, use the lower-level templates:

```console
sova target template browser-agent website-target.json
sova target template local-process software-target.json
sova target validate website-target.json
sova target plan website-target.json website-plan.json
```

Edit the template to declare the exact target version, capability surface,
allowed origins or interface, and authorization scope. Do not place passwords,
cookies, tokens, API keys, or login values in the manifest. `target plan` is
inert: it records the required stages and executor choices but neither proves
ownership nor connects to the target.

## Admit an executor

- Browser targets: pinned Microsoft Playwright MCP is the preferred public
  adapter. It uses an isolated profile and SOVA post-action observations.
- Windows UI: the optional Windows-MCP adapter starts read-only and never maps
  PowerShell, registry, filesystem, process, or clipboard tools.
- Local software: `RestrictedLocalExecutor` accepts only an explicitly
  allowlisted absolute executable and confined working directory. It is not a
  security sandbox; use a disposable VM/container/OS sandbox for untrusted code.
- MELRA is optional and never supplies SOVA authorization, evidence, policy,
  judging, signing, or replay semantics.

Before a live run, review the exact action/effect budget, provide fresh
out-of-band authorization, prepare an isolated test account and data set, and
define deterministic post-action oracles. CAPTCHA bypass, unauthorized account
creation, third-party production access, and stealth persistence are outside
the default workflow.

## Run the real owned-browser acceptance target

The first live runner is deliberately narrow and directly testable:

```console
sova detonate owned-web-fixture ./live-browser-proof --headed --record-video \
  --playwright-browser-cache ./.cache/playwright-browsers
sova verify --require-signature ./live-browser-proof/run.sova-trace
sova verify --require-signature ./live-browser-proof/reproduction.sova-trace
sova inspect ./live-browser-proof/evidence.sova
sova playback ./live-browser-proof/run.sova-trace
sova replay capsule ./live-browser-proof/evidence.sova ./live-browser-proof/replay.html
```

Video recording is explicit opt-in. Before the first recorded run, install the
FFmpeg runtime required by the pinned Playwright backend into the same local
browser cache (PowerShell shown):

```powershell
$videoCache = (New-Item -ItemType Directory -Force .\.cache\playwright-browsers).FullName
$env:PLAYWRIGHT_BROWSERS_PATH = $videoCache
npx.cmd --yes playwright-core@1.62.0-alpha-1783623505000 install ffmpeg
```

The runtime is Playwright's approximately 1.3 MiB FFmpeg build (LGPL-2.1) and
is not committed to SOVA. The version above is the transitive runtime used by
the pinned `@playwright/mcp@0.0.78`; it must be reviewed whenever that pin
changes. `--playwright-browser-cache` keeps the runtime in a caller-selected
cache instead of a user-global directory.

SOVA launches a real HTTP server on loopback, starts pinned Playwright MCP with
an ephemeral headless browser profile, limits admitted navigation to the exact
origin, displays every intended action in a closed batch, requests one fresh
exact approval phrase for that batch, issues a separate signed one-use token
for every action, executes a two-turn planted behavior, judges the final
accessibility snapshot, repeats the
scenario with fresh authority, compares the observable oracle result, captures
accessibility, console, network, and screenshot digest/size sensor evidence,
optionally records the headed browser pixels as WebM, signs both traces, and
embeds the traces and typed visual replay in an evidence capsule.

Raw screenshot pixels are not written into the trace. The adapter validates the
bounded binary response, computes SHA-256 and byte-size evidence, then discards
the pixels. This minimizes disclosure risk; it is not visual redaction and does
not prove that an executor did not retain its own copy.

The optional WebM is intentionally different: it preserves the reviewed
browser session so a human can watch the interaction. It may contain target
content, identifiers, or secrets visible on screen, so use isolated accounts,
review it before export, and apply the declared retention policy. Recorded
runs package a digest-bound replay cue for every passing deterministic oracle.
`sova replay capsule` verifies every capsule object, validates each cue against
the selected media and traces, opens on the decisive event with bounded
pre/post roll, embeds the video in one self-contained inert HTML page, and
removes the temporary files. Cue timing uses a same-host monotonic recorder
start RPC bound; it is not a cryptographically attested frame timestamp.

This proves the live browser/evidence path on SOVA's own target. It is not a VM
sandbox, a production-site test, a jailbreak-superiority result, or evidence
that arbitrary web applications are supported. Playwright's origin filter is
defense in depth and does not replace SOVA's pre-dispatch origin check or
post-run evidence review.

## Run a capsule against an external website you own

Edit a `browser-agent` target manifest so it contains exactly one bare HTTPS
origin and no credentials. Then:

```console
sova target challenge website-target.json website-challenge.json
# Publish the exact token at the proofUrl shown in website-challenge.json.
sova target prove website-target.json website-challenge.json website-proof.json
sova detonate browser website-target.json scenario.sova website-proof-output \
  --control-proof website-proof.json --headed --record-video \
  --playwright-browser-cache ./.cache/playwright-browsers
```

`target challenge` makes no network request. `target prove` performs one
bounded HTTPS GET with normal certificate validation, accepts no redirect,
requires the exact token and final URL, and emits an expiring proof. The
detonation command binds that proof to the exact target host and allowed origin,
then requests a fresh exact-batch approval in a human-operated terminal. Every
action is still independently scope checked and consumes its own one-use token;
an action omitted from the reviewed batch cannot be substituted later.

The proof establishes only short-lived control of that web origin. It does not
authorize sibling domains, third-party integrations, user accounts, destructive
actions, CAPTCHA bypass, unsolicited account creation, or data collection.
Review the `.sova` procedure, accounts, fixtures, stop conditions, retention,
and disclosure policy before approving it. Remove the hosted challenge token
after proof collection.

## Search a bounded candidate set through a real browser

First prove the complete path on SOVA's owned loopback target:

```console
sova hunt owned-web-fixture ./live-browser-hunt
sova verify --require-signature ./live-browser-hunt/traces/attempt-004.sova-trace
sova verify ./live-browser-hunt/discovery.sova
```

This runs four exact candidates, observes a near miss, discovers the planted
two-turn behavior, requests fresh approval for controlled reproduction, and
packages the winning scenario and signed traces.

For an external website you control, start with
[`examples/live/browser-campaign.json`](../../examples/live/browser-campaign.json),
update its URL, UI targets, candidates, oracle, and exact derived action count,
then run:

```console
sova hunt browser website-target.json browser-campaign.json website-hunt \
  --control-proof website-proof.json
```

If the target renders a temporary loading label after submit, declare a
bounded completion gate inside the campaign interaction, for example
`"completionWait":{"textGone":"Generating...","timeoutSeconds":120}`.
SOVA rejects unknown completion fields, counts one additional reviewed wait per
message in `budgets.maxActions`, and applies the declared timeout as the
scenario's per-step ceiling. Choose text that is target-specific and reliably
present during generation; the deterministic oracle still decides success from
the recorded post-wait observation.

Version 0.1 searches only the reviewed finite candidate set. It does not
generate unreviewed actions at runtime, bypass CAPTCHA, create unsolicited
accounts, or infer permission from a login session.

## Let isolated model roles propose the candidate set

Copy and edit the secret-free
[`examples/live/provider-runtime.json`](../../examples/live/provider-runtime.json),
then run:

```console
sova hunt agent-browser website-target.json browser-campaign.json \
  provider-runtime.json website-agent-hunt --control-proof website-proof.json \
  --allow-provider-calls
```

This flag authorizes only the configured provider requests. It does not approve
browser actions. SOVA first asks the recon, explorer, strategist, and attacker
roles for strict bounded JSON, derives an exact finite campaign, and then shows
the entire action batch for separate human approval. The judge sees a bounded
evidence summary and cannot override the deterministic oracle. Provider output
content is omitted from the orchestration report; identity, digests, usage, and
fallback failures remain auditable.

## Adapt between independently approved candidate batches

Copy
[`examples/live/adaptive-browser-policy.json`](../../examples/live/adaptive-browser-policy.json)
and set the provider runtime's `maxModelTurns` to at least five times the
policy's `maxRounds`. Then run:

```console
sova hunt adaptive-browser website-target.json browser-campaign.json \
  adaptive-browser-policy.json provider-runtime.json website-adaptive-hunt \
  --control-proof website-proof.json --allow-provider-calls
```

Each round is planned and authorized separately. Only the earlier candidate
sequences plus deterministic score and coverage fields reach the next round;
raw target content does not. The global duration, candidate, model-turn, and
optional token budgets cannot be widened by a provider. See the
[adaptive browser specification](../specifications/adaptive-browser-campaign-0.1.md).

## What can be validated without a live browser

`sova target fixture website DEST` and `sova target fixture software DEST`
exercise target → plan → scenario → observable execution → signed trace →
capsule → controlled reproduction → offline verification using deterministic
self-owned scripted fixtures. The first command above is the real-browser
acceptance lane. The external path is available only after the control proof,
target-specific scenario, data policy, accounts, and oracles are reviewed and
admitted.
