<!-- status: implemented -->

# Command reference

Run `sova COMMAND --help` for exact arguments. Commands use no ANSI color, keep
errors on stderr, and emit canonical JSON for machine-oriented reports unless a
human text or HTML artifact is the command's purpose.

| Family | Implemented operations |
|---|---|
| Setup | `init`, `doctor`, `data delete` |
| Capsule | `inspect`, `validate`, `lint`, `verify`, `migrate`, `compat`, `format`, `hash`, `template`, `pack` |
| Trace/replay | `playback`, one-step `replay FINDING.sova`, `replay open`, `replay modes`, `replay timeline`, `replay capsule`, `replay serve`, `replay study`, `replay clip`, `query`, `compare`, `export`, `recover-trace` |
| First value | `map`, `check`, `demo`, `safety backends`, `safety attest-docker`, `safety attest-gvisor`, `executors receipts` |
| Search and analysis | `hunt owned-web-fixture`, `hunt browser`, `hunt agent-browser`, `hunt adaptive-browser`, `hunt-demo`, `forensics reconstruct`, `forensics attribute`, `forensics browser-counterfactual`, `forensics benchmark`, `forensics blind-fixture`, `forensics blind-run`, `forensics blind-score`, `forensics blind-keygen`, `forensics blind-sign-key`, `evidence`, `case build`, `adjudicate`, `compose` |
| Rehearsal and monitoring | `rehearse prepare`, `rehearse run`, `rehearse agent-run`, `rehearse export`, `trace command`, `trace run`, `trace snapshot`, `diff`, `sentinel`, `monitor serve`, `monitor status`, `ci`, `self-check` |
| Registry/community | `registry init-service`, `registry prepare-upload`, `registry serve`, `registry healthcheck`, `registry verify-live-index`, `registry verify`, `sync`, `contribute`, `probe issue`, `probe verify`, `arena run`, `arena agent-run`, `arena chamber`, `arena web`, `arena explore-web`, `arena swarm-web`, `leaderboard build`, `ctf build` |
| Extensions and agents | `extension discover`, `extension prepare`, `extension run`, `agent conform-oci` |
| Local MCP | `mcp manifest`, `mcp init-control`, `mcp approve`, `mcp serve` |
| Release and compatibility | `release sbom`, `release checksums`, `release verify-checksums`, `conformance export`, `conformance verify` |
| Final-mile acceptance | `acceptance run`, `acceptance evaluate`, `acceptance template` |
| Authorized targets | `target browser-kit`, `target template`, `target validate`, `target plan`, `target fixture`, `target challenge`, `target prove`, `detonate owned-web-fixture`, `detonate owned-software-fixture`, `detonate browser`, `detonate software`, `hunt owned-web-fixture`, `hunt browser`, `hunt agent-browser`, `hunt adaptive-browser` |

`sova target browser-kit ORIGIN DESTINATION` writes an inert, secret-free
browser assessment starter kit. It accepts HTTPS or loopback HTTP, performs no
network request, establishes no authorization, and deliberately requires the
operator to replace scenario placeholders before a live run.

The CLI browser detonation accepts the built-in loopback fixture or one external
HTTPS origin with a current well-known control proof. It requires a
human-operated terminal and an exact fresh approval phrase for every action.
Other `detonate` and `probe` operations remain exact-gated local MCP tools;
every offensive MCP invocation requires an expiring, single-use approval
through the separate local control channel.

`sova probe issue REQUEST RESPONSE` signs a strict local observation document
with an ephemeral Ed25519 key. `probe verify` checks signature, nonce, exact
scope, TTL, optional key pinning, and local revocation entirely offline. The
included key proves document integrity only; neither command establishes the
subject's identity, trustworthiness, or independent certification.

The software detonation commands accept only finite `process.exec` scenarios
against credential-stripped disposable copies and one exact trusted
executable. They capture process output plus bounded workspace-file deltas,
then perform a fresh controlled reproduction. The backend is ordinary
restricted host-process execution—not a security sandbox or native desktop UI
driver—and does not block or observe target effects outside the copied
workspace.

`sova check target.json OUTPUT --browser-campaign campaign.json` uses the same
proof-of-control and exact-batch approval boundary for a non-offensive dynamic
check. It verifies every emitted trace signature before returning
`confirmed-behavior`, `not-observed`, or `inconclusive`; `not-observed` means
only that the finite declared candidate set was exhausted.

Trace playback, controlled re-execution, and semantic reproduction are distinct
operations. No command claims to capture hidden chain-of-thought.

`sova replay FINDING.sova` is the one-step human interface. It verifies the
capsule, derives `FINDING-replay.html` beside it, selects its decisive evidence,
and asks the operating system to open only that generated local HTML file. It
never opens a recorded URL or executes a recorded action. Use `--no-open` for
automation, or `sova replay open FINDING.sova --output OUTPUT.html` to choose a
destination while retaining the same report. The canonical JSON response gives
the absolute HTML path and local URI plus cue ID, channel, trace event/sequence,
video offset, pre/post-roll, selected trace side, media duration, and whether a
local-browser launch was requested and accepted.

`sova replay timeline TRACE OUTPUT --media SESSION.webm` embeds one reviewed
WebM/MP4 in the inert offline evidence navigator. The backward-compatible
`sova replay capsule EVIDENCE.sova OUTPUT` performs the same capsule rendering
without opening a browser. Use `sova inspect EVIDENCE.sova` to see exact object
paths; selection flags are required when a capsule has multiple possible
comparisons or recordings. Video capture itself is opt-in on browser detonation and
provider-backed `arena web` through `--headed --record-video` and requires a
caller-managed Playwright FFmpeg cache. A recorded passing oracle is packaged
with a media-digest-bound cue; capsule replay selects that trace event and its
bounded video window. `opensAtDecisiveMoment` is true only when the
selected WebM/MP4 exposes a finite container duration (or a finalized WebM block
timeline) and both the decisive cue and chapter fall within it; a magic-byte-only
or too-short recording cannot receive that state. Recordings may contain
screen-visible secrets, and same-host cue synchronization is not a frame-level
cryptographic attestation.

`sova replay serve TRACE` is a foreground, read-only, loopback reference
service for a sealed trace or its integrity-valid live prefix. It uses a random
unlogged capability URL, exact Host-header checks, finite SSE updates, and no
action endpoint. The URL can still leak through browser history or a compromised
local host, and the bundled HTTP server is not an Internet-production service.

The blinded forensics commands enforce a three-phase task, prediction, and
scoring workflow. `blind-run` has no answer-key argument. `blind-score` verifies
the committed answer core and can require a DSSE reviewer-key pin. The supplied
stochastic fixture validates software and statistics only; it does not establish
real-agent accuracy or independently verify reviewer identity.

`sova trace command TRACE --working-directory DIR -- EXECUTABLE ARG...` is the
interactive front door for one local shell-free command. It resolves and
allowlists the exact executable, rejects credential-shaped arguments, shows a
canonical review document, and requires its digest-bound phrase in a TTY before
execution. It inherits only the restricted local-executor environment and signs
the result, but it still runs with ordinary host authority and is not a sandbox.

`hunt agent-browser` adds tool-isolated provider roles before the same reviewed
browser authority. It requires `--allow-provider-calls`; provider configuration
is secret-free, model output is untrusted, and deterministic evidence controls
the verdict.

`hunt adaptive-browser` repeats that plan-review-execute-evaluate sequence for
separately approved bounded batches. Earlier rounds disclose only candidate
sequences and deterministic outcome fields to the next planner. Global round,
candidate, time, model-turn, and optional token ceilings fail closed.

`arena agent-run` runs a local synthetic multi-agent message experiment with
scripted, credential-late provider, and/or explicitly authorized external OCI
participants. External agents must implement the strict SOVA JSON protocol and
run from exact digest-pinned images through an attested gVisor `runsc` runtime;
they receive no target, browser, network, host-mount, credential, or Docker
socket authority. Provider calls and sandboxed native code have separate opt-in
flags. The run emits signed trace/capsule evidence and remains custom and
non-comparable.

`arena chamber` is the sensor-instrumented environment runner. Agents select
only operator-declared action IDs; SOVA executes them in an inert event-sourced
world, evaluates canonical events, streams the already-redacted hash-chained
trace in real time, and packages the signed trace and replay recipe. `arena
web` applies provider-backed candidate selection to an exactly authorized
website through the same human-reviewed browser campaign boundary. See the
[Arena chamber specification](../specifications/arena-chamber-0.1.md).

`arena explore-web` is the adaptive semantic UI lane. The planner can inspect
successive redacted accessibility snapshots, choose among typed browser
primitives (`navigate`, `back`, `click`, `type`, `select`, `press`, `hover`,
`drag`, `dialog`, `tab-new`, `tab-close`, and `wait`), discover same-origin
pages, and revise its plan after every observed batch. SOVA, not the model,
enforces origin, action, page, mutation, failure,
turn, time, text, and token budgets. Every generated batch receives a fresh
digest-bound human approval; only deterministic persisted oracles can declare a
finding; and a second clean reproduction is required. The resulting discovery
capsule exposes unambiguous trace-role selections for decisive discovery and
controlled reproduction while retaining earlier exploration traces as
content-addressed history attachments. One-step `sova replay FINDING.sova`
requests opening the generated local proof with the duration-bounded reproduced
oracle cue selected; `replay capsule` renders the same selection to an explicit
output path without requesting a browser. See the
[semantic browser workflow
specification](../specifications/semantic-browser-workflow-0.1.md).

`arena swarm-web` lets two through eight bounded model roles take sequential
turns over one opaque target-bound browser profile. A role selects only a
granted operator-authored campaign candidate; SOVA applies fresh human browser
approval, records per-role signed subtraces plus a signed coordinator trace,
and packages the exact live-channel evidence. See the
[browser swarm specification](../specifications/executor-backed-browser-swarm-0.1.md).

`rehearse agent-run` asks one tool-free provider strategist to propose a strict,
bounded portable plan for an already prepared workspace. It requires an exact
approval before disclosing the bounded sanitized inventory and another exact
approval over the validated plan before execution. File effects remain in the
disposable workspace; all service effects remain inert substitutes.

`sova case build TRACE CAPSULE OUTPUT` verifies that the capsule contains the
exact complete signed trace, then creates a local forensic, replay, evidence,
monitoring, and contribution-preview workspace. It performs no target action,
network request, upload, or automatic disclosure approval.

`sova registry serve` runs a loopback-only staged contribution service. It
requires a private local token and explicit evidence-signer pins, never executes
submitted content, recovers an interrupted verification queue, and exposes a
DSSE-signed index plus SSE updates. `registry healthcheck` verifies the exact
loopback readiness response, status, service-key digest, redirect policy, and
response-size boundary used by the hardened deployment blueprint.
`registry verify-live-index` requires an out-of-band service-key pin and can
enforce a minimum sequence. The bundled compose/Caddy blueprint supplies a
non-root, read-only, capability-dropped deployment foundation; operating a
public service still requires an operator-owned domain and TLS policy, identity
and authorization, human moderation, backups and restore exercises, abuse and
DDoS controls, monitoring, and incident response. See the [community service
specification](../specifications/self-hosted-community-service-0.1.md).

`sova monitor serve` schedules only declared local snapshot comparisons. It has
no command/provider/URL field, rejects overlapping instances through an OS
lock, recovers interrupted state, prunes reports and history, and writes a
signed drift-result trace. Optional `--alert-webhook HTTPS_URL
--alert-secret-env ENV_NAME` sends a path-free HMAC-authenticated alert and
requires an exact idempotency acknowledgement. See the [continuous monitor
specification](../specifications/continuous-monitor-service-0.1.md) and
[managed-service boundary](../specifications/managed-services-and-hosting-0.1.md).

`sova acceptance run DEST` proves only the credential-free local engineering
slice. `acceptance template` emits an inconclusive external-receipt skeleton;
`acceptance evaluate` requires actual distinct environments and organizations
for the declared stable gates. Self-authored templates never make 1.0 ready.

`sova extension discover` reads entry-point metadata without importing plugin
code. `extension prepare` creates a local launch document pinned to absolute
executable and regular-file hashes without execution. `extension run` requires
an exact interactive approval over the full launch, rechecks every pin, uses no
shell, and records signed evidence. It executes an ordinary process with the
operator's host authority; it is not a security sandbox. See the
[safe extension example](../../examples/extensions/README.md).

`sova safety attest-gvisor --docker DOCKER --image REPOSITORY@sha256:DIGEST`
verifies that `runsc` is registered and that the exact image is already cached;
it does not execute the image. `sova agent conform-oci RUNTIME DESTINATION`
then exact-approves and runs the agent's `describe`, `self-test`, and `respond`
operations through that enforced profile, validates one digest-bound JSON
response per operation, and records a signed conformance trace and report. SOVA
refuses silent fallback to ordinary containers. gVisor materially narrows the
host-kernel interface but is not a separate VM kernel; production operators
must patch, monitor, and independently test the host, engine, and `runsc` stack.
See the [OCI agent runtime
specification](../specifications/oci-agent-runtime-0.1.md).
