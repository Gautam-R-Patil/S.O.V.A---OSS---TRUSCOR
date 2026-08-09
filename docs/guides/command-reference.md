<!-- status: implemented -->

# Command reference

Run `sova COMMAND --help` for exact arguments. Commands use no ANSI color, keep
errors on stderr, and emit canonical JSON for machine-oriented reports unless a
human text or HTML artifact is the command's purpose.

| Family | Implemented operations |
|---|---|
| Setup | `init`, `doctor`, `data delete` |
| Capsule | `inspect`, `validate`, `lint`, `verify`, `migrate`, `compat`, `format`, `hash`, `template`, `pack` |
| Trace/replay | `playback`, `replay modes`, `replay timeline`, `replay study`, `replay clip`, `query`, `compare`, `export`, `recover-trace` |
| First value | `map`, `check`, `demo`, `safety backends`, `executors receipts` |
| Search and analysis | `hunt owned-web-fixture`, `hunt browser`, `hunt agent-browser`, `hunt adaptive-browser`, `hunt-demo`, `forensics reconstruct`, `forensics attribute`, `forensics browser-counterfactual`, `forensics benchmark`, `evidence`, `case build`, `adjudicate`, `compose` |
| Rehearsal and monitoring | `rehearse prepare`, `rehearse run`, `rehearse agent-run`, `rehearse export`, `trace command`, `trace run`, `trace snapshot`, `diff`, `sentinel`, `ci`, `self-check` |
| Registry/community | `registry verify`, `sync`, `contribute`, `probe issue`, `probe verify`, `arena run`, `arena agent-run`, `arena chamber`, `arena web`, `leaderboard build`, `ctf build` |
| Extensions | `extension discover`, `extension prepare`, `extension run` |
| Local MCP | `mcp manifest`, `mcp init-control`, `mcp approve`, `mcp serve` |
| Release and compatibility | `release sbom`, `release checksums`, `release verify-checksums`, `conformance export`, `conformance verify` |
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

`arena agent-run` uses the same credential-late provider boundary for a local
synthetic multi-agent message experiment. It grants participants no tools,
requires an explicit provider-call flag, emits signed trace/capsule evidence,
and always marks the run custom and non-comparable.

`arena chamber` is the sensor-instrumented environment runner. Agents select
only operator-declared action IDs; SOVA executes them in an inert event-sourced
world, evaluates canonical events, streams the already-redacted hash-chained
trace in real time, and packages the signed trace and replay recipe. `arena
web` applies provider-backed planning to an exactly authorized website through
the same human-reviewed browser campaign boundary. See the
[Arena chamber specification](../specifications/arena-chamber-0.1.md).

`rehearse agent-run` asks one tool-free provider strategist to propose a strict,
bounded portable plan for an already prepared workspace. It requires an exact
approval before disclosing the bounded sanitized inventory and another exact
approval over the validated plan before execution. File effects remain in the
disposable workspace; all service effects remain inert substitutes.

`sova case build TRACE CAPSULE OUTPUT` verifies that the capsule contains the
exact complete signed trace, then creates a local forensic, replay, evidence,
monitoring, and contribution-preview workspace. It performs no target action,
network request, upload, or automatic disclosure approval.

`sova extension discover` reads entry-point metadata without importing plugin
code. `extension prepare` creates a local launch document pinned to absolute
executable and regular-file hashes without execution. `extension run` requires
an exact interactive approval over the full launch, rechecks every pin, uses no
shell, and records signed evidence. It executes an ordinary process with the
operator's host authority; it is not a security sandbox. See the
[safe extension example](../../examples/extensions/README.md).
