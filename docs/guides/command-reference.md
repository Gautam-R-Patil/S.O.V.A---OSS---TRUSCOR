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
| Search and analysis | `hunt owned-web-fixture`, `hunt browser`, `hunt agent-browser`, `hunt-demo`, `forensics reconstruct`, `forensics attribute`, `forensics browser-counterfactual`, `forensics benchmark`, `evidence`, `case build`, `adjudicate`, `compose` |
| Rehearsal and monitoring | `rehearse prepare`, `rehearse run`, `rehearse export`, `trace run`, `trace snapshot`, `diff`, `sentinel`, `ci`, `self-check` |
| Registry/community | `registry verify`, `sync`, `contribute`, `probe verify`, `arena run`, `arena agent-run`, `leaderboard build`, `ctf build` |
| Local MCP | `mcp manifest`, `mcp init-control`, `mcp approve`, `mcp serve` |
| Release and compatibility | `release sbom`, `release checksums`, `release verify-checksums`, `conformance export`, `conformance verify` |
| Authorized targets | `target template`, `target validate`, `target plan`, `target fixture`, `target challenge`, `target prove`, `detonate owned-web-fixture`, `detonate browser`, `hunt owned-web-fixture`, `hunt browser`, `hunt agent-browser` |

The CLI browser detonation accepts the built-in loopback fixture or one external
HTTPS origin with a current well-known control proof. It requires a
human-operated terminal and an exact fresh approval phrase for every action.
Other `detonate` and `probe` operations remain exact-gated local MCP tools;
every offensive MCP invocation requires an expiring, single-use approval
through the separate local control channel.

`sova check target.json OUTPUT --browser-campaign campaign.json` uses the same
proof-of-control and exact-batch approval boundary for a non-offensive dynamic
check. It verifies every emitted trace signature before returning
`confirmed-behavior`, `not-observed`, or `inconclusive`; `not-observed` means
only that the finite declared candidate set was exhausted.

Trace playback, controlled re-execution, and semantic reproduction are distinct
operations. No command claims to capture hidden chain-of-thought.

`hunt agent-browser` adds tool-isolated provider roles before the same reviewed
browser authority. It requires `--allow-provider-calls`; provider configuration
is secret-free, model output is untrusted, and deterministic evidence controls
the verdict.

`arena agent-run` uses the same credential-late provider boundary for a local
synthetic multi-agent message experiment. It grants participants no tools,
requires an explicit provider-call flag, emits signed trace/capsule evidence,
and always marks the run custom and non-comparable.

`sova case build TRACE CAPSULE OUTPUT` verifies that the capsule contains the
exact complete signed trace, then creates a local forensic, replay, evidence,
monitoring, and contribution-preview workspace. It performs no target action,
network request, upload, or automatic disclosure approval.
