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
| Search and analysis | `hunt-demo`, `forensics reconstruct`, `forensics attribute`, `forensics benchmark`, `evidence`, `adjudicate`, `compose` |
| Rehearsal and monitoring | `rehearse prepare`, `rehearse run`, `rehearse export`, `trace run`, `trace snapshot`, `diff`, `sentinel`, `ci`, `self-check` |
| Registry/community | `registry verify`, `sync`, `contribute`, `probe verify`, `arena run`, `leaderboard build`, `ctf build` |
| Local MCP | `mcp manifest`, `mcp init-control`, `mcp approve`, `mcp serve` |
| Release and compatibility | `release sbom`, `release checksums`, `release verify-checksums`, `conformance export`, `conformance verify` |
| Authorized targets | `target template`, `target validate`, `target plan`, `target fixture` |

`detonate` and `probe` are exposed as exact-gated local MCP tools, not as an
unguarded CLI shortcut. Every offensive MCP invocation requires an expiring,
single-use approval through the separate local control channel.

Trace playback, controlled re-execution, and semantic reproduction are distinct
operations. No command claims to capture hidden chain-of-thought.
