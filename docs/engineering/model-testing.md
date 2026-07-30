<!-- status: implemented -->

# Model testing lanes

## Mandatory deterministic lane

`ScriptedModel` is the CI authority for format and orchestration tests. It
consumes fixed expected prompts, emits deterministic responses and tool calls,
supports explicit fault injection, needs no network or credentials, and writes
ordinary `.sova-trace` events.

The public conditional-trigger fixture proves:

```text
.sova capsule
  -> fresh synthetic authorization
  -> scripted baseline and trigger turns
  -> redacted .sova-trace
  -> inert playback
  -> offline integrity verification
  -> exact observable-outcome comparison
```

This is a fixture result, not evidence about a production model.

## Optional official Codex lane

`CodexExecAdapter` follows the official non-interactive contract:

- preflight only with `codex login status`;
- `codex exec --ephemeral --sandbox read-only --json`;
- `--ignore-user-config` and `--ignore-rules` for controlled fixture behavior;
- a structured `--output-schema` inside the isolated fixture directory;
- a `.sova-codex-fixture` marker;
- sanitized environment without API-key variables;
- duration, prompt, and output-size budgets;
- JSONL mapping into observable SOVA events;
- no reads, copies, parsing, logging, or export of Codex auth files or tokens.

The official manual documents `thread.*`, `turn.*`, `item.*`, and `error` JSONL
events. SOVA maps agent messages, provider-exposed reasoning summaries, command
executions, file changes, MCP calls, web searches, and plan updates without
claiming private chain-of-thought access.

Availability, authentication, rate limits, plan limits, or Windows execution
denial produce a visible optional result or skipped optional test. The shipped
core and mandatory CI never require Codex.
