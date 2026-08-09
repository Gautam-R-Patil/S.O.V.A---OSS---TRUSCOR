<!-- status: implemented -->

# External execution broker 0.1

## Purpose

The SOVA Capability Execution Broker routes one portable action to an admitted
executor. It is the free/open-source fallback architecture for MELRA and does
not depend on a hosted service, model provider, or secret.

## Protocol client

`StdioMCPClient` implements the MCP 2025-11-25 stdio subset required by the
adapters:

- JSON-RPC initialization and initialized notification;
- paginated `tools/list` discovery;
- bounded `tools/call` results;
- newline-delimited UTF-8 JSON with stdout reserved for protocol messages;
- argv-only process launch with a small environment allowlist;
- rejection of secret-shaped environment keys;
- message, stderr, startup, and call time limits; and
- visible malformed-message, remote-error, timeout, close, and process failure.

Tool descriptions, annotations, input/output schemas, and provider receipts are
untrusted hints. SOVA maps only tools it recognizes and validates the result
again after normalization.

## Backend set

| Backend | Role | Admission and limitation |
|---|---|---|
| `ScriptedExecutor` | offline deterministic CI | no external process or credential |
| `RestrictedLocalExecutor` | bounded local file/process/terminal intent | ordinary host process confinement is not a security sandbox |
| Microsoft Playwright MCP 0.0.78 | preferred browser backend | isolated profile, exact executable, origin policy plus SOVA post-observation; Playwright MCP is not containment |
| Windows-MCP 0.8.2 | optional Windows desktop reads/actions | Python 3.13+, telemetry disabled, explicit tool allowlist; full host access remains high risk |
| CUA Driver 0.12.6 | optional Windows computer backend | signed release checksum, private service generation, bounded session manifest, telemetry off; live reads passed, live mutation remains unadmitted on this runner |
| MELRA 0.3.0-alpha.10 | optional browser/computer/terminal adapter | public HEAD and lockfile pinned; provider policy and receipts are not SOVA authority/evidence |

The default Windows-MCP launch allowlist is read-only: `Snapshot,Screenshot`.
`Click,Type,Scroll,WaitFor` require an explicit `allow_input=True` launch
decision. PowerShell, Registry, FileSystem, Process, and Clipboard are never
mapped by the adapter.

## Mapping and normalization

A `ToolMapping` binds portable action, exact MCP tool, capability version,
maximum side effect, idempotency, expected evidence, argument projection, and
optional post-observation tool. Unrecognized MCP content is labeled rather than
executed. Text is capped at 1 MiB and binary content at 16 MiB. Binary, text,
structured, and post-observation evidence receives a content digest.

Read actions use their direct result as the observation. Mutations remain
`provider-result-only` unless a separate observation succeeds. The broker
accepts neither that state nor MELRA's defense-in-depth result as independent
verification.

The CUA adapter additionally requires an exact positive PID/HWND for every
mutation, sends background delivery first, and permits a foreground retry only
after CUA emits `background_unavailable` and SOVA supplies a separate fresh
foreground approval. CUA's second provider call is explicitly not independent
SOVA verification. Desktop-wide capture is disabled unless the adapter is
constructed with an explicit opt-in.

## Reliability and fallback

The broker records each attempt and a restart checkpoint containing only action
identity, state, executor names, and attempt count. It never persists inputs,
cookies, login material, or session tokens in that checkpoint.

Fallback is permitted for unsupported actions, or for idempotent actions whose
failed/timeout/partial state is attributable to executor, environment, timeout,
or evidence. Denial and uncertain mutation are terminal. SOVA does not repeat a
possibly completed click, type, terminal command, or other mutation merely
because its receipt was lost.

## MELRA-specific mapping

MELRA is planned then executed through `melra_plan` and `melra_execute`.
`melra_task_status` and `melra_task_cancel` are separately normalized when
available. Only internal `task.status == verified_success` maps to SOVA
`succeeded`. `policy_blocked`, approval/wait states, partial, budget, recovery,
cancel, failure, nonterminal, unknown, and substituted-task results remain
explicit non-success outcomes even when MCP transport returned `isError=false`.

MELRA approval never replaces SOVA approval. MELRA task records are filtered so
their echoed requests do not become SOVA evidence. Provider output, receipt,
and certificate material is digest-referenced and remains untrusted.

## Version upgrades

Every deployment records `sova executors receipts`, re-runs tool discovery,
adapter unit tests, deterministic MCP conformance, safe live smoke checks, and
the complete SOVA suite before changing a pinned backend. A disappeared tool is
an explicit capability downgrade. No adapter version may change artifact
interpretation.

Primary specifications and implementations:

- [MCP 2025-11-25 transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
- [MCP 2025-11-25 tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
- [Microsoft Playwright MCP](https://github.com/microsoft/playwright-mcp)
- [Windows-MCP](https://github.com/CursorTouch/Windows-MCP)
- [CUA](https://github.com/trycua/cua)
- [MELRA](https://github.com/XAGI-Lab/melra)
