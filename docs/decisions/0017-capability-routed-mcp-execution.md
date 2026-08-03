<!-- status: decision -->

# ADR-0017: Capability-routed MCP execution without a MELRA dependency

- **Status:** Accepted
- **Date:** 2026-08-03
- **Owner:** Gautam R. Patil
- **Scope:** Topic 13 external execution

## Decision

SOVA owns a small, bounded MCP stdio client and a capability execution broker.
Portable action intent is mapped to exact discovered tools at runtime. The
default free/open-source backend set is:

- `ScriptedExecutor` for deterministic offline conformance;
- `RestrictedLocalExecutor` for bounded local files/processes;
- Microsoft Playwright MCP for browser automation;
- Windows-MCP as an optional, explicitly whitelisted desktop backend; and
- MELRA as an optional adapter, never a required trust root.

Every backend result is normalized into the SOVA executor contract. Read
results are direct observations. Mutations require a separate post-action
observation. Provider annotations, task states, receipts, certificates, and
policy decisions remain untrusted input. SOVA authorization, evidence,
redaction, oracles, judging, signing, replay, and forensics remain outside the
adapters.

Fallback is allowed only when effects are known not to have occurred or the
action is idempotent and failure is attributable to executor, environment,
timeout, or evidence. An uncertain mutating action is never silently retried.

## Alternatives rejected

- Depend on MELRA for core execution: its audited Windows build and tests fail.
- Treat MCP transport success as task success: MELRA can return a successful
  JSON-RPC response containing `policy_blocked`.
- Trust tool annotations or receipts as independent evidence: they are supplied
  by the executor being measured.
- Offer every Windows-MCP tool: this would expose unrestricted host shell,
  registry, filesystem, process, and clipboard operations.

## Consequences

Removing MELRA does not change `.sova`, `.sova-trace`, or the SOVA evidence
model. The broker is orchestration, not containment. Browser and desktop MCP
servers retain their own host access and must be admitted under SOVA policy.
