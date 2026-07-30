<!-- status: decision -->

# ADR-0010: Executor contract and no-Atlas reference backends

- Status: Accepted
- Date: 2026-07-30
- Owner: TRUSCOR Private Limited
- Scope: Topic 06 executor boundary

## Context

SOVA scenarios must remain portable across execution providers. Coupling the
format to Atlas MCP, a shell, or one operating system would make replay recipes
provider-specific and would move security decisions into a layer that cannot be
treated as a trust root.

## Decision

SOVA uses exact versioned capability negotiation over a minimal provider-neutral
executor protocol. Requests, outcomes, evidence, effects, cancellation,
timeouts, retry metadata, limitations, and post-action verification are
normalized by the protocol.

The open-source reference implementation provides:

1. `ScriptedExecutor` for deterministic, credential-free conformance and fault
   injection;
2. `RestrictedLocalExecutor` for content-addressed artifact reads and optional
   shell-free execution of explicitly allowlisted absolute executables.

The same public capsule is tested against both backends. Provider adapters own
only execution mechanics. SOVA retains authorization, safety policy,
containment selection, observation, judging, redaction, signing, trace
construction, and threat-model claims.

Atlas MCP remains an optional future browser/computer/terminal adapter. Its
absence cannot prevent core format, evidence, replay, or local conformance work.

## Safety boundary

The local backend is not called `LocalSandboxExecutor` in code because ordinary
host-process restrictions do not constitute a security sandbox. It provides
useful confinement and normalized evidence but no claim of kernel, network, or
filesystem isolation. Destructive actions are not implemented.

Fresh explicit authorization is required before the scenario runner invokes any
backend. This initial check is not the complete Topic 07 authorization model.

## Consequences

- A backend can be added without changing `.sova` or `.sova-trace`.
- Unsupported capabilities fail before any scenario action executes.
- Mandatory tests remain offline and deterministic.
- Local process execution is intentionally narrow and unsuitable for hostile
  targets until true containment exists.
- Provider-specific fidelity must be declared rather than silently invented.

## Alternatives rejected

- Atlas-first implementation: rejected because it would couple SOVA's core to a
  separate provider and delayed capability surface.
- Raw shell command strings: rejected because quoting, shell expansion, and
  ambient environment make behavior less portable and less controllable.
- Treating host restrictions as a sandbox: rejected as an unsafe overclaim.
- Silent capability downgrade: rejected because it changes scenario meaning.
