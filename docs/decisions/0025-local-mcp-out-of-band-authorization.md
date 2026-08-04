<!-- status: decision -->

# ADR-0025: Local MCP with exact out-of-band authorization

- **Status:** Accepted
- **Date:** 2026-08-04
- **Owner:** Gautam R. Patil
- **Scope:** Topic 21 local MCP, tool manifest, and offensive-action authorization

## Decision

SOVA exposes one account-free local MCP server over inherited stdio using the
MCP `2025-11-25` tool contract. Tool schemas reject undeclared arguments and
the versioned manifest is digest-pinned. MCP annotations are treated only as
hints; SOVA's dispatcher and authorization kernel remain authoritative.

`sova.detonate`, `sova.rehearse`, and `sova.probe` cannot execute from an MCP
request alone. The first exact invocation produces an expiring challenge and a
signed denial trace. A human must review its target, arguments, effects,
budgets, and risks through a separate local interactive control channel outside
the agent-visible workspace. The resulting token binds the exact invocation
digest, expires, and is consumed once. There is deliberately no MCP approval
tool. Prompt content, tool output, and model claims cannot mint approval.

Workspace mapping is additionally disabled unless the operator consented when
starting the server. Paths remain relative to a pinned workspace. The server
opens no socket and has no hosted SOVA dependency.

## Alternatives rejected

- Approval as another MCP tool: the same compromised agent could call it.
- A reusable session-wide “authorized” flag: it silently widens target and effects.
- Trusting model-generated consent text: prompt injection can manufacture it.
- HTTP by default: unnecessary listener, origin, and authentication surface for local use.
- Treating `readOnlyHint` as enforcement: MCP specifies annotations as advisory.

## Consequences

Gated automation has one extra human round trip, intentionally. Tool-contract
changes fail `sova check --self` until the digest pin is deliberately reviewed.
The release-candidate workflow creates checksums and GitHub/Sigstore provenance
attestations, but no package or release has been published by this decision.
