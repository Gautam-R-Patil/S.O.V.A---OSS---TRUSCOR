<!-- status: decision -->

# ADR-0023: Multi-axis drift and local regression evidence

- **Status:** Accepted
- **Date:** 2026-08-03
- **Owner:** Gautam R. Patil
- **Scope:** Topic 19 tracing, diff, sentinel, CI, and integrity monitoring

## Decision

SOVA snapshots behavior, environment, and methodology as independent canonical
axes. `sova diff` classifies target, model, tool-schema, permission,
dependency, registry, approval-surface, observed-effect, reproduction-rate,
finding, capture-profile, taxonomy, and methodology changes. A changed digest
identifies declared drift; it is not a causal explanation or new security
evidence.

`sova trace run` wraps one explicitly authorized, exact-allowlisted, shell-free
local process through `RestrictedLocalExecutor` and writes a signed trace. The
direct process channel is observed; model, tool, MCP, memory, retrieval,
browser, computer, and egress events are accepted only when an instrumented
adapter emits registered events. Ordinary host execution is not a sandbox.

`sova sentinel` appends local methodology-preserving history and never uploads.
`sova ci` applies deterministic drift and flakiness policy, emits annotations
and SARIF, and never patches. `sova self-check` hashes explicitly listed files;
its baseline must be protected independently.

## Alternatives rejected

- One opaque "drift score": hides whether the system, behavior, or test changed.
- Treat every changed result as a vulnerability: overstates evidence.
- Capture hidden chain-of-thought: unavailable, unsafe to claim, and non-portable.
- Enable arbitrary shell command strings: expands injection and scope risk.
- Call local history a continuous third-party attestation: false authority claim.

## Consequences

Known regression snapshots can gate CI independently from environment and
methodology changes. Statistical nondeterministic regression testing remains a
separate research layer; this implementation is a deterministic contract and
does not claim superiority over published agent-regression methods.
