<!-- status: implemented -->

# Safe rehearsal 0.1

## Preparation contract

`sova rehearse prepare SOURCE WORKSPACE` creates a new disposable workspace
outside `SOURCE`. It refuses symlinks, secret-shaped filenames, binary files,
oversized inputs, VCS metadata, dependency caches, virtual environments, and
the private tree. UTF-8 text is copied with credential-shaped assignments
replaced by typed redaction markers. The workspace records source-file digests,
omissions, sanitization counts, substitute names, and the exact non-sandbox
isolation claim without storing the source path.
Each substitute receives an empty, synthetic-fixtures-only service descriptor
and an inert ledger protocol. An action is rejected if its service family was
not prepared; no substitute can fall through to production.

The built-in `FilesystemSubstituteBackend` is one implementation of
`RehearsalIsolationBackend`. A stronger backend must still return the same
environment contract. Backend selection cannot move authorization, review,
signing, or evidence policy out of SOVA.

## Execution contract

`sova rehearse run SPEC WORKSPACE TRACE REPORT` accepts file write/delete,
process, database, API, network, browser, and computer action families. The
specification requires a task, one user-agent identity, unique action IDs, and
explicit authorization. Credential-shaped values are rejected except opaque
`sova-secret:` references and typed redaction placeholders. The built-in
backend mutates only workspace files; every other family becomes an inert,
ordered substitute ledger record.

`RehearsalAgentDriver` is the user-agent adapter boundary. It receives only a
credential-free environment descriptor and proposes portable actions under the
same gates. `ScriptedRehearsalAgent` proves the deterministic offline lane;
framework-specific user-agent adapters can implement the protocol without
turning SOVA's attacker into the task-driving agent.

`withAttack` requires a named attack profile. The attacker receives a distinct
actor ID and phase. Material browser/computer steps receive an SVG state capture
that explicitly says no production service was contacted. Success and failure
both finalize a signed `.sova-trace`. A failure records a stable error code but
not raw exception text.

## Review and export contract

The report contains a clean diff, before/after digests, ordered trace,
substitute effects, material captures, capability reach, omissions, and
limitations. Proposed changes are not approvals.

`sova rehearse export REPORT WORKSPACE STAGING --approve ID`:

- rejects unknown IDs and non-file effects;
- re-hashes file content after review and rejects drift;
- copies approved writes to a new staging tree;
- records approved deletions without deleting anything;
- rejects an existing, nested, or rehearsal destination;
- never patches production.

## Boundary

This is a real file-task rehearsal with inert service effects. It is not a
microVM, a production-equivalent digital twin, a browser automation engine, or
proof that substituted responses match a live system. Synthetic detonation
data and cloned rehearsal structure remain separately labeled.
