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

### Provider-assisted agent run

`sova rehearse agent-run REQUEST PROVIDER_RUNTIME WORKSPACE OUTPUT
--allow-provider-calls` adds a credential-late, tool-free planning lane. It is
optional; the SOVA core and mandatory tests do not require a provider, network,
or API credential.

The request declares a task, SOVA-owned agent identity, maximum action count,
and exact workspace-disclosure bounds. SOVA inventories only regular files in
the already prepared workspace. Rehearsal control files are never disclosed.
The default disclosure is metadata-only: normalized paths, byte sizes, and
SHA-256 digests. Text content is included only after explicit opt-in, within
per-file and total-byte ceilings, and after capture-time credential redaction.
The terminal shows the complete disclosure summary and requires an exact
digest-bound phrase before the first provider call.

The provider receives one strict JSON contract and no browser, computer,
terminal, target, filesystem, or host tools. Its response must contain only a
non-empty bounded action list with exact fields. SOVA assigns the actor ID,
rejects unknown kinds and fields, validates every normal rehearsal invariant,
rejects credential-shaped output, and fails closed on forbidden tool calls,
invalid usage, or configured token-budget uncertainty. Provider prose and
private reasoning are neither required nor claimed. Only observable structured
output is considered, and that output is untrusted planning data.

After validation, SOVA displays the complete action plan and requires a second
exact phrase bound to the canonical plan digest. No plan effect occurs before
that review. Approved file effects remain inside the prepared disposable
workspace; non-file effects remain inert substitute ledger entries. Planning
and execution use the same ephemeral signing key and produce separate signed
traces. A `.sova` capsule packages the portable plan, request, and both traces;
the report records disclosure, usage metadata, hashes, claims, and limitations.

`maxTotalTokens` remains fail-closed: when configured, missing adapter-reported
usage or an exceeded limit aborts the run. `maxModelTurns` must admit the one
strategist invocation. Provider availability, plan quality, and cross-provider
equivalence remain optional external validation results, never mandatory CI
claims.

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
