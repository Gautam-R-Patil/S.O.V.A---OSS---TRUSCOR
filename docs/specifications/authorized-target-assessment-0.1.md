<!-- status: implemented -->

# Authorized target assessment 0.1

The target contract separates portable intent from executor mechanics. Eight
target kinds declare exact versions, required capabilities, authorization
scope, and secret-free configuration. Unknown fields, nested secret-shaped
keys, missing baseline capabilities, or a trace-only target that advertises
execution fail closed.

An assessment plan is an inert content-addressed document. It identifies the
target digest, required capabilities, candidate adapters, fresh authorization,
containment/substitution, execution, independent observation, oracles, trace,
capsule, and offline verification. It is neither proof of ownership nor an
execution request.

`sova target browser-kit ORIGIN DEST` writes the target manifest, a strict
finite browser-campaign template, the inert plan, and operator instructions as
one authoring workspace. It normalizes the exact origin, rejects external HTTP,
uses no network, establishes no authorization, and keeps the generated
campaign visibly unready until its placeholders and scope are reviewed.

The deterministic website/software fixtures exercise the complete measurement
pipeline twice and compare observable outcomes. They deliberately label
`liveTargetExecuted=false`; live execution requires an exact target, explicit
authorization, admitted executor, budgets, and target-specific oracles.
