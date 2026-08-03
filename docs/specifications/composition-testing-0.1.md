<!-- status: implemented -->

# Composition and emergent-chain testing 0.1

## Graph

A composition graph contains typed agents, models, tools, identities, data
stores, MCP servers, and external services. Typed edges cover declared or
observed dependency, handoff, permission, shared memory, shared-credential
metadata, cross-agent, and cross-MCP interaction. Edges may carry provenance,
observation state, risk weight, permission name, resource metadata, order, and
state condition. Raw credentials, passwords, tokens, cookies, authorization
values, and API keys are rejected recursively.

## Search and budgets

`sova compose plan GRAPH.json` produces content-addressed candidates without
execution. Strategies are connected-pair baseline, bounded t-wise, risk-guided
simple paths, and trigger-aware ordered/stateful paths. Candidate, attempt,
duration, t, and path-length ceilings are explicit and deterministic.

`sova compose evaluate STUDY.json` evaluates only already-reviewed observations
keyed by candidate digest. Missing observations remain inconclusive. Executor
mechanics, authorization, containment, and side effects are intentionally
outside the graph/search algorithm and must pass their own gates before a live
runner supplies an observation.

## Confirmation, minimization, and attribution

A positive requires `triggered=true` and complete oracle evidence. Minimization
removes one edge or component and requires a fresh confirming observation after
each removal. Removing a component also removes incident edges. The report then
re-runs element removals and records effect prevented, effect persisted, or
inconclusive under that context.

`compositionOnlyConfirmed=true` additionally requires explicit isolated
`false` outcomes for exactly every node in the successful chain. It means the
declared isolated tests did not fail; it does not establish universal innocence.
The `.sova` extension fragment packages portable component identities,
interactions, sequence, candidate digest, and limitations without credential
values or executor-specific mechanics.

## Acceptance fixture and limits

The safe deterministic fixture plants an order-dependent
memory→agent→sink-tool effect. All nodes are negative alone; the ordered chain
is positive; removing either required edge or node prevents it. This proves the
reference implementation can find and reproduce that known ground truth. It is
not evidence that risk guidance outperforms random or pairwise search on real
systems; that comparison remains Research Gate 17-A.
