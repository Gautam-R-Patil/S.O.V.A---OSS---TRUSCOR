<!-- status: implemented -->

# Capability map and reach model 0.1

`sova map` produces a distinct `sova.map` artifact. It is an air-gapped,
read-only discovery result, not a vulnerability verdict and not proof that an
inferred path can execute.

## Inputs and collectors

The reference collector inspects agent/sub-agent manifests, MCP declarations,
tool schemas, skills, plugins, Python tool decorators, Python and JavaScript
package declarations, and explicitly supplied inventories. It skips private,
confidential, dependency, version-control, trace, browser-profile, and secret
state directories. Environment variable names may be recorded; `.env` values,
credentials, URL locators, cookies, and authentication material are not.

Static collection never executes target code. Imported runtime observations
require `--authorize-runtime-inventory` and must contain witness references.
Malformed or unsupported inputs produce limitations and partial coverage rather
than a false complete result.

## Typed graph

Nodes cover agents, sub-agents, MCP servers, tools, skills, plugins, packages,
runtimes, identities, permissions, data sources, destinations, approval gates,
external systems, and execution runtimes. Edges cover declaration, delegation,
invocation, use, grants, reads, writes, reach, egress, protection, and
dependency.

Every edge has an evidence class:

- `declared`: supplied by a manifest, schema, policy, or inventory;
- `observed`: witnessed by authorized runtime evidence;
- `inferred`: derived by a named static heuristic;
- `refuted`: evidence that a declared or inferred relation did not hold under
  the recorded conditions.

Provenance contains a relative source name, JSON/AST pointer, collector,
collection method, and digest of a redacted projection. It never contains the
original credential-bearing object.

## Provenance-separated closures

The report does not collapse graph reach into one misleading “actual access”
number. It exposes four separate path sets:

- declared closure;
- witness-linked closure, where every required edge carries runtime witnesses;
- possible closure, which may contain inference;
- conflicts, where refutation or contradictory evidence requires review.

Each finding references its node and edge identifiers and names its evidence
class. Transitive paths, credential references, egress, approval gaps,
undeclared observed relationships, and possible permission rot are findings,
not executed exploits.

## Tool-definition integrity

Approved tool definitions are canonicalized and content-addressed. A new
snapshot is compared with an immutable baseline and reports added, removed,
input-schema, entrypoint, description, and semantic-unknown changes. A textual
description change is never automatically called harmless; semantic equality
is not inferred from matching hashes or schema shape.

## Artifact and interoperability

The JSON Schema identity is `sova.map` version `0.1.0`. Paths are normalized to
authorized-root-relative POSIX form so equivalent inputs can be compared across
machines. Canonical JSON and the report content digest support exact inspection
and tamper detection. Unknown formats are reported as partial; report writers
refuse overwrite.

This graph can map to W3C PROV or SPDX relationships, but those projections are
lossy unless the destination vocabulary preserves evidence class, conditions,
witnesses, refutations, and SOVA limitations.

## Safety and claim limits

Mapping a local, self-owned declaration tree is read-only and needs no separate
offensive authorization. Runtime inventory, third-party targets, credential
resolution, or any active probe requires the governing authorization contract.
The report explicitly sets `executedVulnerability`, `safeOrClean`, and
`inferenceIsEvidence` to false.

The five-minute target is a product-performance ceiling, not a completeness or
usability claim. Current tests cover a representative local project and the
repository itself; wider real-agent usability evidence remains future work.
