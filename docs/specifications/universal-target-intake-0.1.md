<!-- status: implemented -->

# Universal target intake 0.1

## Purpose and boundary

Universal intake turns content-bound target materials into one deterministic,
secret-free `TargetProfile`, a provenance-separated workflow graph, an attack-
surface graph, and measured coverage. It does not execute target code, crawl a
network, establish authorization, or claim that every workflow or vulnerability
was found. Missing, changed, unsupported, and malformed evidence remains visible.

All effectful collection remains behind SOVA's existing proof-of-control,
authorization, approval, containment, budget, trace, and evidence boundaries.
The P1 command may import observations produced by an approved collector only
when `--authorize-active-observations` is explicit; importing an observation is
not proof that SOVA executed it.

## Portable profile

`target-profile-0.1.0` defines:

- stable identity, title, authorization scope, provenance, and explicit target
  kinds;
- inert URL/API/host/CIDR/package/process/agent/MCP/A2A entry points;
- supplied materials bound by exact SHA-256 digest, source class, media type,
  required/optional status, and a portable logical name;
- opaque `sova-secret:` credential references, environment requirements,
  non-secret constraints, declared boundaries, and explicit unknowns; and
- an optional exact legacy `TargetManifest` authority binding.

Profiles reject embedded credentials, secret-shaped values, credential-like
configuration keys, credential-bearing URLs, unsafe paths, floats, and other
non-canonical values. Sensitive material and browser profiles never enter a
portable profile or intake artifact.

## Input front ends

| Target surface | Content-bound inputs |
|---|---|
| Web/UI | HTML, HAR, and bounded web inventory containing pages, routes, forms, upload/download, service workers, WebSockets, storage, policy observations, and authentication transitions |
| API | OpenAPI/Swagger, GraphQL schema, gRPC proto/descriptor text, Postman collections, HAR, and state links |
| Source/package | Bounded source trees or safely inspected archives, build metadata, lockfiles, SBOMs, static entry points, binaries, configs, tests, and secret-presence observations without values |
| OCI/image | Manifest, config, layers, entry point, environment-name metadata, SBOM/scanner assertions, capabilities, mounts, ports, provenance, and runtime requirements |
| Network | Authorized inventory of hosts/CIDRs, services, protocols, TLS, DNS relationships, and segmentation observations |
| Desktop | Process generations, windows, controls, accessibility surfaces, privileges, cross-process boundaries, and declared filesystem/process/network side effects |
| AI/agent/MCP/A2A | Model/provider declarations, tools/resources, policies/prompts when supplied, memory, identities, skills, protocols, handoffs, trust boundaries, and observed consequential actions |
| Third party | Declared external boundary plus any supplied or observed interface evidence; absence stays unknown |

Readers are bounded by file count and byte limits. Archive members are inspected
without extraction; traversal paths, absolute paths, links, devices, excess size,
and excess member count fail closed. Package-controlled setup is never run.

## Graph and evidence contract

Workflow nodes cover actors, states, preconditions, observations, effects,
failures, and transitions. Surface nodes cover inputs, identities, privileges,
trust boundaries, data stores, dependencies, protocols, tool calls, and externally
controlled resources. Stable identifiers are derived deterministically.

Every projection records one evidence class:

- `declared`: supplied specification or declaration;
- `observed`: passive or explicitly authorized active observation;
- `inferred`: static or heuristic discovery that is not execution evidence; or
- `refuted`: evidence that contradicts a prior projection.

Each projection retains source material, a content digest, and decimal-string
confidence. Scanner assertions and heuristic secret detection remain observations,
not confirmed vulnerabilities.

## Coverage, drift, and failures

The report accounts separately for `declared`, `discovered`, `exercised`,
`reproduced`, `blocked`, `unsupported`, and `unknown` nodes and edges. Coverage
does not collapse unknown or unsupported work into success, and the report makes
no completeness claim.

Every material is fingerprinted before and after intake. A missing required input,
digest mismatch, mid-run change, unsafe archive, malformed required document, or
unauthorized active observation makes the result `inconclusive` and records an
explicit failure node. Target drift therefore cannot silently produce a successful
generation.

## Offline-verifiable output

One successful or inconclusive run writes transactionally:

- `target-profile.json` — the exact validated profile;
- `intake-report.json` — graphs, coverage, failures, fingerprints, and status;
- `intake.sova-trace` — a signed trace using existing trace extensions; and
- `intake.sova` — an offline-verifiable capsule containing the report and complete
  trace through existing artifact and extension rules.

## CLI

```text
sova target profile-create ID PROFILE.json --kind web --kind api \
  --authorization-scope owned-lab \
  --material openapi=openapi=supplied=api.yaml \
  --entrypoint web=url=web=https://owned.example
sova target profile-validate PROFILE.json
sova target intake PROFILE.json OUTPUT --material openapi=api.yaml
```

`--material` values passed to `profile-create` are digested immediately. Intake
rechecks each exact binding; overrides use `ID=PATH`. The command returns exit code
2 for an inconclusive intake so automation cannot mistake it for success.

## Compatibility

The normative schemas are `target-profile-0.1.0.schema.json` and
`intake-report-0.1.0.schema.json`. They use JSON Schema 2020-12, participate in the
cross-validator parity suite, and receive a new version for breaking changes.
