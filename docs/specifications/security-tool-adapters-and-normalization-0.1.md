<!-- status: implemented -->

# Security-tool adapters and evidence normalization 0.1

## Scope

This specification defines how SOVA admits an external security tool without
making that tool an authorization, evidence, oracle, or finding trust root. It
covers descriptors, operator-supplied binaries, execution proposals,
authorization routing, raw-result capture, normalization, failure separation,
privacy defaults, cleanup, and trace bindings.

It does not install tools, authorize targets, provide production containment,
or establish that an upstream assertion is correct.

## Trust boundary

```text
operator inputs
  -> descriptor and byte/version/config/rules validation
  -> inert request plus ActionIntent proposal
  -> fresh authority and disclosure decisions
  -> existing Executor.process.exec capability
  -> bounded raw artifact digest
  -> versioned parser
  -> unverified observation
  -> later oracle calibration and independent reproduction
  -> possible finding promotion outside this adapter layer
```

The adapter layer MUST NOT set `findingConfirmed` or
`independentlyReproduced`. Both are structurally fixed to `false` in the
normalized-observation schema.

## Descriptor

`sova.adapter-descriptor` 0.1.0 records:

- stable adapter ID and admission tier;
- exact tool version, executable names, runtime SHA-256 requirement, licence,
  source, and release provenance;
- supported platforms and target predicates;
- capabilities, transport, network need, and maximum effect;
- output media types, output source, parser ID, and parser version;
- shell-free argument template and environment defaults;
- timeout, output, assertion, process, and network ceilings;
- accepted result exit codes, which only permit report parsing;
- template/rules/configuration catalog pins and runtime digests;
- limitations, legal notes, and fail-closed privacy defaults.

Admission tiers are:

- `promoted`: a dedicated parser and complete failure matrix exist;
- `constrained`: execution additionally needs explicit per-call opt-in and the
  tool-specific restrictions in the descriptor; and
- `legal-hold`: the runner refuses execution.

Catalog presence is not an installation, compatibility, safety, or legal
clearance claim.

## Proposal and authorization

`build_security_adapter_proposal` is inert. It validates all available bytes
and produces the exact `ActionRequest` and `ActionIntent` that approval must
bind. It performs no tool execution.

The proposal MUST fail before authorization when:

- the platform, descriptor, exact version, or captured version-evidence digest
  does not match;
- the exact executable is absent, relative, or named outside the descriptor;
- a required config/ruleset is absent or differs from its declared SHA-256;
- an output path is absolute, escapes the workspace, already exists, or lacks
  an existing parent;
- a network/provider adapter lacks an allowed disclosure decision whose target,
  destination, ID, and digest exactly match the invocation;
- a constrained adapter lacks explicit opt-in; or
- the adapter is on legal hold.

The executable is streamed through SHA-256 at proposal time. The complete
request is canonically hashed. The capability-generation digest binds the
descriptor digest, executor identity, and advertised executor capabilities.

`run_security_adapter` claims a single-use authority, records a fresh
authorization decision, verifies its intent/request/capability bindings, and
calls the existing executor only when the decision is allowed. The caller
cannot substitute an approval for a neighboring request.

## Result and failure semantics

The following remain distinct:

| State | Meaning |
|---|---|
| `tool-asserted-failure` | the parsed tool report asserted a problem |
| `tool-asserted-pass` | the parsed report asserted no failure in its tested scope |
| `informational` | inventory or non-verdict output |
| `inconclusive` | the producer did not establish a usable assertion |
| `infrastructure-failure` | execution, capture, timeout, parser, or evidence handling failed |

An accepted non-zero result exit code means only that SOVA may parse the bound
report. An exit code alone never creates an observation or finding. Timeout,
cancellation, unsupported execution, corrupt output, missing output, output
truncation, and parser rejection create infrastructure-failure observations
and MUST NOT be reported as target failures or passes.

Raw bytes are bounded and hashed. By default they are not copied into the trace
because scanner reports can contain secrets. The trace records their digest,
size, media type, completeness, and non-retention decision. Normalized metadata
is intentionally narrow; Gitleaks secret/match material and Semgrep code
fragments/metavars are not retained.

## Normalized observation

`sova.normalized-observation` 0.1.0 binds:

- descriptor and executable digests;
- exact tool and parser versions;
- target profile digest and target generation;
- raw artifact digest, media type, size, completeness, and source;
- rule, title, state, severity, confidence, location, and bounded metadata;
- actual configuration and ruleset digests;
- schema, summary, and evidence trust; and
- a semantic fingerprint excluding run and raw-encoding identity.

Semantic fingerprints permit reproduction comparison while raw digests still
prove the exact captured bytes. Equal semantic sets from two runs are a
reproduction assessment, not automatic finding confirmation.

## Generic MCP/stdio/HTTP producers

Generic producer envelopes record transport, producer, raw digest, schema
digest, summary presence, and evidence-reference count. Provider schemas,
summaries, and evidence begin `untrusted`; construction rejects attempts to
self-upgrade them. SOVA validation may later establish only the property it
actually checked.

## Privacy and supply chain

Every descriptor fixes telemetry, remote generation, uploads, implicit pulls,
auto-update, and unreviewed templates to `false`. External transfer requires a
separate human and destination-retention review; unredacted secrets are denied,
and the resulting decision digest is bound into the authorized process request.
Tool-specific environment and argv controls are defense in depth; only an
egress-enforcing worker can make a network-isolation claim.

Runtime executable, configuration, ruleset, raw output, descriptor, request,
capability generation, target profile, target generation, and trace are all
content-bound. A recorded SHA-256 establishes byte identity, not benevolence.

## Cleanup

The output path MUST be absent before execution. After capture, the runner
deletes only that exact ordinary file and verifies absence. It never recursively
deletes a directory or follows a caller-chosen cleanup tree. Cleanup failure is
terminal, is recorded in the trace, and makes the run an infrastructure
failure.

## Verification requirement

Each promoted parser MUST have positive, corruption, partial-output,
false-positive/trust, and independent semantic-reproduction fixtures. The
shared runner MUST exercise every promoted descriptor against timeout, partial
output, version drift, and cleanup failure. At least one owned end-to-end
fixture MUST demonstrate allowed authorization, one executor call, trace
creation, normalization, and verified cleanup. A denied fixture MUST show zero
executor calls.

The test evidence establishes these contracts only. It does not establish live
compatibility with every upstream binary or production-safe isolation.
