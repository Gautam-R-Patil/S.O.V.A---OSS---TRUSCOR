# ADR-0009: `.sova` behavior capsule and `.sova-trace` event model

- **Status:** Accepted
- **Decision date:** 2026-07-30
- **Roadmap scope:** Topics 04 and 05
- **Supersedes:** ADR-0001's scenario-only meaning for the `.sova` filename
- **Preserves:** ADR-0001's separation of scenario, trace, finding, report,
  target, and registry semantics

## Decision

`.sova` is the portable, versioned, inert-by-default **AI-behavior capsule**.
It packages or content-addresses the material needed to inspect, share,
evaluate, and—when explicitly authorized—attempt to reproduce an observed or
hypothesized AI behavior.

The capsule serves:

- AI security and vulnerability research;
- agent and model development;
- evaluations and regression testing;
- behavioral and interpretability research;
- incident response and forensics;
- audit and assurance workflows;
- academic publication and peer review;
- ordinary users who need to preserve and share a surprising behavior.

Security is an important profile, not the file's only identity.

`.sova-trace` remains the canonical low-level event and evidence stream for one
run. It may be shared alone or embedded by digest in a `.sova` capsule. A trace
is always inert and is never a hidden command stream.

## The semantic object model

The outer capsule does not erase type boundaries. It contains separately typed,
independently digestible objects:

| Object | Role |
|---|---|
| Capsule manifest | Identity, version, profile, object index, compatibility, integrity, authorship, citation, disclosure, and lifecycle |
| Scenario | Declarative interactions, conditions, parameters, mutations, expected effects, oracles, safety, cleanup, and reproduction procedure |
| Environment | OS/runtime/model/agent/tool/dependency identities, fingerprints, and safe provisioning hints |
| Trace | Ordered observed events, causal links, redactions, artifacts, completion state, and integrity material |
| Artifact | Content-addressed prompt, response, tool result, file, image, recording, fixture, or other bounded payload |
| Evaluation | Versioned oracle or judge inputs, outputs, uncertainty, and limitations |
| Finding | A lifecycle-qualified conclusion citing scenarios, traces, evaluations, and affected versions |
| Hypothesis | A falsifiable proposed explanation or trigger linked to evidence and a test plan |
| Provenance | Authorship, transformations, custody, source references, and migration lineage |
| Attestation | An optional digest-bound statement evaluated under an explicit trust policy |

The minimum viable capsule is small: a manifest and one typed object. Rich
forensic or interpretability data is optional and content-addressed. Large
objects may remain external with verified descriptors when policy permits.

## What `.sova` does and does not record

It can record the observable process surrounding a behavior:

- prompts, messages, structured outputs, and model/provider metadata;
- agent decisions that the runtime explicitly exposes;
- tool declarations, calls, approvals, results, and errors;
- memory, retrieval, protocol, filesystem, process, browser, computer, and
  network observations;
- environment and dependency fingerprints;
- test procedure, triggers, mutations, expected effects, and cleanup;
- evaluations, findings, hypotheses, annotations, and evidence references.

It does **not** claim to capture a model's private hidden chain of thought,
unobservable internal state, or metaphysical "thinking." Optional activation,
attention, attribution, probe, or intervention data may be attached when a
model/runtime legitimately exposes it, with method and limitations recorded.

## Three operations that must remain distinct

1. **Trace playback** deterministically inspects already recorded material. It
   never operates the original target.
2. **Controlled re-execution** runs a declared scenario again with explicit
   authorization, capability checks, safety limits, and a new trace.
3. **Semantic reproduction** performs one or more fresh runs and evaluates
   whether the same declared material outcome recurs. It reports conditions,
   trial counts, exclusions, uncertainty, and differences.

Exact behavior is not promised across stochastic models, provider revisions,
platforms, hardware, or unavailable dependencies.

## Packaging and safety

The experimental `0.x` representation is a deterministic ZIP-based package
with:

- `manifest.json` at the root;
- sorted, relative, normalized paths;
- content descriptors carrying media type, SHA-256 digest, and byte size;
- canonical JSON for manifests and typed JSON objects;
- bounded entry count, size, nesting, and compression ratio;
- no absolute paths, traversal, links, devices, macros, or install hooks;
- no execution during open, inspect, validate, verify, render, migrate, import,
  or registry operations.

Opening a capsule must be as safe as opening untrusted data can reasonably be:
the reader verifies structure and limits before materializing content.
Untrusted HTML, Markdown, SVG, model output, filenames, and terminal text must
be escaped by renderers.

Only an explicit run command may interpret scenario intent. It must bind a
fresh authorization decision, a compatible target, a supported executor, and
the declared safety policy. Missing must-understand features fail closed.

## Portability model

Portability means preserving declared meaning and exposing incompatibility—not
pretending every runtime is identical.

A capsule declares:

- core schema and profile;
- required and optional feature identifiers;
- executor and sensor capabilities;
- target constraints;
- model, agent, tool, protocol, and environment compatibility;
- exact, compatible, substitutable, or unavailable dependencies;
- fidelity and known limitations;
- provisioning hints that never auto-install.

`sova doctor` will report what is available. Provisioning is a separate,
explicit, reviewable operation. A receiver can always inspect the capsule
without installing its runtime dependencies.

## Capture model

Maximum adoption comes from a minimum native core plus adapters:

1. a native SOVA recording API for highest fidelity;
2. OpenTelemetry and OpenInference import/export;
3. protocol mappings for MCP, A2A, and related agent interfaces;
4. importers for evaluation and tracing ecosystems;
5. optional interpretability attachments for instrumented model runtimes.

Every import emits a fidelity report. SOVA never fabricates missing
authorization, provenance, causal, environment, or observation fields.

## Capture profiles

| Capture profile | Intended use | Default volume |
|---|---|---|
| Lite | Share a behavior or compact regression recipe | Manifest, scenario, key events, selected artifacts |
| Standard | Development, evaluation, and normal research | Full agent/model/tool timeline and environment fingerprints |
| Forensic | Incident reconstruction and security evidence | Expanded system observations, custody, integrity, and redaction records |
| Interpretability | Instrumented model research | Standard trace plus explicitly supported activations/probes/interventions |

Capsule domain profiles—security, evaluation, agent trajectory, behavioral
interpretability, incident forensics, and publication—select vocabulary and
recommended objects without changing the core package format.

## Versioning and migrations

ADR-0002 applies to the entire capsule family:

- experimental schemas remain `0.x`;
- stable schemas are immutable;
- readers use the writer schema;
- migrations are deterministic and non-destructive;
- unknown optional data is preserved;
- unknown required behavior fails closed;
- unavailable historical information is represented honestly;
- source digest, destination digest, and migration path are retained;
- signatures are never copied to changed bytes.

The logical object model is independent of the ZIP representation so a future
encoding can be introduced without changing behavior semantics.

## Integrity and trust

Content digests detect accidental or malicious byte changes. Hash-chained trace
events detect covered insertion, deletion, modification, and reordering.
Optional DSSE-compatible signatures bind a typed payload to a key. Optional
Sigstore-compatible material may be carried.

These mechanisms do not prove:

- that an observation is true;
- that an instrumented runtime was honest;
- that a signer was authorized;
- that an oracle is correct;
- that behavior is a vulnerability;
- causality or non-repudiation.

Public wording is limited to "integrity-checked," "content-addressed," or
"tamper-evident under the documented threat model."

## Privacy

The default recorder captures no raw process environment and no credentials.
Secrets are omitted structurally before persistence. Keyed commitments are
optional; unkeyed hashes of low-entropy secrets are prohibited because they
enable dictionary attacks. Encryption and selective disclosure are explicit
future profiles, not implied by redaction.

Every shared capsule declares omissions and redactions. The operator reviews
exports locally; SOVA uploads nothing automatically.

## Standards and prior art

SOVA intentionally composes established mechanisms from JSON Schema, RFC 8785,
OpenTelemetry, OpenInference, W3C Trace Context, OCI descriptors, RO-Crate,
W3C PROV, CycloneDX, in-toto, DSSE, and Sigstore.

Workflow replay, program replay, ML reproducibility, provenance-aware
execution, and tamper-evident logs have substantial public and patent prior
art. SOVA therefore makes no broad novelty claim for recording, packaging,
hashing, signing, or replaying execution. Any future novelty claim requires a
separate private gate, measured evidence, qualified counsel, and explicit
founder approval before disclosure.

## Public/proprietary boundary

The public project includes the complete specification, parser, validator,
canonicalizer, migrator, recorder, verifier, renderer, adapters, and baseline
replay/reproduction workflow for published schemas.

The separate proprietary SOVA Engine may add private intelligence, corpora,
hosted coordination, enterprise operations, fitted models, and commercial
authority. The public format never calls or depends on it. Interoperability is
not a hidden service gate.

## Consequences

- Topic 04 implements the outer capsule and typed scenario core.
- Topic 05 implements the trace/event substrate.
- Topic 06 executors consume scenarios and emit traces without changing either
  schema family.
- Existing scenario-only documents and fixtures are historical until migrated.
- Marketing must describe a portable AI-behavior capsule, not a mind-reading
  file, deterministic clone, or security-only exploit format.

## Acceptance checks

- [x] The user's expanded cross-field vision is controlling.
- [x] Scenario and trace semantics remain independently typed.
- [x] Playback, re-execution, and semantic reproduction are distinct.
- [x] Maximum adoption does not require maximum mandatory payload.
- [x] Safe inspection never executes capsule content.
- [x] Hidden chain-of-thought capture is explicitly excluded.
- [x] Interoperability uses versioned adapters and fidelity reports.
- [x] Public integrity and novelty claims are bounded.
- [x] The public implementation remains independent of SOVA Engine and Atlas.
