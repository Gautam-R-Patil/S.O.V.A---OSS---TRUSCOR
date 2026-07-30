<!-- status: implemented -->

# `.sova-trace` event and evidence stream 0.1

## Role

A `.sova-trace` is the inert canonical record of one realized run. It records
observable requests, responses, provider-authorized summaries, tool actions,
approvals, effects, artifacts, and state transitions. It does not record
private model thoughts or prove that an observation is true.

## Event envelope

Every event records:

- `sova.event` and schema `0.1.0`;
- event and run identifiers;
- zero-based local sequence;
- open event kind and phase;
- actor and target;
- producer and recorder clock domain;
- wall-clock time, monotonic time, clock source, precision, skew estimate, and
  whether the time source is trusted;
- causal parent event identifiers;
- external/distributed links with relation, source scheme/version, fidelity,
  and trust;
- attempt identifier where applicable;
- typed payload and redaction records;
- previous event hash and current event hash.

The event vocabulary covers run, phase, attempt, actor, prompt, model, tool,
approval, memory, retrieval, MCP, inter-agent, filesystem, process,
environment, database, API, network, browser, computer, oracle, judge, finding,
attribution, authorization, safety, blocked, stop, artifact, redaction,
signature, verification, export, error, and recovery events. Namespaced `x.*`
kinds remain possible.

Sequence gives a total local writer order. Parents express recorded causal
relationships and MUST refer to earlier events in the same trace. Neither is a
proof of real-world causality. External links never participate in the local
hash chain and distributed events are never silently wall-clock sorted.

The manifest pins the `sova.event-families` registry version and digest. Each
registered family declares privacy class, lifecycle shape, Lite-profile
behavior, and export mapping. `x.*` remains the explicit extension family.

## Streaming and finalization

The writer persists canonical JSONL events into event- and byte-bounded numbered
segments. Each event is privacy-transformed, canonicalized, hash-chained, and
validated before append. `lite` is buffered, `standard` flushes and syncs at
segment boundaries, and `forensic` flushes and syncs each acknowledged event.
These modes cannot override filesystem or hardware durability behavior. Large
payloads become content-addressed blobs and duplicate bytes share one object.

Finalization packages the segments, blobs, capture/loss policy, event-registry
pin, environment/target/code/dependency/registry/model fingerprints,
recorder version, authorization result, redaction policy, and integrity
material. `completed`, `failed`, `cancelled`, `timeout`, `crashed`, `partial`,
and `recovered` all use the same trace family. Non-success is never rewritten
as success.

The writer uses a private `.partial` staging directory beside the destination
and writes secret-free recovery-session metadata. `sova recover-trace` can
retain only complete newline-terminated, schema-valid, chain-valid records,
marks the trace `recovered`, records discarded tail bytes, makes only an
observable-prefix completeness claim, and retains staging for operator review.
Other corruption fails; it is never silently repaired.

## Integrity

Covered properties:

1. object descriptors detect byte substitution;
2. the event chain detects covered insertion, deletion, modification, or
   reordering;
3. the manifest digest binds the unsigned normalized manifest;
4. an optional DSSE v1.0.2-compatible envelope signs an in-toto Statement/v1
   style statement with
   Ed25519;
5. the public key may travel with the trace for offline integrity checking.

An included key proves only that the same included key verifies the signature.
External identity requires a named trust policy and trusted key material.
Timestamp or transparency material can be digest-bound inside the signed
statement. The reference verifier reports it as present but not externally
verified. A pinned trusted-root snapshot, identity policy, and format-specific
verifier are still required. A timestamp proves digest existence under that
authority's policy, not event truth.

The reference verifier supports unsigned inspection, signature-required
verification, and exact required-key verification. Unsupported or mismatched
trust requirements fail visibly.

The separately implemented offline verifier validates archives, descriptors,
canonical manifests, event order/hash chains, and redaction structure without
importing SOVA. Its standard-library core inspects unsigned evidence; when the
optional signing dependency is available, `--require-signature` and
`--required-key-id` independently verify the DSSE/Ed25519 statement. Carried
timestamp/transparency material remains explicitly unverified.

A second dependency-free Node.js verifier implements the same bounded archive,
canonicalization, trace-chain, redaction, DSSE/Ed25519, and required-key checks
without importing either Python verifier. Cross-language agreement is tested
when Node.js is available. Neither implementation establishes observation
truth, external signer identity, freshness, or transparency inclusion.

## Offline query and playback

The reader verifies descriptors before parsing, validates every event, rebuilds
the hash chain, validates redaction placeholders/records and the manifest root,
and then builds sequence, stable-ID, kind, and actor indexes. Playback is a
deterministic text timeline and never invokes recorded actions. Native JSONL,
OTel-shaped JSONL, and explicit unsigned disclosure views are local machine
exports.

Scenario execution may emit `oracle.completed` after evaluating registered
deterministic rules over recorded observable values. Oracle pass/fail/
inconclusive is distinct from run completion. The reference rules and bounded
cross-run comparison are specified in
[observable oracles 0.1](./observable-oracles-0.1.md).
Reference-generated oracle events identify their producer as the SOVA
deterministic observer (`sova:actor:oracle`); this makes the source of the
conclusion explicit but does not make the observation independent or true.

## Partial and distributed traces

Local sequence remains authoritative inside one writer. Wall time is
contextual; clock precision and skew are explicit. Cross-process, MCP, A2A, or
OpenTelemetry correlation uses recorded links and imported trace identifiers.
Conflicting clocks are retained, not silently reordered.

Distributed merge and external timestamp/transparency verification are not
implemented in `0.1.0`. Imported order and carried verification material are
reported with their fidelity, source, and unverified status.
