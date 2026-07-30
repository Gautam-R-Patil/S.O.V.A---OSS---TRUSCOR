# ADR-0002: SOVA versioning and lossless migration policy

- **Status:** Accepted
- **Decision date:** 2026-07-29
- **Roadmap scope:** Topic 00.3 — Version-freeze policy
- **Applies first to:** `.sova`
- **Applies by the same rules to:** Every stable SOVA machine-readable artifact family
- **Amended by:** ADR-0009; references to a `.sova` scenario now mean the
  `.sova` behavior capsule and its separately typed internal scenario object

## Decision

SOVA will make stable artifacts durable by design:

1. Every published stable schema is immutable.
2. Future SOVA releases continue to read every stable `.sova` major version.
3. Every schema change ships with an explicit, deterministic migration path when conversion is possible.
4. Migration never overwrites the source by default, never silently drops data, never fabricates unavailable information, and never weakens safety.
5. A migrated artifact records the digest of its source and the exact migration path.
6. Unknown optional data is preserved; unknown required behavior fails closed.
7. A conversion that cannot preserve source information and execution meaning is not called lossless.

The project will freeze semantic invariants now, use experimental `0.y.z` schemas while real scenarios stress the design, and declare `1.0.0` only after the evidence gate in this decision passes.

## Is the requested v1-to-v2 experience possible?

Yes, with a precise boundary.

A v2 SOVA implementation can read a v1 artifact and convert it to v2 without losing anything that v1 actually contained. It can make implicit v1 defaults explicit, reorganize fields reversibly, preserve unknown values, retain attachments byte-for-byte, and record provenance from the old digest to the new digest.

What no format can guarantee is the creation of information that never existed. If v2 introduces a new field that cannot be derived from v1:

- the converter uses an exact v1-equivalent default when the v2 specification defines one;
- otherwise it records `unknown` or `not-recorded` when the field is informational;
- if the missing value is required for safe or correct execution, conversion stops and asks for an explicit user decision.

This is not data loss. It is honest representation of missing historical information.

The stronger claim—“every arbitrary future v2 artifact can always be downgraded to v1 without loss”—is impossible if v2 uses behavior v1 cannot express. SOVA will instead support a lossless downgrade when the newer artifact stays inside the older version's feature set, and fail with an exact incompatibility report otherwise.

## Public compatibility promise

After `.sova` reaches `1.0.0`, SOVA intends to make this durable promise:

> A valid stable `.sova` artifact remains inspectable, verifiable, and forward-migratable by future SOVA releases. Migration preserves every source value, payload, attachment, ordering rule, safety constraint, oracle, and declared behavior that the destination version can represent. Missing future-only information is never invented. Any incompatibility or loss is reported before output is written.

This promise does not mean:

- converted bytes keep the same content digest;
- an old signature magically authenticates newly serialized bytes;
- a newer runtime must execute legacy behavior that is now known to be unsafe;
- an old tool can execute future required features it does not understand;
- model, provider, target, or environment drift cannot change a fresh run's outcome.

Legacy artifacts remain parseable even when execution must be blocked for a documented security reason.

## Version axes

SOVA must not overload one number with several meanings.

| Version | Meaning | Example | Controlled by |
|---|---|---|---|
| `specVersion` | Version of one artifact kind's public schema and semantics | `1.2.0` for `sova.scenario` | SOVA specification |
| `artifactVersion` | Author's revision of one logical scenario | `3.1.0` | Artifact author |
| `containerVersion` | Physical package/envelope encoding, if `.sova` becomes a multi-file container | `1.0.0` | SOVA packaging specification |
| `toolVersion` | CLI, SDK, producer, validator, or migrator release | `0.8.0` | Tool maintainer |
| `extensionVersion` | Contract version for one namespaced extension | `2.0.0` | Extension owner |
| Taxonomy, methodology, oracle, adapter, model, and target versions | Scientific and execution context | Independent values | Their respective owners |

Each artifact kind evolves independently. A `.sova` capsule at `2.0.0` does
not force its internal scenario object, `.sova-trace`, `sova-target.json`, or
`*.sova-finding.json` to use the same version.

Every canonical JSON artifact will eventually carry a common header equivalent to:

```json
{
  "kind": "sova.scenario",
  "specVersion": "1.2.0",
  "schema": "https://example.invalid/sova/schemas/scenario/1.2.0",
  "id": "sova:scenario:example/sleeper-trigger",
  "artifactVersion": "3.1.0",
  "requires": [],
  "extensions": {}
}
```

The URL above is illustrative, not a reserved SOVA domain. Topic 04 will choose the permanent schema identifier. A schema identifier never creates a runtime network dependency: stable schemas and migrations must ship with the CLI and remain usable offline.

## Release stages

### Experimental: `0.y.z`

- `0.y.z` is development territory.
- Breaking changes may occur on a minor release.
- Every published experimental revision still gets a schema, changelog, and best-effort forward migrator.
- Experimental artifacts must be visibly labelled and must not be advertised as ecosystem-stable.
- The CLI must show the effective version before execution.
- No `0.x` design is allowed to create silent behavior changes or bypass safety checks merely because it is experimental.

### Stable: `1.0.0` and later

- `1.0.0` begins the stable compatibility promise.
- A published stable specification, schema, migration definition, or conformance fixture is immutable.
- Corrections are new patch releases; files at an old version identifier are never rewritten.
- Stable readers, schemas, and migrators remain in the repository with no planned removal.
- The latest SOVA may use a newer internal model, but it must retain version adapters for every stable external representation.

### Version-number meaning

SOVA adopts the familiar `MAJOR.MINOR.PATCH` ordering and change categories from Semantic Versioning, applied to an artifact's public schema and behavior:

- **PATCH:** Clarification or compatible bug fix that does not change valid data meaning, accepted inputs, or execution results.
- **MINOR:** Backward-compatible additions or reversible changes. New behavior that an old tool cannot safely ignore must be feature-gated.
- **MAJOR:** Any incompatible schema or semantic change, including changed defaults, changed safety meaning, removed required behavior, non-reversible field transformations, or newly mandatory information with no exact old-version default.

Version numbers are not decorations. Each release defines reader, writer, migration, and failure behavior.

## Compatibility model

SOVA distinguishes four properties that are often incorrectly collapsed into “compatible.”

| Property | Question |
|---|---|
| Parse compatibility | Can the consumer safely decode and preserve the artifact? |
| Validation compatibility | Does the artifact satisfy the consumer's known schema and invariants? |
| Execution compatibility | Can the consumer execute every required feature with the specified meaning and safety controls? |
| Migration compatibility | Can the artifact be transformed to the destination version without information or semantic loss? |

A parser successfully opening a file does not imply that execution is safe.

### Reader and writer rule

SOVA always identifies both sides:

- the **writer specification** is the artifact's declared `kind` and `specVersion`;
- the **reader specification** is the version the consuming tool understands or wants to produce.

The consumer resolves the writer representation into the reader representation using a declared migration path. It never guesses based only on a filename.

### Supported-version rule

The latest SOVA release must:

- natively recognize every stable `.sova` major version;
- validate with the exact historical schema;
- migrate forward in memory for current execution without modifying the source;
- expose an explicit command to write a converted artifact;
- reject unknown major versions cleanly;
- preserve optional unknown data during read-modify-write operations;
- refuse execution when an unknown required feature is present.

## Schema-evolution rules

These rules apply from the first experimental schema so the ecosystem learns the correct behavior before `1.0`.

### Allowed compatible changes

- Add an optional field with a precise old-version-equivalent default.
- Add an informational field whose absence explicitly means `unknown` or `not-recorded`.
- Add a new namespaced optional extension.
- Add an open annotation value that consumers are required to preserve.
- Add an alias while continuing to accept and migrate the old name.
- Split presentation-only data when the transformation is exactly reversible.
- Tighten non-semantic documentation without changing validation or execution.

### Breaking changes

- Change a field's meaning while keeping its name.
- Change a field's type in a way that is not exactly and reversibly representable.
- Change the meaning of absence, `null`, zero, empty string, or an empty collection.
- Add a required field without an exact value derivable from older artifacts.
- Rename or move a field without a published transformation.
- Merge multiple source fields when the reverse mapping is ambiguous.
- Remove a value that a stable artifact may contain.
- Reuse a retired field name for a different meaning.
- Change action ordering, oracle semantics, safety behavior, or default authorization.
- Turn previously inert data into executable intent.

### Permanent reservations

Retired core field names, kind identifiers, action identifiers, enum values, extension namespaces, and semantic meanings are reserved forever. They may be recognized as deprecated, but they must never be reassigned.

### Presence is explicit

Schemas must distinguish:

- field absent;
- field present with `null`, when allowed;
- field present with a default-looking value;
- field present but intentionally redacted;
- field not recorded by the source version;
- value unknown after migration.

This prevents a converter from confusing “the author explicitly chose zero” with “v1 did not have this field.”

## Extensions and must-understand behavior

Forward compatibility fails when old software silently ignores new behavior that changes execution. SOVA therefore uses two extension classes.

### Optional extensions

- Namespaced and independently versioned.
- May add annotations, presentation hints, or behavior that does not alter core execution when ignored.
- Unknown optional extensions are retained losslessly and may be ignored.
- Read-modify-write tools must round-trip them.

### Required features and extensions

- Listed explicitly in `requires`.
- May affect execution, safety, or oracle meaning.
- A tool that does not support one must preserve it but refuse to execute, migrate semantically, or claim verification.
- No “ignore unknown and continue” behavior is allowed for required semantics.

The conformance suite will inject unknown optional and required extensions to ensure implementations preserve the first and fail closed on the second.

## Lossless migration definition

SOVA uses “lossless” only when all four conditions hold.

### 1. Source preservation

- The original artifact is never modified by default.
- Its exact bytes and digest remain available.
- A new output path is required unless the user explicitly chooses a separately designed replacement workflow with a recoverable backup.

### 2. Information preservation

- Every accepted source value is represented in the destination or retained in an opaque preservation area.
- Payload and attachment bytes keep their exact content digest.
- Unknown optional fields and extensions survive.
- Ordering that has semantic meaning survives.
- Formatting, insignificant whitespace, and JSON object-member order need not be reproduced because the unchanged original bytes remain the authoritative source for byte-level inspection.

### 3. Semantic equivalence

Under the same declared target and environment:

- action order and branching mean the same thing;
- implicit old defaults become explicit equivalent values;
- success, failure, and inconclusive conditions remain equivalent;
- safety constraints are never weakened;
- cleanup and reset behavior remain equivalent;
- no new side effect appears merely because conversion occurred.

When semantic equivalence cannot be demonstrated, the migration is classified as one-way or lossy and `--require-lossless` fails.

### 4. Evidentiary continuity

- The new artifact identifies the old kind, version, and digest.
- It records the ordered migration steps, migrator version, assumptions, warnings, and unresolved values.
- The old signature is verified against the old bytes when available.
- The converted artifact receives a new digest and must be signed separately.
- The old signature is never copied as if it authenticated the new bytes.

## Migration architecture

The reference implementation will use:

```text
versioned source bytes
        │
        ▼
strict parser for the writer version
        │
        ▼
lossless migration IR
  ├─ known semantic model
  ├─ explicit presence state
  ├─ opaque unknown-field store
  └─ content-addressed attachments
        │
        ▼
ordered adjacent transformations
  v1.0 → v1.1 → v1.2 → v2.0
        │
        ▼
destination validation + equivalence checks
        │
        ▼
new artifact + provenance + migration report
```

### Transformation rules

- Migrations are pure, deterministic, offline functions.
- No migration may call a model, Atlas, a remote registry, or the target.
- The same valid input, migrator release, destination version, and options must produce the same canonical output.
- Migrations are defined between adjacent released versions and composed in order rather than maintaining an error-prone converter for every version pair.
- Each step declares `lossless-forward`, `lossless-bidirectional`, `one-way`, or `unsupported`.
- A reverse transformation is published only when it is genuinely unambiguous.
- Failed migration writes no destination artifact.
- Migration logs cannot contain secrets or raw private target data.

### Schema and migration distribution

- Each release ships historical schemas, migration definitions, and conformance fixtures.
- Published schema and migration identifiers are immutable and content-addressed.
- The CLI never needs a live SOVA service to read or migrate an artifact.
- Registry copies are mirrors; they are not the authority for interpretation.

## Planned CLI experience

```bash
# Explain compatibility without writing anything
sova migrate scenario.sova --check

# Create a side-by-side artifact at the newest supported stable version
sova migrate scenario.sova --to latest --require-lossless

# Choose the output explicitly
sova migrate scenario.sova --to 2.0.0 --output scenario.v2.sova

# Show every transformation, default, preserved unknown, and unresolved value
sova migrate scenario.sova --to 2.0.0 --explain

# Downgrade only when every used feature is exactly representable
sova migrate scenario.v2.sova --to 1.0.0 --require-lossless
```

Default behavior:

- no in-place overwrite;
- `--require-lossless` for stable-to-stable conversion;
- clear exit codes for compatible, user-input-required, lossy, unsupported, invalid, and unsafe;
- a human-readable explanation plus a machine-readable migration report;
- no execution as part of conversion.

Running an old stable artifact does not require the user to rewrite it:

```bash
sova run scenario.v1.sova
```

The current CLI validates it with the v1 schema, migrates it in memory to the current internal representation, displays the source and effective versions, executes only if all required features are supported, and records both versions in the resulting trace.

## Sender and receiver examples

### v1 sender, v2 receiver

This is the primary compatibility case.

1. The receiver detects `specVersion: 1.x`.
2. It validates with the bundled immutable v1 schema.
3. It applies the bundled v1-to-v2 transformation.
4. It makes v1 defaults explicit, preserves source data, and lists unavailable v2-only detail as `unknown`.
5. It executes only if all v1-required semantics are supported.
6. It records the original digest and effective execution version.

The sender may also run `sova migrate` before sending. Both paths produce the same canonical v2 result when tool versions and options match.

### v2 sender, v1 receiver

1. The sender checks whether the v2 artifact uses only the v1-compatible feature subset.
2. If yes, SOVA emits a lossless v1 projection with provenance.
3. If no, downgrade fails and lists the exact unrepresentable fields or features.
4. The receiver must upgrade its tool or the sender must deliberately author a v1-compatible scenario.

SOVA never silently deletes v2 behavior to satisfy an older receiver.

## Deprecation policy

- Deprecation means “do not use for new artifacts,” not “old artifacts stop working.”
- A deprecation includes replacement guidance and a migrator where applicable.
- A stable field is not removed from historical schemas.
- Current writers may stop emitting a deprecated field after the replacement is stable.
- Current readers continue to recognize and migrate it.
- Legacy execution may be disabled only for a documented safety vulnerability; inspection, verification of historical signatures, and migration remain available.
- A withdrawn or unsafe extension remains reserved and visibly classified.
- No telemetry, account, or hosted service is required to learn that an artifact is old; the local schema bundle provides the answer.

## `1.0.0` evidence gate

SOVA must not call `.sova` stable merely because a schema file exists. Every item below is required.

### Semantic completeness

- The Topic 04.1 invariants are specified without unresolved collisions.
- Scenario identity, target binding, authorization, preconditions, actions, branching, mutation, oracles, safety, cleanup, evidence requirements, extensions, and limitations have explicit semantics.
- Absence, `null`, defaults, redaction, unknown values, and unsupported behavior are distinct.
- The public specification states what conforming readers, writers, validators, and executors must do.

### Real-scenario pressure

- The format has represented single-turn, multi-turn, persistent-state, dormant-trigger, tool/permission, file/process/network-effect, and compositional scenarios.
- The corpus includes both valid successes and expected failure/inconclusive cases.
- Representative scenarios have executed through `ScriptedExecutor` and the restricted local backend.
- At least one scenario has round-tripped across two executor implementations without changing its declared meaning.
- Atlas is not required for format stability.

### Migration proof

- At least three real experimental schema revisions have been migrated through the same public migration mechanism.
- Every retained `0.x` corpus artifact migrates to the release candidate or has a documented, explicit reason it cannot.
- Golden tests cover upgrade, compatible downgrade, one-way migration, unsupported conversion, unknown optional fields, unknown required features, and interrupted migration.
- Property tests establish parse → migrate → serialize → parse semantic equivalence.
- Repeated migration is idempotent at the same destination version.
- The full migration corpus is public and remains in regression tests.

### Independent interoperability

- Two independently implemented validator/canonicalizer paths agree on valid and invalid fixtures.
- At least two implementation languages produce the same canonical digest for the conformance corpus.
- A non-reference consumer can read the artifact without importing SOVA's engine.
- Feature negotiation and clean-failure behavior are tested between old and new tool versions.

### Security and resilience

- Strict JSON handling rejects duplicate member names, invalid Unicode, unsafe numeric ranges, malformed versions, type confusion, and ambiguous presence.
- Parser and migration fuzzing cover deep nesting, oversized values, decompression limits, path traversal, malicious attachments, and resource exhaustion.
- Unknown extensions cannot execute code or acquire ambient capabilities.
- Safety-critical new semantics are must-understand.
- Migration cannot weaken authorization, blast-radius, cleanup, or forbidden-effect constraints.
- Signatures and content digests are revalidated across the migration chain.

### Documentation and governance

- Immutable schemas, changelog, compatibility matrix, migration guide, conformance suite, threat model, and limitation statement are published.
- The `0.x` to `1.0.0` transition has an explicit release candidate and external review period.
- Every field and extension namespace has an owner and retirement rule.
- The format's publication, licensing, safety, and IP gates are cleared.
- No unresolved issue is being hidden behind a default that could change execution or evidence meaning.

If any requirement is missing, the format remains experimental.

## Reconciliation of the freeze-order conflict

Two earlier goals appeared to conflict:

- freeze `.sova` before an ecosystem depends on it;
- do not freeze a schema before real scenarios reveal what it needs.

Both are satisfied by separating **invariants**, **experimental schemas**, and **stable promotion**:

1. Freeze artifact meanings and compatibility rules now through ADR-0001 and ADR-0002.
2. Build and publish clearly experimental `0.x` schemas and tooling.
3. Stress them with real scenarios, migration rehearsals, independent implementations, and hostile inputs.
4. Freeze `1.0.0` only after the evidence gate passes.
5. Do not market, register, or encourage ecosystem dependence on a stable `.sova` standard before that point.

Public pre-alpha design work is allowed. A false stability claim is not.

## Standards basis

This policy reuses proven ideas rather than claiming a new versioning invention:

| Source | Lesson applied to SOVA |
|---|---|
| [Semantic Versioning 2.0.0](https://semver.org/) | Immutable releases, unstable major zero, and meaningful major/minor/patch changes |
| [Apache Avro 1.12.0 schema resolution](https://avro.apache.org/docs/1.12.0/specification/) | Interpret data using both writer and reader schemas; use explicit resolution rather than guessing |
| [Protocol Buffers compatibility guidance](https://protobuf.dev/programming-guides/proto3/#updating) | Preserve unknown fields, reserve retired identifiers, avoid type reuse, and test real wire behavior |
| [ProtoJSON compatibility limits](https://protobuf.dev/programming-guides/json/) | JSON does not preserve unknown data automatically, so SOVA must implement and test preservation explicitly |
| [Kubernetes storage versions](https://kubernetes.io/docs/concepts/overview/working-with-objects/storage-version/) | Keep external versions separate from an internal hub representation and convert at boundaries |
| [OpenTelemetry Schemas](https://opentelemetry.io/docs/specs/otel/schemas/) | Publish immutable versioned transformations and let producers and consumers evolve independently |
| [IETF RFC 6709](https://datatracker.ietf.org/doc/html/rfc6709) | Define interoperability and clean failure behavior; a version field without rules is insufficient |
| [JSON RFC 8259](https://www.rfc-editor.org/rfc/rfc8259) | Enforce interoperable UTF-8 JSON, unique names, and bounded numeric behavior |

## Research and IP assessment

The policy above is established compatibility engineering assembled from public standards. It is not presented as novel mathematics, a new migration algorithm, or a patent claim.

If implementation later produces a genuinely new method for proving behavioral equivalence across adversarial scenario migrations, that method must enter the invention ledger before public disclosure. Ordinary schema transforms and compatibility testing proceed as open engineering work.

## Consequences

- Topic 04 must design `.sova` as a versioned schema family, not a single frozen JSON shape.
- `sova migrate` becomes a named public CLI surface under Topic 04 tooling.
- Historical schemas and migrators become permanent release assets.
- The parser needs a lossless unknown-data representation instead of ordinary typed deserialization alone.
- The executor must distinguish “parsed” from “safe and supported to execute.”
- Traces must record source version, effective execution version, migrations, and source/output digests.
- Registry entries must declare supported versions and required features.
- Every schema proposal must include compatibility classification and migration impact.
- Major releases should be rare; compatible additions and namespaced extensions are preferred.

## Acceptance checks

- [x] Only invariants are frozen now; the field schema remains experimental.
- [x] The evidence required for `1.0.0` is explicit and testable.
- [x] Compatibility, extension, deprecation, and migration behavior is defined.
- [x] The freeze-order conflict is reconciled.
- [x] v1-to-v2 forward migration has a deterministic, non-destructive design.
- [x] The limit on inventing future-only information is explicit.
- [x] Lossless migration has a precise definition.
- [x] Unknown optional data is preserved and unknown required behavior fails closed.
- [x] Conversion retains provenance but receives a new digest and signature.
- [x] No Atlas, hosted service, model, or network call is required.
- [x] The next implementation work can remain `0.x` without creating a false stable-format promise.
