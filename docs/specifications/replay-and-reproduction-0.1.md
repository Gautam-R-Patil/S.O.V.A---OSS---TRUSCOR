<!-- status: implemented -->

# Replay and reproduction 0.1

## Normative modes

| Mode | Executes actions | Input | Output | Permitted claim |
|---|---:|---|---|---|
| `trace-playback` | No | integrity-valid trace | text/query or inert HTML | recorded evidence was inspected |
| `controlled-reexecution` | Yes | capsule, source trace, fresh authority | new linked trace plus drift report | a fresh run produced the reported observable result |
| `semantic-reproduction` | Outside the study function | reference and independent trial traces | counts, uncertainty, classification, sensitivity | the declared outcome recurred under the named conditions |

Mode names are stable invariants. A command or report must not silently switch
between them.

## Offline verification

`sova verify ARTIFACT` performs no execution and no network operation. It
returns one top-level state:

- `verified`: every applicable local check passed;
- `partial`: integrity is valid but signatures, pins, fingerprints, timestamp
  roots, or evidence completeness are absent or incomplete;
- `invalid`: schema, canonical package, object digest, event ordering, causal
  link, redaction, signature, or other integrity validation failed; or
- `unsupported`: the artifact is well formed but requires an unknown type or
  feature.

Trace checks cover canonical package objects, event sequence/hash chain,
causal parents, typed redaction placeholders, capture loss, environment/model/
code/dependency fingerprints, recorder signature, optional timestamp or
transparency material, and the disclosed threat model. Capsule checks cover
schema, objects, feature requirements, methodology/taxonomy pins,
authorization, safety, disclosure, licensing, and limitations.

Verification establishes tamper evidence and provenance within the documented
threat model. It does not establish recorder honesty, claim truth, safe target
behavior, or non-repudiation.

## Controlled re-execution

`controlled_reexecute()`:

1. refuses an invalid source or capsule;
2. refuses an existing destination or a destination equal to the source;
3. negotiates exact executor capabilities through `run_capsule()`;
4. records platform, Python, and executor drift without rewriting it;
5. requires fresh authorization under the ordinary SOVA executor rules;
6. writes a new `run.started` linkage to the original trace-byte digest; and
7. compares deterministic `oracle.completed` outcomes.

Synthetic fixtures embedded in a capsule reconstruct through the ordinary
content-addressed object store. External state remains an explicit precondition
and cannot be inferred from missing evidence.

## Semantic reproduction

The reference outcome is the declared observable oracle result, not token
identity or private model thought. Every trial is independently integrity
checked. Deterministic comparison decides first; an optional isolated judge is
consulted only when deterministic evidence is inconclusive.

Reports include total trials, eligible denominator, reproduced numerator,
inconclusive count, per-condition sensitivity, and a two-sided 95% Wilson score
interval. Classification is:

- `structural-under-declared-conditions`: all eligible trials reproduce and at
  least three eligible trials exist;
- `flaky-under-declared-conditions`: some but not all eligible trials reproduce,
  or too few trials support the structural label;
- `not-reproduced-under-declared-conditions`: no eligible trial reproduces; or
- `inconclusive`: evidence loss, missing events, or judge abstention prevents a
  complete denominator.

Judge calibration reports agreement, false positives, and false negatives on
labeled cases. Model-judge output is not deterministic execution evidence.

## Inspection interfaces

- `sova playback TRACE`: canonical text event timeline.
- `sova query TRACE`: filters by family prefix, actor, and sequence interval.
- `sova replay timeline SOURCE OUTPUT [--comparison TRACE] [--media VIDEO]`:
  self-contained,
  inert, scrubbable, side-by-side HTML with play/pause, speed, sensor lanes,
  recorded links, search, and synchronized evidence details. Payloads are
  inserted with `textContent`, not executed as markup.
- `sova replay capsule CAPSULE OUTPUT`: verifies the complete capsule, chooses
  its canonical `run.sova-trace`, optional `reproduction.sova-trace`, and typed
  visual-replay object, then writes the same inert application without exposing
  a manual archive extraction step. Ambiguous evidence requires exact object
  selection flags.
- `sova replay serve SOURCE [--port PORT]`: bounded loopback live-tail service
  with a random capability URL, Host-header pinning, finite SSE responses, and
  no action-execution endpoint. A live prefix is visibly unsealed until the
  finalized trace passes full verification.
- `sova replay study REFERENCE TRIAL... [--condition LABEL]`: machine-readable
  semantic report.
- `sova replay modes`: machine-readable mode definitions.

Captioned Y4M video export is available through `sova replay clip`; the
interactive evidence application is specified separately in
[evidence replay application 0.1](./evidence-replay-application-0.1.md).

## Gates

Research Gate 12-A remains **HOLD** for cross-model/cross-provider empirical
selection of outcome definitions. Patent Gate 12-B remains **HOLD** because the
public implementation contains no asserted novel reproduction mechanism.
Paper Gate 12-C remains **HOLD** until real cross-system evidence exists. Claim
Gate 12-D is closed by the explicit rejection of bit-for-bit hosted inference
claims.
