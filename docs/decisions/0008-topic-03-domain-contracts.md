<!-- status: decision -->

# ADR-0008: Topic 03 shared domain and version contracts

- **Status:** Accepted
- **Decision date:** 2026-07-29
- **Roadmap scope:** Topics 03.1 through 03.5 and Topic 03 exit
- **Decision owner:** Gautam R. Patil
- **Contract release:** `sova.domain` `0.1.0` (experimental)

## Context

SOVA's later schemas, executors, forensics, reports, registry, and research
results must use the same meanings. A single overloaded status or version
number would make historical interpretation impossible. A single aggregate
coverage percentage would also turn a bounded experiment into an unsupported
safety claim.

Topic 03 therefore freezes semantics and validation primitives, not the field
layout of `.sova`, `.sova-trace`, target, map, finding, or registry artifacts.
Those schemas remain owned by their ordered roadmap topics.

## Decision

### Domain vocabulary

The normative vocabulary is maintained in `docs/glossary.toml` and generated
into `docs/glossary.md`. Definitions distinguish:

- executable actors and components;
- targets, authorization, capabilities, permissions, and effects;
- attacks, conditions, triggers, attempts, runs, and campaigns;
- observations, evaluators, verdicts, findings, severity, harm, and confidence;
- evidence, integrity, provenance, redaction, and commitments;
- playback, controlled re-execution, and semantic reproduction;
- reconstruction, intervention, counterfactual reasoning, and attribution;
- standard and custom profiles, methodology, taxonomy, and observed coverage.

The Python enums in `sova.contracts.vocabulary` are the small closed subsets
needed by implementations. The glossary remains the semantic source.

### Finding lifecycle

A finding is described on five independent, append-only axes:

1. **Evidence:** `candidate`, `not-observed`, `observed`, `reproduced`,
   `verified`, `inconclusive`, or `disputed`.
2. **Disclosure:** `confidential`, `embargoed`, `disclosed`, or `published`.
3. **Remediation:** `open`, `fixed`, or `regressed`.
4. **Adjudication:** `not-required`, `pending`, `scanner-disagreement`, or
   `resolved`.
5. **Record:** `active` or `superseded`.

This prevents invalid statements such as treating publication as evidence,
treating a fix as deletion, or treating scanner agreement as independent
verification. State changes append transition events. A superseding finding
receives a new identity and cites the prior finding; the old record and its
history remain immutable.

`verified` means the named verification policy succeeded. It does not mean
universally safe, independently attested by TRUSCOR, or free from future
dispute. `not-observed` is bounded by the exact run and coverage context.

### Stable identifiers

Logical SOVA records use:

```text
sova:<kind>:<lowercase UUIDv7>
```

UUIDv7 follows RFC 9562 and provides distributed uniqueness and time-ordering
without embedding a host identity. IDs are opaque and stable across revisions.
They are not access tokens and their timestamp component is not trusted
evidence of event time.

Logical identity is separate from:

- author-declared artifact revision;
- immutable content digest;
- schema version;
- external vulnerability identifiers.

External identifiers are version-qualified relationships. CVE, CWE, CAPEC,
ATLAS, OWASP, vendor-advisory, and other identifiers never replace a SOVA ID.
A CVE link can be equivalent or related, but SOVA does not mint CVE IDs.

### Attack taxonomy

The native taxonomy is `sova.attack` `0.1.0`, experimental. Its twelve active
top-level taxa cover the complete Topic 03 attack surface. The fixed standard
profile contains every active taxon exactly once. A custom profile may use a
subset or namespaced additions, but is marked non-standard and cannot be
compared as if it were a standard run.

Taxon identifiers are permanent. Retirement retains the old entry and meaning;
an identifier is never reassigned. Compatible additions increment MINOR,
clarifications that do not change classification increment PATCH, and changed
classification semantics increment MAJOR. All mappings state the SOVA taxon's
relationship to a version-pinned external entry.

External mappings are interoperability aids, not identity or equivalence by
default. SOVA's agent-security categories deliberately cross several external
frameworks and therefore usually use `broader` or `related`.

### Coverage

Observed coverage is a vector over six frozen, declared sets:

- conditions;
- sequences;
- tools;
- capabilities;
- states;
- effects.

For dimension \(d\):

```text
observed_coverage(d) =
  |declared(d) intersect exercised(d)| / |declared(d)|
```

An empty denominator yields `not-applicable`, not zero or one. Newly discovered
surfaces are recorded as `out-of-declaration`; they do not change the frozen
denominator after a run. A later target-map revision may declare them.

The theoretical adversarial space is unbounded and is never used as the
denominator. SOVA reports the six counts and ratios, the declaration
fingerprint, the exploration budget, actual consumption, stopping rule, and
limitations. It does not calculate a universal safety percentage.

### Version context

Every later canonical artifact must be able to carry:

- its own schema name and exact version;
- taxonomy and methodology name and exact version;
- executor and adapter identity and exact version;
- model provider, model identity, provider revision, and a secret-free
  configuration fingerprint;
- target and environment fingerprints;
- judge and oracle identity and exact version;
- registry snapshot identity when registry content influenced the result.

Applicable values may not be omitted or silently defaulted. A context that
truly does not apply, was not recorded by a legacy source, or became unknown
during migration uses an explicit absence reason and explanation. Consumers
must distinguish those cases.

All governed versions use exact Semantic Versioning 2.0.0 values. Content and
configuration fingerprints use lowercase `sha256:<hex>`. Future JSON artifact
specifications may adopt RFC 8785 JCS for canonical hashing, but Topic 03 does
not prematurely choose the bytes or container of those artifacts.

## Failure semantics

The public validation layer fails closed with stable codes:

| Code | Meaning |
|---|---|
| `SOVA-CONTRACT-INVALID-VERSION` | Value is not an exact semantic version |
| `SOVA-CONTRACT-INVALID-DIGEST` | Fingerprint is not canonical SHA-256 |
| `SOVA-CONTRACT-INVALID-ID` | Logical identity is not canonical UUIDv7 form |
| `SOVA-CONTRACT-MISSING-CONTEXT` | Required context was omitted rather than explicitly classified |
| `SOVA-LIFECYCLE-UNKNOWN-STATE` | State does not belong to the selected lifecycle axis |
| `SOVA-LIFECYCLE-ILLEGAL-TRANSITION` | Transition would move across axes or rewrite history |
| `SOVA-TAXONOMY-*` | Native taxonomy, profile, retirement, or mapping contract failed |
| `SOVA-COVERAGE-*` | Denominator, budget, stopping, or dimension contract failed |

Validators never guess, coerce unknown states, fetch a remote schema, execute a
target, contact Atlas, or call a model. Unknown required behavior is preserved
for inspection but blocks execution and semantic claims under ADR-0002.

## Standards basis

The contracts reuse established work:

- [Semantic Versioning 2.0.0](https://semver.org/) for exact governed versions;
- [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562.html) for UUIDv7;
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785.html) as the future JSON
  canonicalization candidate, subject to each artifact specification;
- [CVE identifier rules](https://www.cve.org/about/Process) for external CVE
  syntax and ownership;
- [MITRE ATLAS 5.6.0](https://github.com/mitre-atlas/atlas-data/releases/tag/v5.6.0),
  [CAPEC 3.9](https://capec.mitre.org/), [CWE 4.20](https://cwe.mitre.org/),
  and the [OWASP Agentic Top 10 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
  as versioned mapping targets;
- [NIST AI RMF Measure guidance](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/)
  for documented, repeatable testing, uncertainty, conditions, and limits;
- [NIST AI 800-2 initial public draft](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.800-2.ipd.pdf)
  for explicit agent-evaluation budgets and stopping conditions.

These sources support interoperability and measurement discipline. They do not
validate SOVA findings or comparative claims.

## Research and IP review

Topic 03 combines standard taxonomy, lifecycle, versioning, identity, and
coverage practices. No novel trigger-search, causal-attribution,
semantic-reproduction, migration-proof, evidence-sealing, or sandbox mechanism
is disclosed. No patent hold is triggered.

If later research produces a new way to measure conditional search coverage,
prove semantic equivalence, or infer causal responsibility, that mechanism
must enter the private invention ledger before disclosure.

## Consequences

- Later artifacts have one terminology and one historical context contract.
- Lifecycle dimensions can evolve without destroying earlier claims.
- Standard runs are comparable only within the exact taxonomy and methodology.
- External frameworks can be mapped without controlling SOVA's native model.
- Coverage numbers are useful and honest but intentionally cannot say “safe.”
- Topic 04 and Topic 05 can now design schemas without redefining these terms.

## Topic 03 closure

- [x] Every Topic 03 term has one normative definition.
- [x] Finding lifecycle, disagreement, confidentiality, remediation,
      regression, and supersession are non-destructive and machine-tested.
- [x] Stable UUIDv7 SOVA IDs and version-qualified external references exist.
- [x] The twelve-class experimental taxonomy and external mappings validate.
- [x] Coverage uses a six-dimensional frozen denominator plus explicit budgets
      and stopping rules.
- [x] Historical interpretation context and explicit-absence semantics exist.
- [x] Source examples reconcile without treating configuration as `.sova`,
      traces as verdicts, or bounded non-observation as safety.

## Next

Begin Topic 04 using these identities, terms, taxonomy references, version
contexts, and failures. Do not weaken them inside the `.sova` schema.
