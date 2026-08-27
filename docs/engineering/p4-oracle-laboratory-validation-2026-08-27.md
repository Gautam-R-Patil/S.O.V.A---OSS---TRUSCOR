<!-- status: implemented -->

# P4 oracle-laboratory, reproduction, and coverage validation

- **Date:** 2026-08-27
- **Branch:** `codex/universal-target-foundation`
- **Gate:** P4-01 through P4-09
- **Result:** implementation complete; repository-wide release validation passed

## Delivered boundary

P4 adds typed, schema-validated and content-addressed contracts for proposal,
calibration, comparison, decisive evidence, fresh reproduction, and eight-
dimensional coverage. It adds a deterministic blinded seeded study with injected
false-positive and miss lanes, plus public APIs, package schemas, unit tests,
integration tests, and an acceptance receipt generator.

The normative behavior is in the
[P4 specification](../specifications/oracle-laboratory-reproduction-and-coverage-0.1.md),
and the design sources and non-adoptions are in the
[P4 research refresh](../research/p4-oracle-laboratory-research-2026-08-27.md).

## Checklist evidence

| IDs | Evidence |
|---|---|
| P4-01 | `ProposalSeed`, `OracleSource`, and `derive_oracle_proposals` cover all eight proposal sources and bind target profile plus evaluator identity/configuration without granting authority. |
| P4-02 | The three blinded-study artifacts commit task, predictions, and answer labels in order; `score_blinded_study` covers all four calibration classes. |
| P4-03 | `assess_fresh_reproduction` requires a promoted valid oracle, fresh target generation, distinct runner, new trace, reset receipt, environment fingerprints, causal evidence, and complete decisive evidence. |
| P4-04 | `ComparisonAxis`, `ComparisonRelation`, and `evaluate_comparison` cover seven axes and six differential/metamorphic relations. |
| P4-05 | `OracleCalibration` records sensitivity, specificity, false positives, misses, Wilson 95% bounds, blind spots, validity window, and exact decision reasons. |
| P4-06 | Promotion can terminate as `rejected`, `no-reliable-oracle`, or `human-review-required`; no forced positive/negative result exists. |
| P4-07 | `build_coverage_report` accounts separately for all eight dimensions with per-dimension denominators and named gaps, never an overall score. |
| P4-08 | Oracle, comparison, reproduction, and coverage enums preserve not-observed, unsupported, blocked, inconclusive, and infrastructure-failure states. |
| P4-09 | `bind_decisive_evidence` requires verified SHA-256 bindings for decisive cue, raw evidence, replay media, trace, and capsule; reproduction binds the evidence-set digest. |

## Acceptance result

The deterministic acceptance fixture produced `coreAcceptancePassed=true`, eight
proposal sources, all seven comparison axes, all eight coverage dimensions, a
promoted error-free calibration with sensitivity and specificity of 1, rejected
false-positive and miss injections, and a confirmed fresh reproduction. Its claims
retain `fieldValidated=false`, `allVulnerabilitiesFound=false`, and
`universallyReliableOracle=false`.

## Validation receipts

| Gate | Result |
|---|---|
| Focused P4 positive/adverse tests | `46 passed` |
| Focused Ruff format and lint | passed |
| Focused strict mypy | passed for 13 source files |
| Deterministic P4 acceptance | passed; receipt digest `sha256:2aa9c85dd15f13ea86fa341aebdbf27ef9976fc04c4ec6ed9693c2dba0d7c531` |
| Full repository suite | `2,407 passed, 29 skipped in 907.39s` |
| Combined statement/branch coverage | `95.04%`; mandatory 95% gate passed |
| Optional skips | 29 explicitly capability-gated browser, CUA, MELRA, Docker, gVisor, or Windows-symlink lanes; none were reported as passes |
| CLI parser-to-handler execution audit | `144/144`; no unexecuted command |
| Full Ruff format and lint | `663 files already formatted`; `All checks passed!` (local inaccessible pytest scratch directory emitted a non-fatal scan warning) |
| Full strict mypy | `Success: no issues found in 473 source files` |
| Lock, glossary, and taxonomy | 62-package lock resolved; both generated-artifact checks passed |
| Dependency audit | OSV audit of locked direct and development requirements found no known vulnerabilities |
| Wheel and sdist | built `sova_oss-0.1.0a0`; isolated wheel smoke returned `sova 0.1.0a0` |
| P4 package resources | all nine P4 schemas are present in both wheel and source distribution |
| Repository and public boundary | both passed; 789 tracked or unignored files scanned |

## Evidence interpretation

The seeded fixture validates lifecycle order, scoring, error rejection, state
separation, fresh-reproduction admission, and coverage accounting. It does not
measure arbitrary-target accuracy or provider/model performance and does not
establish production isolation. Those deployment and external-validation claims
remain P5 and P6 gates.
