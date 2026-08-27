<!-- status: implemented -->

# Oracle laboratory, fresh reproduction, and coverage accounting 0.1

## Scope

This specification defines SOVA's boundary between an observation and a confirmed
finding. It applies to target-derived oracle proposals, calibration studies,
differential and metamorphic comparisons, decisive evidence, fresh reproduction,
and assessment coverage. It does not authorize target actions and it does not turn
missing evidence into a pass.

## Lifecycle

1. Derive a typed proposal from a target contract, specification, invariant,
   differential, metamorphic relation, state effect, log, or human acceptance
   criterion.
2. Bind the proposal to the exact target profile, evaluator version and
   configuration, evidence requirements, known blind spots, and three-way positive,
   negative, and ambiguous signals.
3. Freeze predictions on a label-free calibration task before binding the held-out
   answer key.
4. Calibrate on known-positive, known-negative, ambiguous, and infrastructure-
   failure cases. Measure false positives, misses, sensitivity, specificity, and a
   Wilson confidence interval.
5. Promote only when the predeclared policy passes. Otherwise retain `rejected`,
   `no-reliable-oracle`, or `human-review-required`.
6. Confirm a finding only after a separate runner reproduces a positive result from
   fresh target state with a new trace, reset receipt, environment fingerprints,
   causal evidence, and a complete digest-verified evidence set during the oracle's
   validity window.

The deterministic seeded study proves the lifecycle and adverse-case machinery. It
is not evidence of real-target accuracy or generalization.

## Verdict separation

Oracle and reproduction contracts preserve these terminal states independently:
`positive`, `negative`, `abstain`, `not-observed`, `unsupported`, `blocked`,
`inconclusive`, and `infrastructure-failure`. None of `not-observed`, `unsupported`,
`blocked`, `inconclusive`, or `infrastructure-failure` means passed, safe, or clean.

## Comparison contract

Predeclared differential and metamorphic relations may compare identity, role,
state, provider, version, configuration, and intervention-pair axes. Supported
relations are equality, inequality, subset, superset, nondecreasing, and
nonincreasing. A satisfied relation is evidence only for that declared pair and
does not establish universal invariance or causality.

## Decisive evidence and reproduction

A decisive evidence set requires exactly one verified, content-addressed binding
for each role: decisive cue, raw evidence, replay media, `.sova-trace`, and `.sova`
capsule. The controller validates schemas and canonical SHA-256 digests. Guest,
scanner, model, and adapter summaries cannot confirm themselves.

Fresh reproduction requires different target generations, runner identities, and
trace digests. The result is `confirmed` only for a positive verdict from a
promoted, currently valid oracle with complete evidence. Expired calibration,
incomplete evidence, stale state, or a reused runner is inconclusive.

## Coverage contract

Coverage is recorded separately for workflow, surface, playbook, state,
identity/role, adapter, oracle, and reproduction. Every named subject receives one
terminal state with evidence where required. Per-dimension ratios retain their
denominators; SOVA does not combine them into an overall safety score.

Every coverage artifact fixes these claims to false: exhaustive assessment, all
workflows understood, all attack surfaces enumerated, all vulnerabilities found,
safe/clean, unknown equals pass, not-observed equals safe, and infrastructure
failure equals pass.

## Artifacts and limits

The versioned artifacts are `sova.oracle-proposal`, `sova.oracle-calibration`,
`sova.oracle-comparison`, `sova.decisive-evidence-set`,
`sova.fresh-reproduction`, `sova.assessment-coverage`, and the three blinded-study
artifacts. Content-addressed artifacts use canonical JSON SHA-256 digests and are
validated offline before semantic use.

This contract cannot guarantee a reliable oracle for every target, exhaustive
coverage, absence of vulnerabilities, model expertise, or field performance.
