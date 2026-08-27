<!-- status: implemented -->

# P4 oracle-laboratory research refresh — 2026-08-27

## Result

SOVA should treat oracle construction as a measured lifecycle, not as a prompt or
scanner verdict. The adopted design combines held-out calibration, explicit
abstention and infrastructure states, metamorphic/differential relations,
content-addressed evidence, and independent fresh-state reproduction. No reviewed
project supplies a universal vulnerability oracle or justifies an exhaustive
security claim.

## High-confidence adaptations

- The long-established [test-oracle problem](https://discovery.ucl.ac.uk/id/eprint/1471263/)
  supports making oracle adequacy and limitations first-class evidence rather than
  assuming every target has an automatic ground truth.
- Metamorphic testing provides useful follow-up relations when a direct expected
  output is unavailable. SOVA adopts the relation pattern described in the
  [foundational survey](https://doi.org/10.1109/TSE.2013.46) and security-oriented
  applications to [web systems](https://arxiv.org/abs/1912.05278) and
  [REST APIs](https://arxiv.org/abs/2208.09505), but keeps every conclusion bounded
  to the declared relation and evidence pair.
- Hypothesis-style state-machine thinking informed the state and transition
  coverage model, while SOVA retains its own target, authority, trace, and evidence
  contracts rather than importing a second execution authority.
- PyRIT's scorer and evaluation design informed the need for versioned evaluator
  identity. An upstream report about conflating scoring failure with a blocked
  result ([PyRIT issue 2044](https://github.com/microsoft/PyRIT/issues/2044))
  reinforces SOVA's separate abstain, blocked, unsupported, inconclusive, and
  infrastructure-failure states. SOVA does not treat a provider score as truth.

## Implemented seam

The implementation uses typed, target-bound proposals and a blinded sequence in
which predictions are committed before the answer key is bound. Promotion policy
requires known-positive and known-negative evidence, zero false positives and
misses by default, ambiguous-case abstention, and infrastructure-failure
separation. Metrics include sensitivity, specificity, Wilson 95% bounds, validity
dates, and known blind spots.

Confirmation is a separate operation. It requires a promoted oracle, fresh target
generation, independent runner identity, new trace, reset receipt, environment
fingerprints, causal evidence, and all five digest-verified evidence roles. Eight
coverage dimensions preserve gaps without producing an overall safety score.

## Rejected shortcuts

- No model-generated criterion can authorize actions or confirm its own finding.
- No scanner result, LLM judge, benchmark label, log message, or replay summary is
  trusted without provenance and calibration.
- No synthetic seeded study is presented as field accuracy.
- No forced verdict is created when the result should be `no-reliable-oracle` or
  `human-review-required`.
- No coverage percentage means all workflows, surfaces, or vulnerabilities were
  found.
- No upstream code, datasets, prompts, or prose were copied or vendored for P4.

## Evidence location

The implementation is in `src/sova/oracle_lab`, its public schemas are in
`src/sova/schemas`, and its positive/adverse acceptance fixture is
`scripts/validate_p4_oracle_lab.py`. The normative boundary is in the
[P4 specification](../specifications/oracle-laboratory-reproduction-and-coverage-0.1.md).
