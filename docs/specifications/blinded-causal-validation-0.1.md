<!-- status: implemented -->

# Blinded causal-validation protocol 0.1

## Research question

Can SOVA's paired-intervention attribution method identify the declared causal
layer of an observable behavior, while abstaining when the evidence is
insufficient, without reading ground-truth labels before predictions are
frozen?

This protocol evaluates that question. It does not infer private model thought,
prove philosophical causation, assign human or legal blame, or turn a synthetic
benchmark into real-agent accuracy evidence.

## Three-phase protocol

1. **Prepare.** A study designer emits a label-free
   `sova.blinded-causal-study/0.1.0` and a separately held
   `sova.blinded-causal-answer-key/0.1.0`. The task contains the SHA-256 digest
   of the canonical answer core, predeclared thresholds, randomized paired
   interventions, observable outcomes, eligibility fields, and limitations.
2. **Freeze predictions.** `sova forensics blind-run TASK PREDICTIONS` accepts
   no answer-key path and emits `answerKeyLoaded: false`. It applies the same
   eligibility, uncertainty, and abstention rules used by ordinary forensics.
3. **Unblind and score.** `sova forensics blind-score` verifies task, key,
   prediction, study, case, and commitment bindings before calculating metrics.
   No result is accepted after a missing, changed, duplicated, substituted, or
   uncommitted label set.

Every artifact has a strict, bounded JSON Schema and the parser additionally
rejects unknown fields, duplicate identifiers, aggregate layers as candidates,
invalid outcomes, excessive cases/trials, and predictions that do not bind to
the exact task digest.

## Ground truth and interventions

Ground truth is an externally declared intervention target with observable
baseline and counterfactual outcomes. Eligible trials change exactly the named
layer, hold the declared context equivalent, provide complete evidence, and
link both traces. Candidate layers are model, system policy, orchestration,
tool, permission, memory/retrieval, handoff/sub-agent, and environment/service.

An external study must pre-register case construction, allocation, intervention
fidelity checks, exclusion rules, sensor requirements, sample size, and
thresholds. Blinding reduces assessment bias; it does not repair incorrect
labels, ineffective interventions, unmeasured common causes, target drift, or
non-independent trials.

## Commitment and reviewer attestation

`blind-keygen` creates separate raw Ed25519 private/public files with exclusive
creation and rollback if either half fails. `blind-sign-key` DSSE-signs the
exact unsigned answer-key document. Scoring can require the out-of-band SHA-256
public-key identifier and verifies both the DSSE payload and pin.

The commitment proves that the disclosed answer core matches the committed
bytes. The signature proves possession of the pinned private key for that
payload. Neither proves that a reviewer is a human, independent, qualified, or
correct. SOVA therefore always emits
`independentReviewerIdentityCryptographicallyVerified: false`; identity and
independence require an external governance record.

Private reviewer keys must never be committed, printed, logged, or placed in a
shared evidence capsule.

## Metrics and gates

The scorer reports top-one accuracy with a two-sided Wilson 95% interval,
decision accuracy (including predeclared correct abstentions), coverage,
selective accuracy, false-attribution rate, macro F1, supported-prediction
Brier score, per-layer precision/recall/F1, and explicit error rows. It then
evaluates the predeclared minimum-case, minimum-decision-accuracy,
maximum-false-attribution, and minimum-coverage gates.

Passing a gate means only that this frozen dataset met its declared threshold.
It is not a universal accuracy, calibration, safety, or product-superiority
claim.

## Built-in stochastic fixture

`blind-fixture` generates CPU-only Bernoulli outcomes for eight intervention
layers, randomized trial order, and periodic expected-abstention cases. Its
seed is fixed for reproducible software testing and is unsuitable for concealed
allocation. The fixture tests parsing, stochastic aggregation, metrics,
commitments, abstention, and signatures; it is not empirical AI-agent evidence.

The external exit gate requires a separately designed nondeterministic dataset,
a frozen task before prediction, an answer key held outside the prediction
process, reviewer-key pinning, intervention-fidelity review, and public reporting
of failures and exclusions. Independent review remains an external human and
institutional act.

## Threat model

The protocol detects accidental label leakage through its CLI separation and
post-freeze substitution through commitments and optional DSSE pins. It does
not resist a malicious study designer who fabricates outcomes, a compromised
host that reads both files, colluding reviewers, selective case publication,
weak randomization, mislabeled interventions, or a scorer modified before use.
Reproducible builds, separate machines/accounts, preregistration, audit logs,
and independent replication are recommended external controls.

The design is informed by controlled-trial blinding/reporting principles and
recent causal-replay work, but the current protocol makes no novelty claim:

- [CONSORT 2025 explanation and elaboration](https://www.bmj.com/content/389/bmj-2024-081124)
- [Causal Agent Replay](https://arxiv.org/abs/2606.08275)
- [CausalFlow](https://arxiv.org/abs/2605.25338)
- [TraceElephant](https://aclanthology.org/2026.acl-long.912/)
