<!-- status: implemented -->

# Forensics and counterfactual attribution 0.1

## Reconstruction contract

`sova forensics reconstruct SOURCE` accepts a verified `.sova-trace` or a
normalized external event document. Native traces are verified before reading.
External documents must declare an event array and carry an explicit integrity
state; their evidence is not silently upgraded to verified.

The output schema is `sova.forensic-reconstruction/0.1.0`. It contains:

- a deterministic topological order over declared causal parents;
- local monotonic order only inside one clock domain;
- uncertain cross-clock pairs when neither causal links nor compatible clocks
  establish order;
- missing-parent, dropped-event, redaction, omitted-content, clock-trust, and
  skew-bound markers;
- decision-point labels for observable model, policy, authorization, tool,
  memory/retrieval, inter-agent, judge, and oracle activity; and
- an event identifier and available evidence digest for each statement.

All registered `.sova-trace` event families pass through the same reconstruction
path. SOVA records observable activity; it does not recover private model
thoughts or hidden chain-of-thought.

## Counterfactual contract

`sova forensics attribute STUDY.json` consumes reviewed paired trials. Candidate
layers are base model, system prompt/policy, orchestration, tool, authorization,
memory/retrieval, handoff/sub-agent, and environment/external service. Multiple
or unknown causes are output states and study labels, not invented precision.

An eligible trial must:

1. reproduce the baseline behavior;
2. change exactly the candidate layer;
3. declare the remaining context equivalent;
4. contain complete observable evidence; and
5. link the original and counterfactual traces.

Unsupported or incomplete trials become confounded, impossible, or
inconclusive. For an eligible layer, SOVA reports the prevented/persisted count,
prevention rate, Wilson 95% interval, evidence links, and competing assessments.
Support requires at least three eligible trials and a lower bound above 0.5.
This threshold is versioned engineering policy; no single rerun becomes causal
proof and no output assigns legal or organizational blame.

### Evidence-producing browser interventions

`sova forensics browser-counterfactual TARGET STUDY OUTPUT` closes the gap
between authored trial records and real execution for one deliberately narrow
case. A strict study declares exactly one non-offensive baseline message
sequence, an orchestration-layer `remove-message` intervention, and four to ten
repetitions. Each repetition runs the intervention first, then the unchanged
baseline, and freshly reproduces the baseline inside the same origin-restricted
browser session. This ordering prevents a successful baseline from skipping
the counterfactual attempt.

Every pair requires proof of target control and a freshly reviewed exact action
batch. SOVA compares recorded target, environment, code, dependency, registry,
and model fingerprints; incomplete baselines, missing reproduction, sensor
loss, or fingerprint drift make the trial ineligible. The output includes all
signed traces, the reviewed trial records, uncertainty-aware attribution, and
one offline-verifiable `.sova` capsule. Even a supported result is bounded to
the declared target, sequence, intervention, oracle, and cohort; it is not
universal causal proof.

## Validation boundary

The repository includes deterministic known-ground-truth, plausible-cause,
confounded, stochastic/incomplete, missing-sensor, and passive-frequency
baseline cases. These test the implementation and its abstention behavior. Real
model/environment calibration, independent labels, and strongest published
attribution baselines remain Research Gate 15-B work.

The implemented [blinded causal-validation
protocol](./blinded-causal-validation-0.1.md) now freezes label-free prediction
artifacts before commitment-checked scoring, supports DSSE reviewer-key pins,
reports Wilson intervals, coverage, false attribution, F1, calibration, and
abstention, and passes a stochastic synthetic fixture. This closes the missing
software/protocol path, not the external-independent-study gate: the bundled
fixture is not real-agent evidence, and a key signature does not prove reviewer
identity or independence.

`sova forensics benchmark` runs five deterministic labeled cases: two clean
single-layer causes, one confounded case, one stochastic case, and one
missing-sensor case. The frozen acceptance result has 0.4 raw top-one accuracy,
1.0 selective accuracy on non-abstained cases, 0.4 supported coverage, and 1.0
decision accuracy when the three predeclared required-abstention cases are
scored as correct abstentions. The passive frequency baseline is 0.0 on this
deliberately discriminating fixture. These numbers are fixture-scoped and must
not be presented as real-system performance.
