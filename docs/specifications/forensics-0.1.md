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

## Validation boundary

The repository includes deterministic known-ground-truth, plausible-cause,
confounded, stochastic/incomplete, missing-sensor, and passive-frequency
baseline cases. These test the implementation and its abstention behavior. Real
model/environment calibration, independent labels, and strongest published
attribution baselines remain Research Gate 15-B work.

`sova forensics benchmark` runs five deterministic labeled cases: two clean
single-layer causes, one confounded case, one stochastic case, and one
missing-sensor case. The frozen acceptance result has 0.4 raw top-one accuracy,
1.0 selective accuracy on non-abstained cases, 0.4 supported coverage, and 1.0
decision accuracy when the three predeclared required-abstention cases are
scored as correct abstentions. The passive frequency baseline is 0.0 on this
deliberately discriminating fixture. These numbers are fixture-scoped and must
not be presented as real-system performance.
