<!-- status: implemented -->

# Matched comparative benchmark protocol 0.1

`ComparativeBenchmarkProtocol` preregisters a candidate, named baselines, held-out
case identifiers, repeated trials, a seed, and an objective primary metric. Every
`BenchmarkObservation` is bound to the protocol digest and carries the exact tool,
case, trial, outcome, attempts, duration, artifact digest, environment identity, and
limitations. Evaluation rejects protocol drift, duplicate rows, unknown scope, and
silently missing trials.

The protocol deliberately distinguishes five statements:

1. the matched protocol was complete;
2. SOVA had a descriptive advantage on the objective primary metric;
3. the chosen baselines were externally verified as the strongest relevant tools;
4. uncertainty and statistical significance were established;
5. the result was independently replicated and generalized.

Only the first two can be computed from one local run. The last three remain false
until their own evidence exists. A higher pass count in a synthetic fixture is not
proof of product superiority.

Published comparisons should import or adapt held-out tasks from the strongest
applicable primary benchmark suites, including
[OSWorld](https://github.com/xlang-ai/OSWorld),
[OSWorld-V2](https://github.com/xlang-ai/OSWorld-V2), and
[Windows Agent Arena](https://github.com/microsoft/WindowsAgentArena), while
preserving those projects' licenses, task provenance, evaluation rules, and
environment constraints. Security-trigger benchmarks additionally require
objective ground-truth oracles, answer-key separation, contamination analysis,
matched budgets, and disclosure of unequal instrumentation blind spots.

The implementation is in `sova.benchmarks`. It is an evidence-accounting layer,
not a claim that those external suites have already been run or that SOVA currently
beats any competing tool.
