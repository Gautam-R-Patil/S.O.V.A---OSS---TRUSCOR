<!-- status: implemented -->

# Observable oracles and declared-outcome comparison 0.1

Status: experimental

Reference implementation: `sova.oracles` and `sova.reproduction`

## Purpose

An oracle evaluates a declared condition over already observed records. It does
not execute an action, infer hidden model reasoning, establish trace
completeness, or decide whether a behavior is a vulnerability.

Execution completion and behavioral outcome are separate:

- `run.completed` says the bounded procedure reached its execution terminus;
- `oracle.completed` says how the declared observable criteria evaluated;
- a finding, comparison, or research conclusion may cite that result but is a
  separately versioned object.

## Reference deterministic oracle kinds

The reference evaluator implements:

| Kind | Meaning |
|---|---|
| `exact-field` | At least one observable field at the declared JSON path equals the declared value |
| `field-contains` | At least one observable string, list, or object field contains the declared value |
| `fixture-label` | A deterministic synthetic fixture exposes the declared label or text |
| `event-present` | At least one event of the declared kind was observed |
| `execution-status` | At least one normalized executor status equals the declared status |
| `file-state` | A recorded filesystem state/effect matches declared fields |
| `process-state` | A recorded process state matches command, result, or operation |
| `network-effect` | A destination, payload class, delivery, or sink-only effect matches |
| `canary-observed` | A run-bound canary identifier appears in deterministic observations |
| `tool-invocation` | A tool/MCP invocation matches the declared operation |
| `permission-bypass` | Authorization observations match a declared bypass condition |
| `browser-state` | Recorded URL, title, state, or browser operation matches |
| `database-mutation` | A database/API mutation matches declared state fields |
| `inter-agent-handoff` | A recorded sender/recipient/message handoff matches |
| `state-transition` | A recorded state transition matches the declared state |
| `trigger-activation` | An observable trigger state matches the declaration |
| `composite` | Bounded `all`, `any`, or `not` logic over child oracles |

Paths use a deliberately small object-only form: `$` or `$.member.child`.
Unknown oracle kinds return `inconclusive`; they are never treated as passing.
Malformed registered oracle definitions fail visibly.

Each result contains:

- `pass`, `fail`, or `inconclusive`;
- expected and observed values;
- event identifiers for the evidence inspected;
- a stable method identifier and reason;
- limitations that bound the claim.

The aggregate is `fail` if any oracle fails, otherwise `inconclusive` if any
oracle is inconclusive or no oracle exists, and `pass` only when every declared
oracle passes.

## Cross-run comparison

`sova compare LEFT RIGHT` performs inert, deterministic comparison. By default
it compares `model.response` and `oracle.completed`; `--kind` selects explicit
event kinds.

Trace-local event identifiers and raw values already reduced by an oracle are
not treated as semantic differences in the `oracle.completed` projection. The
source traces retain those values for inspection. Other selected event payloads
remain exact. This is a declared-outcome comparison, not a general semantic
judge.

The command reports:

- `equivalent`, `divergent`, or `inconclusive` status plus the compatibility
  Boolean retained for simple consumers;
- both normalized outcome sequences;
- explicit evidence-loss limitations;
- the exact comparison method version.

Both source traces pass full offline structure and integrity verification
before comparison. Recorder-reported dropped events, non-full content capture,
or an absent selected event family force `inconclusive`. Missing evidence is
never converted into equality.

## Safety and limitations

- A passing oracle means only that the named rule matched the records supplied.
- An oracle cannot prove that instrumentation was complete or honest.
- A valid trace hash or signature cannot make an incorrect oracle correct.
- An `equivalent` result is bounded to the selected declared outcomes; it does
  not establish complete trace, trajectory, environment, or causal equivalence.
- `field-contains` is useful for declared benign variation such as line-ending
  differences, but authors must not use it to hide material divergence.
- Human or model judges require separate identity, calibration, uncertainty,
  input, and limitation records; they are not implemented by this evaluator.
- Repeated-trial semantic reproduction and reproduction-rate estimation remain
  separate research mechanisms and are not claimed by this 0.1 evaluator.
