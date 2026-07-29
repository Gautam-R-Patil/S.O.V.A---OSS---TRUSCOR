<!-- status: implemented -->

# Observed coverage model

SOVA reports what a bounded run exercised. It does not estimate the percentage
of all possible attacks that were ruled out.

## Frozen denominator

Before execution, mapping and profile selection freeze six declared sets:

| Dimension | Examples |
|---|---|
| Conditions | input class, identity, invocation count, time, environment predicate |
| Sequences | named ordered interaction or mutation path |
| Tools | callable tool identities exposed in scope |
| Capabilities | file read, process spawn, payment initiation, delegated send |
| States | memory snapshot, permission state, browser state, conversation phase |
| Effects | file write, process start, network egress, external publication |

For each dimension:

```text
covered = declared intersect exercised
ratio = count(covered) / count(declared)
```

If `declared` is empty, the ratio is `not-applicable`. An observed but
undeclared item is listed under `out-of-declaration`; it does not inflate or
retroactively expand the denominator. A later target-map version can add it.

Reports publish each numerator, denominator, exact ratio, uncovered set, and
out-of-declaration set. They do not average the six dimensions into an overall
score unless a future, independently versioned methodology explicitly
predeclares and validates such an aggregation. No aggregation may be labelled
“percent safe.”

## Exploration budget

At least one limit is declared before a run:

- attempts;
- wall-clock milliseconds;
- model tokens;
- monetary microunits;
- executor actions.

The trace records limits and actual consumption. Exploration stops with one
named reason:

- `budget-exhausted`;
- `objective-reached`;
- `no-improvement-window`;
- `operator-cancelled`;
- `safety-stop`;
- `executor-failure`.

The stopping detail is mandatory. “No improvement” must name its window and
metric in the methodology. Cancellation, safety stop, and executor failure are
not successful completion.

## Theoretical space

The theoretical attack space includes unbounded text, tool outputs, histories,
timing, state, environment, model variation, and compositions. Its size is
unknown and is not a legitimate denominator. Standard-profile completeness
means all active taxonomy classes were eligible under the exact profile; it
does not mean every input or trigger in those classes was tested.

## Interpretation example

```text
conditions:   8 / 12
sequences:    5 / 5
tools:        3 / 4
capabilities: 6 / 9
states:       4 / 7
effects:      5 / 6
stop:         budget-exhausted at 200 attempts
limitation:   browser profile state was not explored
```

This is a useful result. It is not `73% safe`, and SOVA will not render it as
one.
