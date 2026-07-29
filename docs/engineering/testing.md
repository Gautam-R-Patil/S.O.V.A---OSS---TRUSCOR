<!-- status: implemented -->

# Testing strategy

SOVA treats its tests as evidence about bounded behavior, not proof of universal
security.

## Layers

| Layer | Location | Required purpose |
|---|---|---|
| Unit | `tests/unit/` | Pure functions, parser decisions, policy primitives |
| Integration | `tests/integration/` | Installed CLI and boundary-spanning behavior |
| Compatibility | `tests/compat/` | Historical schemas, migrations, and adapter contracts |
| Failure | `tests/failure/` | Deterministic faults, cancellation, partial writes, recovery |
| Performance | `tests/performance/` | Declared wall-time/output and later CPU/memory/storage budgets |
| Fixtures | `tests/fixtures/` | Content-addressed synthetic or licensed public inputs |

Later end-to-end security experiments live in a separate harness and produce
run bundles. They do not replace ordinary tests.

## Determinism

- The default seed is `20260729`.
- Override it with `SOVA_TEST_SEED` or `pytest --sova-seed`.
- Each test resets Python's pseudo-random state.
- Time-dependent production code must receive an injected clock.
- Network, model, executor, and filesystem boundaries use scripted fakes before
  live integrations.
- A failing randomized/property case records the effective seed and minimized
  input.
- `PYTHONHASHSEED=0` is set in CI before the interpreter starts.

Determinism applies to the harness and deterministic components. It does not
turn a hosted model or live external service into a deterministic system.

## Golden artifacts and compatibility

`tests/fixtures/provenance.toml` content-addresses all public fixtures. Topic 02
contains only explicit pre-schema rejection sentinels for `.sova` and
`.sova-trace`. Topics 04 and 05 add valid experimental goldens only after their
schemas are decided.

Every published stable schema version retains:

- accepted minimum, maximum, and representative artifacts;
- invalid and hostile cases;
- unknown optional extension round trips;
- unknown required feature rejection;
- migration inputs, outputs, reports, and source digests;
- historical reader tests.

Stable fixtures are immutable.

## Coverage

Production package branch coverage must be at least 95%. Coverage is a missing
test indicator, not a security score. Critical authorization, safety, parser,
integrity, redaction, and recovery code requires explicit behavioral tests even
when line coverage is already high.

## Performance and resources

Each performance test reads a versioned budget. A budget records the measured
operation, platform scope, input class, warm/cold state, sample count, statistic,
and ceiling. The bootstrap CLI uses a deliberately generous regression ceiling
to catch accidental heavyweight imports.

Later security operations separately budget wall time, CPU, memory, storage,
processes, files, network attempts, model calls, tokens, mutations, and output.
Updating a budget requires a rationale and methodology-ledger change.

## Failure injection and recovery

The deterministic `FaultPlan` raises at named checkpoints and visit counts.
The subprocess crash harness verifies process-exit and durable-file behavior.
Production components must expose meaningful checkpoints at:

- authorization and target binding;
- input verification;
- sandbox creation and teardown;
- event append, flush, seal, and signature;
- artifact write and atomic replace;
- cancellation, timeout, executor loss, and disk-full boundaries.

Tests must prove fail-closed behavior and distinguish complete, partial,
unsealed, cancelled, crashed, and recovered states.
