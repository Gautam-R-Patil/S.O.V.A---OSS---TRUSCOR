<!-- status: implemented -->

# MELRA executor adapter boundary 0.1

MELRA is the renamed successor to Atlas MCP/Atlas OS. Dheeraj S of XAGI Labs
built MELRA/Atlas. That contribution is acknowledged here; it does not by
itself make him an author or inventor of SOVA work.

## Boundary

MELRA may supply browser, computer, and terminal execution through the optional
adapter. SOVA retains authority over:

- `.sova`, `.sova-trace`, capture profiles, and event normalization;
- target control, human authorization, effect budgets, and containment
  admission;
- canaries, sensor requirements, deterministic oracles, evidence closure,
  judging, and findings;
- trace integrity, replay, reproduction, disclosure, and research methods.

MELRA receipts are observations, not SOVA's trust root. The adapter must
capability-probe the exact installed release and normalize its results without
promoting MELRA's own policy or verification claims.

## Verified source and live snapshot

The current source review pins public HEAD
`b9edeb35b3749de029386c929fbe8a21cc666a08` (`0.3.0-alpha.10`) and lockfile
SHA-256
`0c85260bc26947ac834ad2202d8c1ecb345cce245fac00e72393c9b064a17fc0`.
The lockfile installation and TypeScript compilation completed. MELRA's
aggregate Windows build still exits after compilation because the CLI build
script invokes Unix `chmod`.

The opt-in live SOVA adapter test passed Windows computer capability
inspection, an allowlisted terminal command, installed-Chrome navigation to a
self-owned loopback fixture, and same-process cookie reuse through a
SOVA-owned opaque profile handle. Cross-process profile persistence is not
claimed. The adapter recognizes only an exact matching plan whose internal
task status is `verified_success`; blocked, partial, waiting, cancelled,
failed, nonterminal, unknown, or substituted-task states are non-success.

Those facts are release-specific. The adapter must not rely on the confidential
target architecture or assume a roadmap capability shipped.

## Admission rules

- No MELRA call occurs without a SOVA authorization decision for that exact
  intent.
- An offensive MCP intent requires fresh destructive-level out-of-band human
  approval every invocation.
- Browser/network destinations must be explicit and owned/authorized.
- Suspected-malicious native code cannot use MELRA's ordinary host process path
  as a detonation sandbox.
- MELRA output is untrusted input to SOVA sensors and redaction.
- Rate, duration, output, mutation, and retry ceilings are enforced on both
  sides; the stricter result wins.
- Missing capabilities produce a visible unsupported result, not substitution.

Implementation and conformance are documented in
[`external-execution-broker-0.1.md`](./external-execution-broker-0.1.md) and the
Topics 12-14 engineering validation record.

The current external-executor evidence, including CUA comparison and failed
paths, is recorded in
[`external-executor-validation-2026-08-09.md`](../engineering/external-executor-validation-2026-08-09.md).

Primary source: [XAGI-Lab/melra](https://github.com/XAGI-Lab/melra), especially
its `docs/CAPABILITIES.md` and `docs/THREAT_MODEL.md` at the pinned commit.
