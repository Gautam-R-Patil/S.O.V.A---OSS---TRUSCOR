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

The source review pinned commit
`a6dd6710f5ae94e8ce825ef99df9b01d7f974b95` (`0.3.0-alpha.0` package
metadata, 2026-08-03). No matching release tag was present. The lockfile digest
is recorded by `sova executors receipts`. The Windows build failed at a Unix-only
`chmod`; the test run failed at a Windows symlink-permission case; and public
documentation did not establish Windows computer input.

The live stdio inventory exposed ten MCP tools. A computer-capability request
returned MCP transport success while the embedded MELRA task was
`policy_blocked`. The adapter therefore recognizes only internal
`verified_success`; every blocked, partial, waiting, cancelled, failed,
nonterminal, unknown, or substituted-task state is non-success.

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

Primary source: [XAGI-Lab/melra](https://github.com/XAGI-Lab/melra), especially
its `docs/CAPABILITIES.md` and `docs/THREAT_MODEL.md` at the pinned commit.
