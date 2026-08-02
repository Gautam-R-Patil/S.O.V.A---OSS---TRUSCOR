<!-- status: researched-not-implemented -->

# MELRA executor adapter boundary 0.1

MELRA is the renamed successor to Atlas MCP/Atlas OS. Dheeraj S of XAGI Labs
built MELRA/Atlas. That contribution is acknowledged here; it does not by
itself make him an author or inventor of SOVA work.

## Boundary

MELRA may supply browser, computer, terminal, and file execution through a
future adapter. SOVA retains authority over:

- `.sova`, `.sova-trace`, capture profiles, and event normalization;
- target control, human authorization, effect budgets, and containment
  admission;
- canaries, sensor requirements, deterministic oracles, evidence closure,
  judging, and findings;
- trace integrity, replay, reproduction, disclosure, and research methods.

MELRA receipts are observations, not SOVA's trust root. The adapter must
capability-probe the exact installed release and normalize its results without
promoting MELRA's own policy or verification claims.

## Verified public snapshot

The source review pinned commit
`a6dd6710f5ae94e8ce825ef99df9b01d7f974b95` (`0.3.0-alpha.0`, 2026-07-31).
Its public documentation reports local stdio, ten MCP tools, bounded files,
terminal, browser, memory, computer operations, and durable workflows. It also
reports material limits: process restrictions are not a native OS sandbox,
receipts are not externally signed, Windows computer input and deterministic
browser replay are absent, desktop focus/post-action verification remains
roadmap work, and independent security review is pending.

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

Implementation and conformance belong to Topic 13. Topic 07/08 only freeze the
boundary and safety prerequisites.

Primary source: [XAGI-Lab/melra](https://github.com/XAGI-Lab/melra), especially
its `docs/CAPABILITIES.md` and `docs/THREAT_MODEL.md` at the pinned commit.
