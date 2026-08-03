<!-- status: implemented -->

# Topics 12-14 validation record

Date: 2026-08-03. This record is an engineering snapshot, not a paper, patent,
security audit, or comparative product claim.

## Deterministic lane

- Replay unit tests cover verified/partial/invalid/unsupported artifacts,
  signature presence, damaged packages, controlled re-execution immutability,
  condition drift, repeated-trial uncertainty, judge calibration, inert/XSS-safe
  rendering, and CLI mode separation.
- MCP tests cover initialization, pagination shape, bounded calls, secret-env
  rejection, malformed-server interruption, mapping, result normalization,
  status/cancel, provider-state failure, task substitution, capability fallback,
  no-session checkpoints, timeout, and cancellation.
- Cross-adapter conformance runs the same capsule through `ScriptedExecutor` and
  a deterministic MCP stdio server and obtains the same declared oracle result.
- Trigger-search tests cover all dimensions, stable grid/random baselines,
  fixed/one-pass misses, adaptive success, minimization, multi-turn reduction,
  digest-only experience, token zeroization, owned-target admission, digest-only
  attempt/browser trace events, exception cleanup, and CLI report structure.

Final local validation before release:

- 563 passed, 1 optional test skipped because official Codex was not logged in;
- 95.23% aggregate branch coverage against a 95% release threshold;
- Ruff formatting/lint: clean;
- strict mypy: 160 source/test files clean;
- source distribution and wheel: built successfully;
- repository and public-boundary checks: passed; and
- dependency audit: no known vulnerabilities, with the local unpublished
  `sova-oss` package explicitly unauditable against PyPI.

Mandatory tests require no network, model, API key, or GPU. The complete suite
includes the digest-only Phantom trace test and is rerun for the release commit.

## Live optional backend checks

### MELRA

- Repository: `XAGI-Lab/melra`
- Commit: `a6dd6710f5ae94e8ce825ef99df9b01d7f974b95`
- Package metadata: `0.3.0-alpha.0`; no matching tag observed
- Lockfile SHA-256:
  `d0556db0883d311dcb017c34a66f68fadad70db6d58f49af09aa7d539ddda1b3`
- Tool inventory: 10 MCP tools over stdio
- Windows build: failed at Unix-only `chmod`
- Windows tests: failed at a symlink-permission case after other packages passed
- Live computer capability request: MCP transport succeeded but internal task
  was `policy_blocked`; the SOVA adapter correctly returned `denied`

### Microsoft Playwright MCP

- npm version: `0.0.78`
- npm integrity:
  `sha512-XLTUeA6mEN9sQ+hJ4dfG8EIkDbxS0K3Trc2RBkUJuf02TgE2FQRNTMtq/aJfhyRMINsRl/Ybc4sxcWLtFn4/TQ==`
- Discovered tools: 24
- Isolated headless data-URL navigation with the installed Chrome executable:
  succeeded with separate post-action observation and two evidence references
- Edge default discovery failed because the package did not find the
  machine-wide executable; explicit Chrome path succeeded

### Windows-MCP

- PyPI version: `0.8.2`; MIT; Python 3.13+
- Installation: 92 packages in an isolated workspace-local uv cache
- Server configuration: stdio, `ANONYMIZED_TELEMETRY=false`, tools restricted to
  `Snapshot,Screenshot`
- Discovered/advertised SOVA capabilities: `computer.snapshot` and
  `computer.screenshot`
- Live snapshot: succeeded as a direct read observation with one evidence
  reference; payload was neither printed nor persisted

These checks establish adapter behavior on this machine only. They do not make
an MCP server a sandbox, prove general reliability, or authorize use against a
third-party target.

## Interactive replay QA

The generated HTML viewer was served only on loopback and inspected in Chrome.
It rendered two panels, four family filters, a three-position scrubber, no
horizontal overflow, and no console errors. Selecting the oracle filter showed
the original `pass` and comparison `fail` payloads side by side, while retaining
the counterfactual label. Temporary traces, page, server, and test script were
removed after the check.

## Deferred work

Paper and patent research is intentionally deferred at the user's instruction.
No public algorithm is described as novel. Real-agent comparative datasets,
external third-party reproduction, and novelty-bearing mechanisms require a
separate approved phase.
