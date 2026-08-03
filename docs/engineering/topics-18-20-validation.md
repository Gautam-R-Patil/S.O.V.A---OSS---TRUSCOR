<!-- status: experiment -->

# Topics 18-20 engineering validation

## Acceptance inventory

| Topic | Public implementation | Verification evidence |
|---|---|---|
| 18 preparation | credential-stripped bounded clone, omission ledger, inert substitutes, backend protocol | credential, binary, symlink/path, size, source-immutability tests |
| 18 execution/review | typed user actions, separate attacker, signed success/failure trace, digest-bound selective export | no-production vertical slice, actor, tamper, drift, malformed-report tests |
| 19 recording | allowlisted shell-free process recorder and registered adapter events | signed success, timeout, bad-event, authorization and allowlist tests |
| 19 drift | canonical environment/behavior/methodology axes | every drift class, non-comparable methodology, secret/unknown-axis tests |
| 19 sentinel/CI | local history, thresholds, SARIF/annotations, flakiness policy, reusable workflow | pass/fail, approval trigger, no-upload/no-patch, CLI tests |
| 19 integrity | explicit file baseline and verification | pass, change, missing, substitution, traversal, size/duplicate tests |
| 20 registry | content objects, signed index, lifecycle tiers, offline verifier | signature, object, taxonomy, substitution, tamper and trust-pin tests |
| 20 sync | mirror selection, immutable cache, atomic pointer | invalid-first source, first/reuse, copy limit and cached-tamper tests |
| 20 contribution | bounded local preview/staging and consent firewall | type, executable, secret, disclosure, provenance, confirm and destination tests |
| 20 adapters | benchmark, passive trace, taxonomy, SARIF import | provenance retention and malformed input tests |

## Deterministic acceptance result

The focused Topics 18-20 suite contains 43 passing tests and measures 96.78%
branch-aware coverage across the new rehearsal, monitoring, and registry
packages. The integration test executes:

```text
owned fixture
-> credential-stripped rehearsal
-> user-agent file task plus inert API effect
-> signed trace and review report
-> selective staging export
-> .sova capsule
-> known behavioral regression and CI failure
-> signed repository-of-files registry
-> offline mirror cache
-> local contribution staging
```

The original fixture digest remains unchanged; the credential file is omitted;
the API effect is a substitute ledger entry; the CI report performs no upload
or patch; registry identity is trusted only with an explicit key pin.

The final repository-wide run completed with 664 passing tests, one visible
optional Codex-lane skip because Codex was not logged in, and 95.34% total
branch-aware coverage. Ruff formatting and lint passed for the whole checkout,
and mypy passed across 208 source files. Mandatory acceptance therefore remains
offline and credential-free; no real-model result is inferred from the skip.

## Limitations and exit interpretation

- The built-in rehearsal backend is not a security sandbox and does not run
  untrusted native code.
- Service substitutes record attempts but do not yet prove live-system fidelity.
- Direct recorder coverage is process-level; other event families require an
  instrumented adapter.
- Deterministic drift is implemented; stochastic detection-power experiments
  and real model/provider comparisons are not.
- Registry transport is supplied externally (for example Git or static files);
  0.1 sync consumes verified local mirrors.
- Included signing keys provide tamper evidence, not independent identity or
  non-repudiation.

Within those declared experimental boundaries, every Topic 18-20 exit is
demonstrated. The research and IP screen remains separate from engineering
acceptance and does not convert these results into novelty claims.
