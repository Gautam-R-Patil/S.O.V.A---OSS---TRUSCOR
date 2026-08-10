<!-- status: experiment -->

# Community and monitoring service validation — 2026-08-09

## Implemented acceptance paths

The deterministic test lane proves:

- a standard Arena capsule and signed trace can be encoded into a bounded local
  upload document, staged through loopback HTTP, verified asynchronously,
  content-addressed, indexed, ranked, queried, and observed through SSE;
- wrong bearer tokens, untrusted evidence keys, tampered digests, path traversal,
  credential-shaped metadata, duplicate evidence, orphan-object reads, and
  service-index rollback fail closed;
- accepted queue state and the service signing identity survive restart, while
  an interrupted verification is visibly re-queued;
- a declared drift job runs on schedule, emits a signed trace, does not overlap,
  survives interrupted state, cooperatively cancels, and prunes both run
  artifacts and history to policy.

## Recorded validation result

The release-candidate workspace passed the following checks on 2026-08-09:

- `pytest`: 1,134 passed and 13 optional-integration tests skipped;
- line coverage: 95.19%, above the required 95% gate;
- focused community/monitoring tests: 30 passed with 97.85% line coverage for
  the two new service modules;
- CLI audit: all 100 command leaves executed by the automated suite;
- `mypy`: no issues in 298 source files;
- Ruff lint and format checks: clean across 448 files;
- repository confidentiality, generated glossary, generated taxonomy, and Git
  whitespace audits: clean; and
- installed `sova monitor serve --once` acceptance: the command ran against
  the public synthetic fixture, wrote durable state and a signed trace, and
  returned the policy-expected drift exit status.

The 13 skips are visible optional lanes requiring operator-provided Codex,
browser/computer-use, MELRA, Docker, or real-provider prerequisites. They are
not silently counted as successful executions.

## Bounded claim

This validates one local process and one loopback HTTP reference service under
deterministic fixtures. It does not validate an Internet deployment, public
moderation, large-scale concurrency, distributed consistency, independent
publisher identity, uptime, public adoption, or the correctness of contributed
claims.

Production hosting remains an operator deployment and independent security
review task. The reference server is deliberately loopback-only because the
Python standard library HTTP server is not recommended for production use.
