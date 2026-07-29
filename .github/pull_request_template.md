## Purpose

Describe the public change and why it belongs in SOVA OSS.

## Verification

List the exact local commands, platform(s), Python version(s), seed(s), and
relevant CI runs used to validate the change.

## Compatibility and documentation

- [ ] Tests cover intended, refused, failure, cancellation, and recovery behavior where applicable.
- [ ] Artifact/schema/adapter compatibility is unchanged, or the required migration and historical tests are included.
- [ ] `CHANGELOG.md`, methodology ledger, glossary, ADRs, and user/developer documentation are updated where applicable.
- [ ] Performance and resource budgets are unchanged, or the reviewed budget change and evidence are included.

## Public-boundary checklist

- [ ] Every changed file is intended for unrestricted public distribution.
- [ ] No secret, private endpoint, internal identity, client data, private trace, or corpus material is present.
- [ ] No matched-loss, private honeypot, TAFAAR, risk-scoring, underwriting, or counter-signature material is present.
- [ ] Atlas-specific content comes only from a cited public source or reproducible behavior of a public release.
- [ ] Fixtures are synthetic or have documented public provenance.
- [ ] Patent, paper, coordinated-disclosure, and third-party-licence gates are cleared.
- [ ] Every new or changed factual, comparative, legal, market, standards, or novelty claim has an active entry in the [claims register](../docs/research/claims-register.md).
- [ ] Comparative language cites a frozen protocol, exact revisions, budgets, uncertainty, and an immutable run-bundle digest.
- [ ] The [publication and IP checklist](../docs/governance/publication-and-ip-review.md) was completed for mechanism-bearing code, papers, benchmark artifacts, demos, or releases.
- [ ] This change contains no invention-hold method, benchmark answer key, unpatched exploit detail, or private/corpus-derived tuning.
- [ ] Every commit includes a Developer Certificate of Origin `Signed-off-by` line.
- [ ] Dependency and GitHub Action changes are pinned/locked, reviewed transitively, and recorded in `THIRD_PARTY_NOTICES.md`.
- [ ] SOVA OSS outputs remain visibly first-party self-assessments.
- [ ] The change does not imply a TRUSCOR certificate, score, financial conclusion, or third-party reliance.
- [ ] The change does not automatically remediate a target or upload data to TRUSCOR.
- [ ] `uv run python scripts/check_repository.py` passes.
- [ ] `pwsh ./scripts/check-public-boundary.ps1` (or the documented Windows equivalent) passes.

See [the public repository boundary](../docs/governance/public-repository-boundary.md).
