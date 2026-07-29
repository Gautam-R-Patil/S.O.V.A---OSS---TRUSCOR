## Purpose

Describe the public change and why it belongs in SOVA OSS.

## Public-boundary checklist

- [ ] Every changed file is intended for unrestricted public distribution.
- [ ] No secret, private endpoint, internal identity, client data, private trace, or corpus material is present.
- [ ] No matched-loss, private honeypot, TAFAAR, risk-scoring, underwriting, or counter-signature material is present.
- [ ] Atlas-specific content comes only from a cited public source or reproducible behavior of a public release.
- [ ] Fixtures are synthetic or have documented public provenance.
- [ ] Patent, paper, coordinated-disclosure, and third-party-licence gates are cleared.
- [ ] SOVA OSS outputs remain visibly first-party self-assessments.
- [ ] The change does not imply a TRUSCOR certificate, score, financial conclusion, or third-party reliance.
- [ ] The change does not automatically remediate a target or upload data to TRUSCOR.
- [ ] `pwsh ./scripts/check-public-boundary.ps1` passes.

See [the public repository boundary](../docs/governance/public-repository-boundary.md).
