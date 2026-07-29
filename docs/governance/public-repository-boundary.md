# Public repository boundary

This policy applies to every SOVA OSS commit, pull request, release artifact, example, fixture, benchmark, issue, discussion, screenshot, and generated document.

The controlling decisions are:

- [ADR-0003 — SOVA OSS and proprietary SOVA Engine boundary](../decisions/0003-open-source-and-proprietary-boundary.md)
- [ADR-0004 — SOVA OSS self-assessment and TRUSCOR authority boundary](../decisions/0004-self-assessment-and-truscor-boundary.md)
- [ADR-0005 — Topic 00 project constitution](../decisions/0005-topic-00-project-constitution.md)

## Classification

### PUBLIC

Material created for unrestricted publication:

- SOVA OSS source, specifications, schemas, migrations, tests, and documentation;
- generic algorithms and working public-data baselines cleared for release;
- synthetic fixtures and deliberately vulnerable test targets;
- public registry artifacts cleared through disclosure and safety review;
- public research whose IP and disclosure gates have passed;
- public Atlas adapter behavior sourced from public Atlas material.

PUBLIC material may be committed.

### REVIEW REQUIRED

Material that may become public only after provenance, IP, safety, and confidentiality review:

- a generic improvement first developed during private work;
- aggregate results derived from non-public experiments;
- a vulnerability finding before coordinated disclosure closes;
- a paper, benchmark, novel method, or new architecture;
- examples adapted from a real engagement;
- third-party content with uncertain redistribution terms;
- Atlas-specific behavior not already documented publicly.

REVIEW REQUIRED material must stay outside this repository until explicitly cleared.

### RESTRICTED

Material that must never enter public Git history:

- private corpus records and fitted conditioning;
- matched failure-to-loss pairs;
- client data, findings, traces, reports, or configurations;
- client-specific or confidential attack intelligence;
- TAFAAR, TRS, EAL, MPL, pricing, premium, or underwriting logic;
- counter-signature keys, attestation policy, certificate issuance, or trust roots;
- private honeypot design, placement, telemetry, or detection-avoidance methods;
- confidential Atlas documents or non-public Atlas implementation details;
- invention ledgers, patent drafts, unpublished claims, and trade-secret methods;
- credentials, tokens, private keys, browser profiles, receipts, and local evidence;
- any third-party material under NDA, embargo, confidentiality, or incompatible licence.

RESTRICTED material is never “anonymized into” this repository. Create a synthetic public fixture from first principles instead.

## Never-publish path classes

The automated boundary check rejects tracked paths representing:

- private planning, company, patent, and confidential context documents;
- `private-corpus`, `matched-loss`, `client-data`, or `client-findings`;
- `truscor-engine`, `tafa ar`, `trade-secrets`, or `internal-only`;
- private honeypot and confidential Atlas material;
- secrets, local configuration, private evidence, receipts, and browser profiles.

`.gitignore` provides local protection. The automated check independently verifies tracked paths because ignored files can still be forced into Git.

## Public fixture rule

Every public fixture and benchmark must have a reproducible provenance statement:

- `synthetic`: created solely for the public test suite;
- `public-source`: identifies the public source and licence;
- `consented-publication`: cites written authority and disclosure status;
- `generated-from-public-inputs`: identifies the public inputs and generation method.

“Anonymized client data” is not an accepted provenance class. Structural fingerprints, rare sequences, timestamps, tool names, and combinations can re-identify a system or leak a private method.

## Atlas rule

Public Atlas integration may rely only on:

- a public Atlas repository release;
- public Atlas documentation;
- a SOVA-owned executor interface;
- reproducible black-box behavior of a public release.

Do not copy or paraphrase confidential Atlas architecture, planned internals, private capabilities, security assumptions, receipts, profiles, credentials, or roadmap material into source comments, fixtures, examples, benchmarks, issues, or documentation.

When a public change makes an Atlas-specific claim, link the public source in the same document or change record.

## Private-to-public extraction

A mechanism developed during restricted work may be proposed for SOVA OSS only through this clean extraction process:

1. Describe the generic problem without private inputs.
2. Identify the author and ownership of the proposed implementation.
3. Confirm that no client or third-party restriction applies.
4. Check the invention ledger and patent/publication gate.
5. Reimplement or extract only the generic mechanism.
6. Build new synthetic or public-source fixtures.
7. Review the diff for private identifiers, constants, prompts, rankings, and comments.
8. Record the public provenance.
9. Obtain the required founder/IP approval.

Copying a private directory and deleting obvious names is prohibited.

## Pull-request checklist

Every public change must confirm:

- [ ] All changed files are intended for unrestricted public distribution.
- [ ] No secret, local configuration, private endpoint, or internal identity is present.
- [ ] No client, corpus, matched-loss, private honeypot, or restricted research material is present.
- [ ] Atlas content comes only from cited public sources or public black-box behavior.
- [ ] Fixtures are synthetic or have documented public provenance.
- [ ] Patent, paper, coordinated-disclosure, and third-party-licence gates are cleared.
- [ ] SOVA OSS outputs remain visibly first-party self-assessments.
- [ ] No TRUSCOR certificate, score, financial, underwriting, or third-party-reliance claim is implied.
- [ ] No automatic remediation or automatic upload to TRUSCOR was introduced.
- [ ] The automated public-boundary check passes.

## Incident procedure

If restricted content reaches a commit:

1. Stop pushes and releases.
2. Treat exposed credentials and keys as compromised; rotate or revoke them immediately.
3. Notify the designated repository and security owners privately.
4. Preserve an internal incident record without copying the restricted content into a public issue.
5. Determine whether Git history, caches, forks, artifacts, logs, and releases contain the material.
6. Use an approved history-rewrite and coordinated notification procedure where necessary.
7. Complete legal, client, disclosure, and security notification review.
8. Record the control failure and add a regression check.

Deleting the latest file is not sufficient because Git history and downstream clones may retain it.

## Enforcement

The repository uses:

- Apache-2.0 licensing, a preserved `NOTICE`, and machine-readable citation metadata;
- the SOVA-OSS trademark and fork-naming policy;
- Developer Certificate of Origin sign-offs for contributor provenance;
- published dual-use and coordinated-disclosure rules;
- exact and class-based `.gitignore` rules;
- `powershell -ExecutionPolicy Bypass -File scripts/check-public-boundary.ps1` on Windows, or `pwsh ./scripts/check-public-boundary.ps1` where PowerShell 7 is available;
- a pull-request template;
- CI execution of the automated check;
- staged-path and secret review before every push;
- human founder/IP review for semantic disclosure.

Automation catches known paths, markers, and common secrets. It cannot determine whether a novel algorithm or innocuous-looking constant was derived from a trade secret. Human review remains mandatory.
