# ADR-0005: Topic 00 project constitution

- **Status:** Accepted
- **Decision date:** 2026-07-29
- **Roadmap scope:** Topics 00.1, 00.6, and Topic 00 exit
- **Decision owner:** Gautam R. Patil

## Purpose

This is the short controlling record for SOVA OSS. It resolves the project-identity, licensing, trademark, safety, disclosure, and source-precedence decisions required before Topic 01.

Detailed artifact and boundary rules remain in ADR-0001 through ADR-0004.

## Source precedence

When project sources conflict, use this order:

1. Accepted public ADRs and governance policies in this repository.
2. The local-only correction in Amendment C of the SOVA OSS master document.
3. The non-conflicting SOVA OSS master vision.
4. Company, patent, publication, Atlas, and other context documents.

Superseded hosted-generation, hosted-conditioning, metering, account, free-tier, and server-side SOVA OSS assumptions must not enter architecture, code, tests, examples, or documentation.

## Product identity

SOVA OSS is:

- a free, local-first, open-source AI-agent security workbench;
- installed and operated by the user on systems they are authorized to test;
- account-free and without automatic telemetry;
- model-agnostic and bring-your-own-model;
- a complete public product rather than a trial or upsell funnel.

The product workflow is:

> **discover → test → capture → explain → prove → watch → share**

The research identity is:

- conditional-trigger search;
- semantic reproduction;
- adversarial evidence;
- causal attribution.

The adoption identity is:

- one install;
- no account;
- local execution;
- value within minutes;
- explicit authorization and limitations;
- polished, portable, verifiable output.

Feature overlap with other tools is allowed when it makes SOVA more complete, reliable, integrated, safe, or easy to use. Product completeness and research novelty are evaluated separately.

## Canonical artifact and version rules

- [ADR-0001](./0001-canonical-artifact-meanings.md) defines `.sova`, `.sova-trace`, target, map, finding, report, and registry meanings.
- [ADR-0002](./0002-versioning-and-lossless-migration.md) freezes versioning and migration invariants while keeping field schemas experimental.
- No artifact-name collision remains.
- `.sova` is a portable adversarial scenario, not a generic configuration or result.
- `.sova-trace` is an inert execution/evidence record.
- Stable formats are immutable and forward-migratable under the published compatibility promise.

## Public, proprietary, and trust boundaries

- [ADR-0003](./0003-open-source-and-proprietary-boundary.md) makes the complete instrument public and keeps private intelligence and commercial authority outside the repository.
- [ADR-0004](./0004-self-assessment-and-truscor-boundary.md) classifies SOVA OSS output as first-party self-assessment.
- The public runtime is **SOVA OSS Core** or **SOVA Runtime**.
- **SOVA Engine** is the separate proprietary TRUSCOR system.
- Atlas MCP is an optional, replaceable execution adapter limited to public browser, computer, and terminal interfaces.
- SOVA owns authorization, sandboxing, search, observation, judging, evidence, replay, and forensics.

## Licence decision

The repository is licensed under **Apache License 2.0**.

Why:

- unrestricted personal, academic, research, enterprise, and commercial use;
- modification, distribution, and derivative works;
- explicit contributor patent grant and patent-termination protection;
- required preservation of licence and relevant attribution notices in distributions;
- required notices on modified files;
- preservation of the repository `NOTICE`;
- no trademark grant;
- high compatibility and low adoption friction.

Apache-2.0 does not require a company that only uses the software privately without distribution to advertise TRUSCOR publicly. SOVA does not add badgeware, forced-display, non-commercial, anti-competitive, or field-of-use terms because those would damage adoption and may cease to qualify as open source.

Attribution is implemented through:

- `LICENSE`;
- `NOTICE`;
- source history and copyright notices;
- `CITATION.cff` for research and publications;
- the SOVA-OSS trademark policy;
- a request that publications cite the exact release or commit.

## Trademark and fork naming

The canonical project mark is **SOVA-OSS™**. Equivalent project stylizations and the official owl logo are covered by [`TRADEMARKS.md`](../../TRADEMARKS.md).

- Unmodified official releases may be identified as SOVA-OSS.
- Materially modified forks must use a distinct primary name and visual identity.
- Forks may truthfully state “based on SOVA-OSS,” “powered by SOVA-OSS,” or “a fork of SOVA-OSS.”
- Nominative reference, compatibility claims, commentary, research, and publication are allowed without implying endorsement.
- A fork may not present itself as official, use the official owl as its primary mark, or imply TRUSCOR review or attestation.
- This decision does not claim verified registration status; use ™ rather than ® until evidence and counsel support otherwise.

Trademark controls identity, not the right to fork the Apache-licensed code.

## Contributor decision

Contributions use Apache-2.0 inbound licensing and the Developer Certificate of Origin 1.1.

- Contributors retain their copyright.
- Every commit is signed off with `Signed-off-by`.
- No contributor copyright assignment is required.
- Public provenance and confidentiality rules are mandatory.
- Private vulnerabilities use `SECURITY.md`, not public issues.

## Dual-use decision

[`DUAL_USE_POLICY.md`](../../DUAL_USE_POLICY.md) is approved as official project governance.

The policy does not add a field-of-use restriction to Apache-2.0. It governs official contributions, registry content, infrastructure, marks, support, and release safety.

Launch-blocking controls remain:

- self-only default scope;
- explicit out-of-band human authorization for every offensive MCP invocation;
- non-destructive proof;
- blast-radius enforcement and hard stops;
- no autonomous offensive invocation;
- no unpatched exploit payload in the registry;
- signed provenance and human review;
- no automatic telemetry or target/finding upload.

Qualified legal review remains required before the first promoted executable offensive release or registry submission. It does not block Topic 01 repository design.

## Coordinated-disclosure decision

[`SECURITY.md`](../../SECURITY.md) is the approved reporting and disclosure policy.

- private reporting to `gautam@truscor.org`;
- acknowledgement target of 3 business days;
- initial-triage target of 7 business days;
- update target of 14 days while active;
- default 90-day coordinated-disclosure period;
- one extension up to 14 days for an imminent fix;
- accelerated disclosure as short as 7 days for credible active exploitation;
- multi-party coordination flexibility;
- no public unpatched payload merely because a deadline expires;
- reporter credit when requested and possible.

This policy authorizes no testing of TRUSCOR, XAGI Labs, Atlas, GitHub, or third-party infrastructure.

## IP reconciliation

The hosted-conditioning premise is withdrawn from SOVA OSS.

- SOVA OSS publishes the complete local architecture and generic trigger-search mechanisms.
- The user supplies models, compute, keys, targets, and optional public registry content.
- TRUSCOR runs no SOVA OSS generation or conditioning service.
- Private corpus-conditioned intelligence, if developed, belongs only to the separate proprietary SOVA Engine and private environment.
- The public repository never calls that private capability.
- Generic public mechanisms follow their paper, patent, defensive-publication, and safety gates before disclosure.
- Confidential data-derived conditioning remains a trade-secret candidate by default.
- A public commit is treated as publication; already disclosed material is never assumed still patentable.
- Patentability and ownership require qualified counsel and current facts.

This reconciliation supersedes patent-strategy statements that depend on SOVA OSS payload generation or conditioning running on TRUSCOR servers. It does not disclose private algorithms, fitted values, data, or patent claims.

## Decision basis

The Topic 00 decisions were checked against:

- the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0), especially copyright, patent, redistribution, notice, and trademark terms;
- the [Open Source Definition](https://opensource.org/osd), including free redistribution, derived works, and no field-of-use discrimination;
- the [Developer Certificate of Origin 1.1](https://developercertificate.org/);
- GitHub's [`CITATION.cff` integration](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-citation-files);
- [CISA vulnerability-disclosure guidance](https://www.cisa.gov/news-events/news/cisa-issues-final-vulnerability-disclosure-policy-directive-federal-agencies);
- [CERT/CC disclosure guidance](https://www.kb.cert.org/vuls/guidance/);
- [FIRST multi-party vulnerability-coordination guidance](https://www.first.org/global/sigs/vulnerability-coordination/multiparty/guidelines-v1-1);
- the official [IP India trademark-search gateway](https://www.ipindia.gov.in/trade-marks-before-you-apply-search-existing-trademarks).

These sources support the governance design but do not replace jurisdiction-specific legal advice.

## Repository controls

Topic 00 establishes:

- [the public repository boundary](../governance/public-repository-boundary.md);
- automated boundary scanning in CI;
- `.gitignore` denylist protections;
- pull-request confidentiality and provenance checks;
- `CODEOWNERS` review for governance and future high-risk surfaces;
- Apache `LICENSE` and durable `NOTICE`;
- citation metadata;
- contributor, trademark, dual-use, and disclosure policies.

Automation is a backstop. Founder/IP review remains mandatory for semantic disclosure.

## Topic 00 closure

- [x] Product, research, and adoption identities are recorded.
- [x] Artifact names and meanings are unambiguous.
- [x] Version-freeze and migration policy is accepted.
- [x] SOVA OSS, proprietary SOVA Engine, TRUSCOR, and Atlas boundaries are explicit.
- [x] The public/private boundary is machine-checkable.
- [x] Apache-2.0 is selected and applied.
- [x] Attribution and academic citation paths exist.
- [x] SOVA-OSS trademark and fork-naming policy is approved.
- [x] Contributor provenance policy is approved.
- [x] Dual-use policy is approved.
- [x] Coordinated-disclosure and embargo rules are approved.
- [x] Hosted-conditioning assumptions are reconciled with the local-only architecture.
- [x] Topic 01 may proceed without importing a superseded hosted tier.

## Next

Begin Topic 01.1 with the claims register and evidence-control process. Do not reopen Topic 00 implicitly; propose a new ADR when a controlling decision must change.
