# ADR-0003: SOVA OSS and proprietary SOVA Engine boundary

- **Status:** Accepted for scope
- **Decision date:** 2026-07-29
- **Roadmap scope:** Topic 00.4 — Open/private boundary
- **Founder decisions still open:** Repository licence, contributor terms, and trademark policy

## Decision

SOVA will use a three-layer boundary:

1. **The instrument is open.** SOVA OSS contains the complete local architecture and every user-facing security workflow promised by the project.
2. **Learned intelligence stays private.** TRUSCOR retains data, tuning, prioritization, and operational knowledge learned from confidential or proprietary activity.
3. **Independent authority is commercial.** The proprietary SOVA Engine and TRUSCOR services add separately governed operation, review, accountability, and any future relied-upon outputs that a self-operated tool cannot create.

The public project must be genuinely useful, auditable, local-first, extensible, and non-crippled. It must not depend on a TRUSCOR service or hide an essential implementation behind an account, feature flag, proprietary plugin, or network call.

The proprietary system must not be stored in this repository. It may consume released SOVA OSS packages and artifacts through stable public interfaces, but the dependency direction is one-way:

```text
SOVA OSS public repository
  specifications • runtime • adapters • evidence • self-assessment
                         │
                         │ stable public interfaces
                         ▼
TRUSCOR private systems
  private intelligence • independent operation • commercial authority
```

SOVA OSS never imports, downloads, or requires a private TRUSCOR module. The private system may depend on the public project; the public project may not depend on the private system.

## The unavoidable open-source truth

It is impossible to publish genuine open-source software while guaranteeing that nobody can inspect, modify, fork, redistribute, or commercially use it.

The [Open Source Definition](https://opensource.org/osd) requires licences to permit derived works and forbids restrictions on fields of endeavour. The [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) expressly permits reproduction, derivative works, sublicensing, and distribution. A competitive-use prohibition would make the project **source-available**, not open source.

Therefore SOVA will not claim:

- that the public architecture cannot be reverse-engineered;
- that a capable team cannot build a competing scanner from a fork;
- that an open-source licence can prohibit commercial competition;
- that obfuscation, withheld build steps, or intentionally weak defaults protect TRUSCOR;
- that the proprietary advantage is simply “better private code.”

The honest position is:

> A fork can clone the public instrument. It does not inherit TRUSCOR's private intelligence, independent authority, accumulated record, relationships, or protected identity.

Competitors may independently build comparable assets over time. The boundary creates a head start and a structurally different product; it is not a monopoly guarantee.

## Canonical product names

Naming must make the separation unmistakable.

| Name | Meaning | Repository status |
|---|---|---|
| **SOVA OSS** | Free, local-first agent-security toolkit operated by the user on systems they are authorized to test | Public |
| **SOVA OSS Core** or **SOVA Runtime** | Public orchestration, validation, evidence, and execution-control code | Public |
| **SOVA Engine** | TRUSCOR's separate proprietary adversarial assessment system | Never a public package or class name |
| **TRUSCOR** | Company providing independent assessment, attestation, risk products, and related commercial services | External to this repository |
| **Atlas MCP** | Separate XAGI Labs execution runtime used only through an optional adapter | External dependency; public interface details only |

The public codebase must not create a package, binary, class, service, or marketing label named `SOVAEngine` or `sova-engine`. Use `sova-core`, `sova-runtime`, or a specific subsystem name. This prevents users from mistaking a self-operated OSS run for the proprietary TRUSCOR system.

## What SOVA OSS includes

SOVA OSS includes the full user-facing product described by the SOVA OSS roadmap. “Open” applies to working implementations, not only interfaces.

### Formats and interoperability

- `.sova`, `.sova-trace`, target, map, finding, report, and registry specifications;
- validators, parsers, canonicalizers, formatters, migrations, and conformance suites;
- integrity, provenance, signing, redaction, verification, and disclosure formats;
- SDKs, local MCP tools, CLI commands, and extension contracts.

### Local security workflows

- agent, tool, MCP, skill, identity, permission, egress, and transitive-reach mapping;
- static and dynamic checks;
- controlled detonation, composition, rehearsal, probe, and local arena workflows;
- generic conditional-trigger search and working public baselines;
- attacker, judge, mutator, oracle, and executor extension points;
- scripted and restricted-local executors plus optional public adapter contracts;
- deterministic sensors and file, process, permission, state, tool, browser, computer, and network oracles;
- trace capture, playback, controlled re-execution, and semantic reproduction;
- local counterfactual analysis and forensic reconstruction;
- technical finding adjudication and self-assessment evidence packaging;
- local regression monitoring, diffing, CI, registry sync, contribution, and coordinated disclosure workflows.

### Public knowledge

- public `.sova` scenarios and component signatures cleared for disclosure;
- public taxonomies, standard profiles, benchmarks, fixtures, and reproducible research;
- public registry metadata and a mirrorable registry client;
- safe vulnerable targets and non-destructive demonstrations;
- methods that have passed the applicable paper, patent, safety, and disclosure gates.

SOVA OSS may be less effective than a mature proprietary system because it lacks private data and operating history. It must not be deliberately weakened to create that difference.

## What never enters the public repository

### Private data and client material

- raw or derived private corpus records;
- matched failure-to-loss pairs;
- client identities, configurations, findings, traces, reports, credentials, or target manifests;
- confidential engagement methods or results;
- non-public vulnerability details under embargo;
- private telemetry, production logs, or model/provider keys.

### Corpus-derived intelligence

- priors learned from confidential outcomes;
- data-derived attack selection, ordering, stopping, and budget-allocation policies;
- private reproduction-rate and adversary-effort distributions;
- client-specific attack packs, target fingerprints, and tuning;
- production playbooks learned from commercial assessments;
- live threat intelligence that TRUSCOR is not permitted to redistribute.

SOVA OSS may expose the generic algorithm, extension point, and public-data baseline for these functions. It must not expose the private data, fitted parameters, rankings, prompts, rules, or evaluation sets derived from restricted sources.

### TRUSCOR commercial and authority assets

- TAFAAR internals, calibration, weights, and validation data;
- TRS, EAL, MPL, loss, premium, pricing, or underwriting logic;
- counter-signature keys, certificate issuance, attestation policy, and trust roots;
- independent adjudication procedures and expert-review work product;
- attested fleet monitoring and certificate-lifecycle infrastructure;
- Underwriting API, insurer/broker integrations, private risk feeds, and partner terms;
- accreditation material, conflict reviews, refusal logs, liability terms, and client operations.

### Confidential research and IP

- invention ledgers, unpublished patent drafts, claims, and filing strategy;
- unpublished paper methods not cleared for disclosure;
- trade-secret designs, experiments, negative results, and internal benchmarks;
- private honeypot architecture, placement, identifiers, telemetry, and detection-avoidance methods.

### Atlas and third-party confidential material

- the confidential Atlas technical report or any derivative excerpt;
- non-public Atlas architecture, roadmap, credentials, receipts, profiles, or implementation details;
- third-party material supplied under NDA, confidentiality, embargo, or a non-redistributable licence.

The public Atlas adapter may use only:

- the public Atlas repository and public documentation;
- an independently defined SOVA executor interface;
- behavior verified against a publicly obtainable Atlas release;
- user-supplied local configuration and credentials that remain untracked.

Every Atlas-specific implementation claim in public code or documentation must be traceable to a public source or to black-box behavior reproducible with a public release.

## Same workflow, different product

Feature names alone do not define the commercial boundary.

| Workflow | SOVA OSS | Proprietary SOVA Engine / TRUSCOR |
|---|---|---|
| Map | User maps an authorized system with public logic | Independently operated assessment plus private population context |
| Detonate and compose | Complete local harness with generic/public-data search | Corpus-conditioned prioritization, private threat intelligence, and client specialization |
| Trigger search | Public method, transparent baselines, user-supplied models and scenarios | Confidential outcome-derived selection and budget policies |
| Forensics | User reconstructs their own incident with bounded technical conclusions | Independent expert work intended for contractual, insurer, or legal reliance |
| Evidence | Self-assessment package with reproducible technical artifacts | Independently reviewed and counter-signed attestation |
| Sentinel | Local monitoring reported to the operator | Attested monitoring, external notification, and certificate lifecycle |
| Adjudicate | Technical comparison of tools and evidence for the operator | Independent dispute or claim work under a commercial mandate |
| Quantify | Technical severity, reach, confidence, and reproduction statistics | TAFAAR, TRS, EAL, MPL, financial loss, premium, and underwriting outputs |

The proprietary system may use the same public evidence formats. A shared format strengthens interoperability; it does not transfer TRUSCOR's authority to the operator or a fork.

This boundary is not a claim that TRUSCOR currently holds a particular accreditation, regulatory status, court acceptance, insurer acceptance, or authority. Each such claim requires separate evidence and legal/commercial review before external use.

## Repository topology and contamination controls

### Physical separation

- The public and proprietary systems use different repositories, access controls, issue trackers, artifact stores, CI secrets, and release pipelines.
- The private repository consumes tagged public releases; private commits are never developed on a branch of the public repository.
- No private Git remote, submodule, package registry credential, internal hostname, or private artifact URL is configured in public source.
- Examples and tests use synthetic fixtures created specifically for public use.
- Production data is never “anonymized and committed.” It remains outside the repository.

### Dependency direction

- Public interfaces are designed without reference to private implementations.
- Private extensions may implement public interfaces.
- Security fixes to public code flow back to SOVA OSS first or simultaneously.
- Private improvements are reviewed by category: generic mechanism may be contributed publicly; restricted data, tuning, and authority remain private.
- Code is never copied from a private source into public history until provenance, confidentiality, patent, licence, and disclosure review all pass.

### Release review

Every public change must answer:

1. Does it contain or derive from client, corpus, honeypot, Atlas-confidential, or other restricted material?
2. Does it reveal fitted values, ordering rules, prompts, rankings, negative results, or benchmarks learned from private data?
3. Does it disclose an invention before its patent or defensive-publication decision?
4. Does it include a secret, private endpoint, internal identity, or confidential filename?
5. Can the example be regenerated from public sources or synthetic data?
6. Does it make SOVA OSS appear to provide TRUSCOR authority?

Any uncertain answer blocks publication and requires founder/IP review.

The repository's [public-boundary policy](../governance/public-repository-boundary.md), automated check, pull-request checklist, and `.gitignore` provide layered enforcement. Automation is a backstop; it does not replace human review for semantic disclosure.

## Licence and fork-control options

The final licence is a founder decision and is not selected by this ADR.

### Permissive OSS

Apache-2.0 maximizes adoption, interoperability, and commercial use. It also allows proprietary forks and derivative products. Its trademark clause does not grant rights to the SOVA or TRUSCOR names.

### Reciprocal OSS

AGPL-3.0 requires corresponding source availability in important distribution and network-use cases. It can reduce private capture of modifications, but it still permits forks, modification, commercial use, and competition. It may complicate proprietary-engine integration and contribution governance, so counsel must review the intended architecture before selection.

### Competitive-use restriction

A licence that prohibits competing services, commercial use, reverse engineering, or particular users would be source-available rather than open source. Choosing that route would require renaming the project category and revising the SOVA OSS promise. This ADR rejects silently applying such restrictions while continuing to market the project as open source.

### Trademark

An open-source copyright licence need not grant trademark rights. A separate, published trademark policy can require forks and materially modified distributions to use a different name and make their non-affiliation clear. Trademark protects identity and user trust; it does not stop the underlying code from being forked.

Until a `LICENSE` file and founder-approved trademark policy are present, the repository is public pre-alpha design material but is not yet a completed licensed OSS release. No executable release should be promoted before those founder gates close.

## Trade-secret requirements

The private boundary has value only if TRUSCOR actually treats it as private.

The [WIPO trade-secret guidance](https://www.wipo.int/web-publications/wipo-guide-to-trade-secrets-and-innovation/en/part-iii-basics-of-trade-secret-protection.html) identifies secrecy, commercial value because of secrecy, and reasonable protective steps as core conditions. It also notes that independent development and reverse engineering generally are not prevented by trade-secret protection.

TRUSCOR therefore needs, outside this repository:

- a named trade-secret inventory and owners;
- need-to-know repository and dataset access;
- signed IP assignment and confidentiality terms for founders, employees, contractors, researchers, and collaborators;
- access logging, offboarding, key rotation, backups, and incident response;
- confidentiality markings and approved handling locations;
- client contracts that define permitted corpus use;
- a publication review covering code, papers, talks, demos, screenshots, prompts, logs, and benchmark results;
- periodic review that each retained secret is still secret and commercially useful.

These are business controls, not SOVA OSS features.

## Research and IP rule

The following is the default classification:

- generic public architecture and already-cleared methods: open engineering or defensive publication;
- universally implemented formats and conformance rules: open specification;
- confidential data and data-derived conditioning invisible from outputs: trade-secret candidate;
- a novel method that must be disclosed to achieve adoption: patent-or-defensive-publication gate before disclosure;
- client or third-party confidential material: never publish without explicit written authority.

This ADR does not decide whether a specific invention is patentable and is not legal advice. Qualified counsel must review the licence, trademark, contributor, patent, and trade-secret programme.

## Consequences

- The public architecture is complete enough that a competent fork can exist. This is accepted.
- SOVA OSS cannot use anti-fork, non-commercial, or anti-competitive restrictions while claiming to be open source.
- Public performance must come from public algorithms, public registry material, user-supplied models, and user-supplied scenarios.
- Proprietary performance may come from restricted data and operating history, not a hidden switch in the OSS.
- Public packages use “SOVA OSS Core” or “SOVA Runtime”; “SOVA Engine” remains proprietary.
- Atlas remains optional and replaceable; only public Atlas information may enter this repository.
- The licence, contributor terms, and trademark policy remain Founder Gates 00-C and 00-D.
- Topic 01 must establish repository layout and continuous boundary checks before implementation broadens.

## Acceptance checks

- [x] SOVA architecture, generic search, trace logic, local MCP, registry client, and every user-facing workflow are classified as OSS scope.
- [x] The private corpus, corpus-derived tuning, matched loss pairs, TAFAAR, counter-signature, client findings, and private honeypot design are excluded.
- [x] The proprietary SOVA Engine is distinguished from the public SOVA OSS Core.
- [x] The impossibility of preventing forks while remaining genuinely open source is explicit.
- [x] The defensible moat is separated into private intelligence, independent authority, identity, and operating record.
- [x] The confidential Atlas report and all non-public Atlas details are in the never-publish class.
- [x] Repository separation, dependency direction, review questions, and trade-secret hygiene are defined.
- [x] Licence and trademark choices remain explicit founder decisions rather than accidental engineering decisions.
