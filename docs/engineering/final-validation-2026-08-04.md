<!-- status: implemented -->

# SOVA OSS whole-repository validation report

Validated on 2026-08-04 against Python 3.11 on Windows. This is an
evidence-backed pre-alpha engineering report, not a safety certificate,
independent audit, patent opinion, peer review, or claim of universal target
coverage.

## Outcome

SOVA OSS is installable and its bounded offline product surface is runnable.
The repository provides portable `.sova` behavior capsules, canonical
`.sova-trace` evidence, verification, playback, controlled re-execution,
semantic comparison, authorization and containment contracts, mapping,
detonation fixtures, trigger search, forensics, evidence exports, composition,
rehearsal, monitoring, registries, local MCP, extensions, provider contracts,
probe/Arena/community artifacts, onboarding, conformance, and release tooling.

The validated result is not “100% complete” in the scientific or ecosystem
sense. Live assessment of an arbitrary target requires that target, fresh
human authorization, credentials kept outside SOVA artifacts, an admitted
executor, and suitable isolation. Independent security review, external
adoption, real-provider comparison, paper submission, peer review, patent
counsel, signed tags, and package-index publication cannot be manufactured by
the project's own test suite.

## Mandatory validation evidence

| Control | Result |
|---|---|
| Complete deterministic test suite | 768 passed, 1 optional Codex test skipped, 0 failed |
| Branch-aware coverage | 95.31% across 12,635 statements and 3,606 branches |
| Registered CLI surface | 67 leaf commands; every handler executed in coverage |
| Formatting and linting | 371 files formatted; Ruff passed |
| Static typing | strict mypy passed for 248 source files |
| Generated contracts | glossary and attack-taxonomy checks passed |
| Repository policy | 445 tracked or unignored files checked; passed |
| Dependency audit | no known non-waived vulnerability; one documented temporary advisory waiver |
| Public boundary | private/confidential path and content scan passed |
| Lockfile | `uv lock --check` passed |
| Private paper package validator | WM-P1/WM-P4/WM-P5/WM-P6 structure, sources, citations, digests, and PDF text passed |
| Deterministic distributions | two source builds and two wheel builds matched byte-for-byte; release manifests carry artifact digests |
| Release metadata | CycloneDX 1.6 runtime SBOM: 10 components; exact four-file checksum verification passed offline |
| Clean-wheel smoke | install, init/doctor/delete, map, signed website/software fixtures, conformance kit, sleeper demo, inspect, verify, and MCP manifest passed |

The optional official Codex lane was skipped because `codex login status`
reported `Not logged in`. It is deliberately not a mandatory dependency and no
authentication material was read, copied, logged, or proxied. No external
provider credential was present or used.

Two deliberately invalid test invocations were also retained as diagnostics:

- direct `uv run pytest` on this Windows checkout omitted the repository root
  from the import path; all public instructions and release automation now use
  the validated `uv run python -m pytest` form;
- a manually selected `C:\\tmp` pytest base directory had a host ACL denial;
  pytest's managed temporary directory passed the same suite.

Neither diagnostic was counted as a product test failure.

The source archive held 283 entries and the wheel 166. Both distribution-name
scans found zero private or confidential paths; the source archive contained
README, citation, code-of-conduct, governance, maintainers, licence, and notice
material. The clean-wheel doctor deliberately warned that portable code cannot
establish Windows ACL strength; that remains a release gate rather than a
suppressed warning.

## Command and feature audit

The coverage audit discovers commands from the parser rather than maintaining
a hand-written allowlist. It covers all 67 leaf handlers in these families:

- capsule and trace: `template`, `validate`, `lint`, `format`, `hash`, `pack`,
  `migrate`, `inspect`, `query`, `recover-trace`, `trace`, and `verify`;
- execution and evidence: `check`, `demo`, `map`, `hunt-demo`, `playback`,
  `replay`, `compare`, `forensics`, `evidence`, `adjudicate`, and `compose`;
- operational workflows: `rehearse`, `sentinel`, `diff`, `ci`, `self-check`,
  `registry`, `sync`, `contribute`, `probe`, `arena`, `leaderboard`, `ctf`, and
  replay clips;
- integration and administration: local `mcp`, executor receipts, target
  contracts, initialization, diagnostics, managed-data deletion, release SBOM
  and checksums, and conformance export/verification.

Handler execution proves that commands are connected and tested. It does not
mean every optional external executor, model provider, operating system, or
real target was available in this run.

## Authorized website and software testing

`sova target template`, `target validate`, and `target plan` create a
secret-free target contract and an inert execution plan. `target fixture
website` and `target fixture software` prove the complete deterministic flow:

target contract -> plan -> scenario -> observable execution -> signed trace ->
capsule -> playback/re-execution comparison -> offline verification.

The website path can be admitted through the pinned Microsoft Playwright MCP
adapter; Windows UI has a read-first Windows-MCP adapter; local programs use an
absolute-executable allowlist and confined working directory through
`RestrictedLocalExecutor`. MELRA is optional. None of these adapters supplies
SOVA authorization, policy, judging, signing, or containment.

An arbitrary live target was not contacted. A live run becomes valid only
after the owner supplies the exact target and scope, out-of-band authorization,
isolated test identities and data, permitted actions and effects, stop
conditions, and target-specific oracles. CAPTCHA bypass, unauthorized account
creation, third-party production testing, and stealth persistence are excluded.
Ordinary host-process restrictions and browser profiles are not security
sandboxes.

See [authorized target testing](../guides/authorized-target-testing.md) and the
[target assessment specification](../specifications/authorized-target-assessment-0.1.md).

## Roadmap disposition

| Topics | Engineering disposition | Open evidence boundary |
|---|---|---|
| 00-03 | Implemented controlling decisions, claims, repository controls, vocabulary, taxonomy, coverage, and version contracts | founder/legal approvals remain human decisions |
| 04-06 | Core capsule, trace, migration, integrity, executor, and no-MELRA vertical slice implemented and tested | independent cross-system adoption, third-party adapter, blinded real-runtime validation |
| 07-11 | Authorization, containment contracts, synthetic world, sensors/oracles, map, engine loop, check, and demo implemented | stronger OS isolation and live optional backends remain environment-dependent |
| 12-14 | Three replay modes, semantic studies, MCP broker/adapters, trigger-space model, baselines, adaptive search, and Phantom contract implemented | multi-provider comparison and larger real-target search experiments |
| 15-17 | Reconstruction, bounded causal attribution, evidence/disclosure, and composition search implemented | nondeterministic causal validation, scanner-disagreement data, and comparative baselines |
| 18-20 | Substitute rehearsal, process traces/drift/sentinel/CI, and signed local registry implemented | authorized live rehearsal, external mirrors, contributors, and maintainer outcomes |
| 21-23 | Human-gated local MCP, extension/provider/target contracts, Inspect bridge, probe, Arena, leaderboard, CTF, and clips implemented | external providers/hosts, additional vulnerable-agent projects, and public comparisons |
| 24 | Private source/opportunity/invention ledgers and four validated private review packages complete | submission remains HOLD pending missing experiments, independence, founder/IP review, and venue process |
| 25 | Account-free install/init/doctor, deletion, guides, command reference, and wheel smoke path implemented | independent cold-install and adoption measurements |
| 26 | Internal hardening, deterministic builds, SBOM/checksums, conformance kit, governance, and release workflows implemented | multi-OS CI result on the public commit, external reviews, signed tag/release, package provenance, founder launch approval |
| 27 | Standards tracking, compatibility kit, archival policy, succession, aging policy, and explicit non-goals implemented | deliberately open-ended research and ecosystem adoption |

Unchecked roadmap entries are not forgotten work. They identify evidence that
requires independent people, a supplied live target, external runtimes,
longitudinal adoption, publication venues, or legal authority. They remain
unchecked until that evidence exists.

## Research, papers, and patents

The private portfolio contains WM-P1, WM-P2, and WM-P4 through WM-P7 working manuscripts
or prospectuses, plus WM-P8/WM-P9 research questions. Four private arXiv-style review
packages include Markdown, TeX, PDF, bibliography, figures, metadata, build
provenance, and source archives. Their structural validator and complete-page
visual inspection passed.

Scientific submission decisions remain HOLD. The strongest current private
readiness estimates are WM-P5 90%, WM-P4 89%, WM-P6 85%, and WM-P1 75%; these are internal
evidence-completeness estimates, not acceptance probabilities. The missing
work is predominantly independent/blinded evaluation, heterogeneous real
runtimes, faithful baseline experiments, external security/privacy review, and
human author/IP approval. The `WM-*` namespace is distinct from the legacy
roadmap `LEG-P5` model-swap and `LEG-P6` detonation-limitations slots; the
private controlling crosswalk preserves the historical records without
renaming digest-bound packages.

Seven narrow invention disclosures remain private and on HOLD pending stronger
comparative evidence, confirmation of human conception and inventorship,
claim-chart refinement, disclosure review, and qualified counsel. Broad claims
over capsules, traces, hash chains, signatures, replay, simulation, registries,
or SBOMs are NO-GO because the fields are occupied. No paper was submitted and
no patent was filed or publicly disclosed by this work.

## Claims and limitations

- SOVA records observable requests, responses, authorized reasoning summaries,
  tool actions, approvals, effects, artifacts, and state transitions. It does
  not capture hidden model thoughts or private chain-of-thought.
- Hash chains, signatures, and DSSE-compatible envelopes provide tamper
  evidence and provenance within the threat model; they are not unforgeable or
  universal non-repudiation.
- Bounded testing can produce verified observations and inconclusive results;
  it cannot prove universal safety or the absence of vulnerabilities.
- A signed SOVA self-assessment is not independent TRUSCOR attestation.
- Experimental `0.x` artifact contracts retain explicit migration paths and
  may change before a stable 1.0 declaration.

## Release decision

The repository is suitable for continued public pre-alpha development and
authorized fixture evaluation. A promoted stable release is **HOLD** until the
public commit passes its full GitHub matrix, founder policy/IP approval is
recorded, at least one independent security review is resolved or disclosed,
and signed release provenance is produced. A scientific or patent launch has
separate gates and must not be inferred from software-test success.
