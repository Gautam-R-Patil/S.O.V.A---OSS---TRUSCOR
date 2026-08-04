# ADR-0006: Topic 01 evidence and publication go/no-go

- **Status:** Accepted
- **Decision date:** 2026-07-29
- **Roadmap scope:** Topics 01.1 through 01.5 and Topic 01 exit
- **Decision owner:** Gautam R. Patil

## Context

Topic 01 exists to prevent SOVA from building or publishing around stale
novelty, market, legal, and competitive assumptions.

The review found direct prior art for:

- dormant/backdoor-trigger detection;
- adaptive long-horizon and multi-turn agent attacks;
- memory poisoning and sequential tool-chain attacks;
- code-guided MCP exploit confirmation;
- counterfactual/intervention-based agent failure attribution;
- passive agent observability;
- selective disclosure, signing envelopes, analysis interchange, and software/AI
  supply-chain metadata.

It also found that several market percentages and the original EU AI Act
summary cannot support their original wording.

## Decision

SOVA OSS proceeds as an integrated, local agent-security and evidence
workbench. It does not proceed on the premise that adjacent categories are
empty.

Product breadth and research novelty are evaluated independently:

- useful overlapping capabilities remain in scope when integration improves the
  user workflow;
- existing scanners, red-team tools, benchmarks, recorders, sandboxes, and
  standards are integrated or interoperated with instead of dismissed;
- novelty and superiority language is withheld until a predeclared comparison
  produces supporting evidence;
- non-trivial trigger-search and semantic-reproduction mechanisms remain under
  publication/IP hold until prior-art and qualified legal review are complete.

## Accepted artifacts

- [Claims register](../research/claims-register.md)
- [Prior-art and interoperability matrix](../research/prior-art-and-interoperability.md)
- [Predeclared comparison protocol](../research/predeclared-comparison-protocol.md)
- [Publication and IP review](../governance/publication-and-ip-review.md)

## Claim decision

Retire broad claims that SOVA is the first/only system to:

- search dormant conditions;
- execute long-horizon or compositional attacks;
- connect attack and evidence;
- perform counterfactual agent attribution;
- report reproduction rates;
- preserve verifiability through selective disclosure.

Retain the problems and features. Replace historical priority with measured
claims about an exact SOVA release, target set, baseline union, protocol, and
result.

`best`, `easiest`, and `most complete` remain value hypotheses. They may guide
design but cannot appear as established comparative facts until usability
evidence exists.

## Build/import/interoperate decision

SOVA builds:

- public adapter contracts and a normalised finding/evidence model;
- explicit authorization and bounded execution;
- local sandbox integration;
- deterministic security oracles;
- trace normalization, provenance, integrity, redaction manifests, verification,
  playback, and repeated confirmation;
- portable `.sova` and `.sova-trace` contracts;
- execution-based cross-scanner adjudication;
- a small owned ground-truth fixture suite;
- a security-layer attribution interface.

SOVA integrates, imports, or interoperates with:

- static MCP/skill scanners;
- red-team and evaluation frameworks;
- AgentDojo, FinBot, ASB, AgentLAB, OASB, and compatible benchmark projects;
- OpenTelemetry/OpenInference/Phoenix-style traces;
- DSSE, Sigstore, SARIF, SPDX, MITRE ATLAS, OWASP, and NIST mappings;
- compatible attribution baselines.

SOVA deliberately skips rebuilding:

- a general static-analysis engine at the start;
- broad probe libraries already maintained elsewhere;
- a generic observability collector or dashboard;
- Firecracker/cloud sandbox infrastructure;
- browser and OS benchmark environments;
- a private signing envelope, SBOM, findings format, or threat taxonomy.

## Experiment decision

Protocol `SOVA-COMP-01` version 1.0 is frozen before implementation and results.
It includes:

- 12 SOVA-owned vulnerable fixtures across dormant, multi-turn, compositional,
  and overt classes;
- 60 matched benign variants;
- pinned AgentDojo and OWASP FinBot public targets;
- static, one-pass dynamic, agent-mediated, long-horizon/compositional, and
  passive-recorder baselines;
- deterministic machine-checkable success oracles;
- five discovery campaigns per active method/target;
- 30 candidate-condition and 30 matched-control confirmation trials;
- explicit false-positive, unsupported, and inconclusive outcomes;
- 40 planted attribution cases;
- immutable run bundles and negative-result preservation.

The protocol includes stronger long-horizon baselines even though they make a
SOVA win harder. Omitting them would not support a credible result.

The minimum harness contract is frozen in the protocol. It is not implemented
inside Topic 01 because the repository language, packaging, test, and dependency
foundation is Topic 02. Building a throwaway harness before that decision would
violate the roadmap’s own order. The first authorised post-foundation slice is
the no-Atlas harness/evidence path.

This is a historical Topic 01 staging statement. The bounded no-MELRA
harness, evidence paths, and comparison fixtures are now implemented; the
large confirmatory experiments below remain unrun unless their individual
result rows say otherwise.

## Evidence gates

| Gate | Decision | Result |
|---|---|---|
| **01-A** | Pass only if SOVA confirms at least two incremental ground-truth defect units from at least two hidden/stateful families, with repeated confirmation, zero matched-control confirmations, zero confirmed false positives across 60 benign variants, and all strong compatible baselines included. | **NOT RUN - UNPROVEN** |
| **01-B** | Pass only if single-layer top-1 accuracy is at least 80%, the 95% Wilson lower bound is at least 65%, at least 4/5 interactions identify all necessary layers, Brier score is at most 0.20, and intervention evidence verifies. | **NOT RUN - UNPROVEN** |

Current consequence:

- **GO** for Topic 02 repository/engineering foundations and the minimum no-Atlas
  evidence harness.
- **NO-GO** for sleeper superiority, “catches what others miss,” causal
  correctness, attribution accuracy, coverage, benchmark-result, and
  implemented-capability claims.
- **NO-GO** for publishing a non-trivial trigger-search or semantic-reproduction
  method before its IP gate.

This is a completed decision, not a successful experiment. “Not run” is the
only truthful evidence-gate result before SOVA exists.

## Publication decision

The repository and high-level artifact decisions were already public before
Topic 01. The original “no public repository before Gate 01-C” wording is
therefore resolved prospectively:

- high-level public material is recorded as already disclosed;
- `.sova` and `.sova-trace` remain open, independently implementable formats;
- mechanism-bearing schema fields require prospective IP review;
- every public commit is treated as disclosure;
- trigger-search Gate 01-D remains **HOLD** for non-trivial methods;
- semantic-reproduction Gate 01-E remains **HOLD** for a proposed novel
  mechanism;
- paper, release, demo, and benchmark publication require the approved
  checklist;
- qualified counsel is required before relying on patentability or legal
  conclusions.

## Safe acquisition decision

The first benchmark can be acquired legally and safely using:

- SOVA-owned synthetic fixtures;
- pinned MIT-licensed AgentDojo;
- pinned Apache-2.0 OWASP FinBot CTF;
- pinned Apache-2.0 Cisco MCP Scanner and Snyk Agent Scan;
- pinned Apache-2.0 OASB, HackMyAgent, and AIR Blackbox plus MIT AgentLens,
  subject to nested dependency/data review;
- MIT-licensed ASB/AgentLAB only after nested asset/dependency provenance;
- STAC only as a separate non-commercial research runner under its declared
  CC BY-NC 4.0 boundary.

All targets run locally with fake data, no real credentials, sink-only egress,
clean reset, explicit authorization, and no live third-party infrastructure.

## Consequences

Positive:

- SOVA’s public story becomes difficult to disprove with one competing link.
- Existing high-quality projects reduce implementation time.
- Benchmark thresholds are fixed before results.
- Negative results cannot silently disappear.
- Patent, trade-secret, publication, safety, licence, and disclosure decisions
  occur before mechanism-bearing publication.

Costs:

- SOVA must earn its strongest message experimentally.
- Some original launch language and percentages cannot be used.
- Fair baselines increase engineering and compute cost.
- IP review can delay publication of non-trivial methods.
- A failed benchmark will narrow the research claims even if the integrated
  product remains useful.

## Topic 01 closure

- [x] Factual, comparative, value, legal, standards, market, and novelty claim
      families are imported into a dated register.
- [x] Every registered claim has an owner, evidence state, checked date, recheck
      date, and public-use decision.
- [x] Prohibited language and a durable retired-claims ledger exist.
- [x] Static, red-team, dynamic, observability, benchmark, attribution,
      computer-use, evidence, compliance, SBOM, SARIF, disclosure, and signing
      prior art is mapped.
- [x] Every overlap has a build/integrate/import/interoperate/skip disposition.
- [x] Targets, hidden/stateful/compositional cases, oracles, trials, budgets,
      false-positive rules, attribution cases, baselines, and negative-result
      handling are predeclared.
- [x] The protocol is frozen before SOVA results.
- [x] The minimum harness contract and post-Topic-02 build authorization are
      recorded.
- [x] Gates 01-A and 01-B have explicit thresholds and the honest current result
      **NOT RUN - UNPROVEN**.
- [x] Disclosures and Gates 01-C, 01-D, and 01-E are resolved.
- [x] The mandatory IP checklist exists.
- [x] The first target/baseline set has pinned revisions and a safe/legal
      acquisition boundary.
- [x] No comparative result or non-trivial mechanism has been represented as
      public evidence.

## Next

Begin Topic 02. Topic 02 establishes repository control, language/runtime,
packaging, dependency policy, test layers, quality gates, CI, documentation,
versioning, release mechanics, and contributor workflow before the minimum
comparison harness is implemented.
