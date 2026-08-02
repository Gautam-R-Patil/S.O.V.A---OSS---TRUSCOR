# SOVA OSS claims register

- **Register version:** 1.0
- **Evidence snapshot:** 2026-08-02
- **Register owner:** Gautam R. Patil
- **Next competitive recheck:** 2026-08-29
- **Legal review state:** qualified counsel not yet recorded

This register controls factual, comparative, market, legal, standards, novelty,
and value language used by SOVA OSS. It replaces undated claims in planning
material. A product feature may remain in scope even when a novelty claim about
that feature is retired.

Every role in the **Owner** column names Gautam R. Patil as the interim
accountable person acting in that role. “Founder plus counsel” means Gautam owns
the claim and must obtain qualified counsel review; no counsel is presently
assigned and the legal dependency is not treated as complete.

## Status rules

| Status | Meaning | Public use |
|---|---|---|
| **VERIFIED** | Direct primary evidence or a reproducible SOVA result supports the exact bounded wording. | Allowed with the cited evidence and its limitations until the recheck date. |
| **PROVISIONAL** | Plausible or planned, but incomplete evidence, implementation, legal review, or replication remains. | Only as an explicitly qualified plan, target, or preliminary observation. |
| **UNVERIFIED** | No adequate primary evidence supports the exact wording. | Prohibited as fact. |
| **RETIRED** | Evidence contradicts the wording, the source is missing, or the claim is too broad to defend. | Prohibited. Use the replacement wording, if any. |
| **VALUE HYPOTHESIS** | A product preference or expected user benefit that must be demonstrated. | Allowed only as an aspiration, never as an established comparative fact. |

For this register, a claim is stale on the stated recheck date. Stale claims
automatically become **UNVERIFIED** until checked again.

## Language control

The following words are prohibited in factual product, release, benchmark, and
paper claims unless the sentence defines the comparison set, method, date, and
limitation:

- `first`, `only`, `nobody`, `unoccupied`, and `unmatched`;
- `safe` and `clean` as universal verdicts;
- `unforgeable`, `tamper-proof`, and `guaranteed`;
- `deterministic` when referring to stochastic model re-execution;
- any unsupported percentage, coverage number, accuracy, detection rate, or
  adoption figure.

`Best`, `easiest`, and `most complete` are product hypotheses. They require a
named comparison set, a predeclared task, participant or automated usability
evidence, and a reproducible result before they become factual claims.

## Source keys

Sources are primary project repositories, standards, regulations, official
guidance, or original research:

- **SRC-ASB:** [Agent Security Bench](https://github.com/agiresearch/ASB)
- **SRC-AGENTLAB:** [AgentLAB paper](https://arxiv.org/abs/2602.16901) and
  [implementation](https://github.com/TanqiuJiang/AgentLAB)
- **SRC-TRIGGER:** [The Trigger in the Haystack](https://arxiv.org/abs/2602.03085)
- **SRC-SLEEPER:** [Sleeper Agents](https://arxiv.org/abs/2401.05566)
- **SRC-STAC:** [STAC implementation and 483-case benchmark](https://github.com/amazon-science/MultiTurnAgentAttack)
- **SRC-AGENTDOJO:** [AgentDojo](https://github.com/ethz-spylab/agentdojo)
- **SRC-VIPER:** [VIPER-MCP](https://arxiv.org/abs/2605.21392)
- **SRC-HMA:** [HackMyAgent](https://github.com/opena2a-org/hackmyagent)
- **SRC-OASB:** [Open Agent Security Benchmark](https://github.com/opena2a-org/oasb)
- **SRC-AIR:** [AIR Blackbox](https://github.com/airblackbox/airblackbox)
- **SRC-AGENTLENS:** [AgentLens](https://github.com/agentkitai/agentlens)
- **SRC-CAR:** [Causal Agent Replay](https://arxiv.org/abs/2606.08275)
- **SRC-AGENTRACER:** [AgenTracer](https://arxiv.org/abs/2509.03312)
- **SRC-WHOWHEN:** [Who & When failure-attribution paper](https://arxiv.org/abs/2505.00212)
- **SRC-OTEL:** [OpenTelemetry GenAI semantic conventions](https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/)
- **SRC-DSSE:** [Dead Simple Signing Envelope](https://github.com/secure-systems-lab/dsse)
- **SRC-SIGSTORE:** [Sigstore bundle verification](https://docs.sigstore.dev/cosign/verifying/verify/)
- **SRC-SARIF:** [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- **SRC-SPDX:** [SPDX specifications](https://spdx.dev/use/specifications/)
- **SRC-SDJWT:** [RFC 9901: Selective Disclosure for JWTs](https://www.rfc-editor.org/rfc/rfc9901.html)
- **SRC-BBS:** [W3C Data Integrity BBS Cryptosuites](https://www.w3.org/TR/vc-di-bbs/)
- **SRC-EU-FAQ:** [European Commission AI Act implementation FAQ](https://digital-strategy.ec.europa.eu/en/faqs/navigating-ai-act)
- **SRC-EU-LAW:** [Regulation (EU) 2024/1689](https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng)
- **SRC-IBM:** [IBM IBV security-platform study](https://www.ibm.com/thought-leadership/institute-business-value/en-us/report/unified-cybersecurity-platform)
- **SRC-VORLON:** [Vendor-sponsored 2026 CISO report](https://go.vorlon.io/hubfs/The%20Agentic%20Ecosystem%20Security%20Gap_%202026%20CISO%20Report%20FINAL.pdf)
- **SRC-OWASP:** [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- **SRC-ATLAS:** [MITRE ATLAS](https://atlas.mitre.org/)
- **SRC-OSI:** [Open Source Definition](https://opensource.org/osd)
- **SRC-LOCAL-ADR:** [Accepted SOVA decisions](../decisions/0005-topic-00-project-constitution.md)
- **SRC-PROTOCOL:** [Predeclared SOVA comparison protocol](./predeclared-comparison-protocol.md)
- **SRC-MELRA:** [MELRA public repository](https://github.com/XAGI-Lab/melra)

## Product and implementation claims

| ID | Controlled claim | Status | Owner | Evidence | Checked | Recheck | Public decision |
|---|---|---|---|---|---|---|---|
| P-01 | SOVA OSS is intended to be local-first, account-free, bring-your-own-model, and without automatic telemetry. | PROVISIONAL | Product owner | SRC-LOCAL-ADR | 2026-07-29 | 2026-10-27 | Say “designed” or “planned” until tested. |
| P-02 | SOVA OSS is a complete public instrument rather than a trial for SOVA Engine. | PROVISIONAL | Product owner | SRC-LOCAL-ADR | 2026-07-29 | 2026-10-27 | Governance is accepted; completeness is not implemented. |
| P-03 | Atlas is optional and replaceable; SOVA owns authorization, containment selection, observation, judging, evidence, replay, and verification. | VERIFIED | Architecture owner | SRC-LOCAL-ADR; [ADR-0010](../decisions/0010-executor-contract-and-no-atlas-backends.md) | 2026-07-31 | 2026-10-29 | Verified for the current provider-neutral contract and two no-Atlas backends; not an Atlas interoperability result. |
| P-04 | Experimental `.sova` is a portable AI-behavior capsule that can contain a scenario and related evidence; `.sova-trace` is the canonical low-level observable event/evidence stream. | VERIFIED | Format owner | [ADR-0009](../decisions/0009-sova-behavior-capsule-and-trace-model.md); implemented schemas and conformance tests | 2026-07-31 | Before 0.2 | Bounded to experimental `0.1.0`; not a stable-1.0, adoption, or novelty claim. |
| P-05 | Stable `.sova` artifacts will migrate forward without silent semantic or data loss. | PROVISIONAL | Format owner | [ADR-0002](../decisions/0002-versioning-and-lossless-migration.md) | 2026-07-29 | Before 1.0 | Compatibility promise; requires conformance tests before `1.0.0`. |
| P-06 | SOVA evidence is operator-controlled self-assessment, not TRUSCOR attestation. | VERIFIED | Governance owner | [ADR-0004](../decisions/0004-self-assessment-and-truscor-boundary.md) | 2026-07-29 | 2027-01-29 | Allowed as a project-boundary statement. |
| P-07 | `map`, `check`, `detonate`, `compose`, `arena`, `rehearse`, `forensics`, `evidence`, `sentinel`, `registry`, `adjudicate`, and `disclose` are available. | UNVERIFIED | Release owner | Repository status | 2026-07-29 | Every release | Prohibited. They are planned commands, not released capabilities. |
| P-08 | `sova map` delivers useful first value within five minutes of a cold install. | VALUE HYPOTHESIS | Product owner | No usability run yet | 2026-07-29 | Before beta | Keep as an engineering target. |
| P-09 | `sova check` completes a representative component test in 60 seconds. | VALUE HYPOTHESIS | Product owner | No performance run yet | 2026-07-29 | Before alpha | Keep as a budget/profile target, not a guarantee. |
| P-10 | SOVA traces can be DSSE-compatible Ed25519 signed and are tamper-evident for covered bytes under the published threat model. | VERIFIED | Evidence owner | SRC-DSSE; SRC-SIGSTORE; [threat model](../specifications/threat-model.md); integrity and hostile-input tests | 2026-07-31 | Before 0.2 | Included-key verification establishes no external signer identity; never say tamper-proof or unforgeable. |
| P-11 | Semantic reproduction is a rate over repeated trials, not exact deterministic rerun. | VERIFIED | Research owner | Project definition; SRC-PROTOCOL | 2026-07-29 | 2026-10-27 | Allowed as SOVA terminology, not as a novelty claim. |
| P-12 | The registry is pull-only and sends no target, trace, credential, or finding data. | PROVISIONAL | Privacy owner | SRC-LOCAL-ADR | 2026-07-29 | Before registry release | Must be enforced and network-tested before factual use. |
| P-13 | SOVA can continuously detect safety regressions after model or component updates. | UNVERIFIED | Sentinel owner | No implementation or longitudinal result | 2026-07-29 | Before sentinel release | Say “planned regression testing.” |
| P-14 | SOVA can assign the responsible model, tool, memory, orchestration, permission, or environment layer. | UNVERIFIED | Forensics owner | Gate 01-B not run | 2026-07-29 | After Gate 01-B | Prohibited as achieved capability. |
| P-15 | One safe owned conditional-behavior capsule can be executed through scripted and restricted-local backends, inspected, played back inertly, compared on declared outcomes, repackaged with both traces, and verified offline without Atlas. | VERIFIED | Architecture owner | `tests/integration/test_no_atlas_complete_vertical_slice.py`; hosted CI for the cited commit | 2026-07-31 | Every executor-contract change | Bounded to the deterministic fixture; host execution is not a security sandbox. |
| P-16 | The public exact declared-outcome comparator refuses equivalence when a source trace is invalid or reports dropped events, non-full capture, or an absent selected event family. | VERIFIED | Evidence owner | `sova.reproduction`; reproduction failure tests | 2026-07-31 | Before 0.2 | This is not the private experimental semantic-reproduction mechanism or a general semantic judge. |
| P-17 | The restricted-local executor can resolve strict opaque `sova-secret:` references just in time without storing the resolved value in the capsule or normal trace outcome. | VERIFIED | Privacy owner | executor/capsule integration tests; [executor contract](../specifications/executor-contract-0.1.md) | 2026-07-31 | Every secret-boundary change | The allowlisted child and host may observe the in-memory value; this is not a hardware secret boundary. |
| P-18 | The reference runner refuses real effectful execution without a live authorization session binding exact intent, proof, containment, budgets, and required evidence; scripted and read-only compatibility paths cannot perform a real mutation. | VERIFIED | Safety owner | [ADR-0011](../decisions/0011-authority-containment-evidence-kernel.md); authorization and integration tests | 2026-08-02 | Every authorization or executor change | Bounded to the implemented reference runner and tested adapters; not a claim about a compromised host or modified binary. |
| P-19 | The bundled synthetic sleeper fixture activates deterministically, exposes inert canary access and sink-only egress through healthy required sensors, emits verifiable artifacts, and resets its event-sourced state. | VERIFIED | Detonation owner | `tests/integration/test_synthetic_detonation_vertical_slice.py`; [synthetic detonation specification](../specifications/synthetic-detonation-0.1.md) | 2026-08-02 | Every sensor, target, or world change | Measurement-system fixture only; it does not establish real-model, anti-sandbox, or native-code fidelity. |
| P-20 | MELRA `0.3.0-alpha.0` has been reviewed as a possible future browser/computer/terminal/file executor, but no MELRA adapter or conformance result ships in SOVA yet. | VERIFIED | Adapter owner | SRC-MELRA at pinned commit `a6dd6710f5ae94e8ce825ef99df9b01d7f974b95`; [adapter boundary](../specifications/melra-adapter-boundary-0.1.md) | 2026-08-02 | Before Topic 13 implementation | The public release review does not verify confidential target architecture or future roadmap capabilities. |
| P-21 | `sova map` produces an air-gapped typed local capability report with separately labeled declared, observed, inferred, and refuted evidence and never claims an inferred edge was executed. | VERIFIED | Mapping owner | [ADR-0013](../decisions/0013-provenance-separated-capability-map.md); map unit, schema, CLI, privacy, cross-machine, and performance tests | 2026-08-02 | Every map schema or collector change | Bounded to supported collectors and supplied inventories; runtime observation needs authorization; partial coverage is explicit. |
| P-22 | The reference SOVA Runtime prevents attacker/model response text and raw tool output values from entering factual judge input, applies deterministic oracles/policies first, and rejects missing evidence references. | VERIFIED | Runtime owner | [ADR-0014](../decisions/0014-evidence-firewalled-runtime.md); evidence-firewall and orchestration tests | 2026-08-02 | Every projection or judge-contract change | This proves tested information-flow and reference checks, not semantic entailment, sensor truth, universal injection resistance, or novelty. |
| P-23 | The bundled no-MELRA demo repeatedly maps and finds its two-factor planted condition, emits signed discovery/reproduction traces plus a capsule, and passes independent offline verification. | VERIFIED | Workflow owner | [ADR-0015](../decisions/0015-bounded-check-and-no-melra-proof.md); three-clean-run integration and performance tests | 2026-08-02 | Every demo, trace, or workflow change | Synthetic measurement fixture and minimal named baselines only; no real-agent detection-superiority claim. |

## Market, incident, and operational claims

| ID | Controlled claim | Status | Owner | Evidence | Checked | Recheck | Public decision |
|---|---|---|---|---|---|---|---|
| M-01 | A February 2026 fintech incident affected about 3,400 interactions, caused at least 11 cross-customer disclosures, and remained unexplained after three weeks. | RETIRED | Research owner | No primary incident record located | 2026-07-29 | Only with primary record | Remove from all public material. |
| M-02 | 99.4% of surveyed leaders reported a SaaS or AI ecosystem incident; 38.2% claimed comprehensive response coverage; 86.8% lacked visibility. | PROVISIONAL | Research owner | SRC-VORLON, vendor-sponsored survey | 2026-07-29 | 2026-08-29 | May be cited only as that report’s result with sample and sponsorship disclosed. |
| M-03 | Security operators spend roughly 80% of their time on plumbing and 20% on probing. | RETIRED | Research owner | No primary study located | 2026-07-29 | Only with primary study | Do not use the percentage. State the integration problem without quantification. |
| M-04 | 78% report fragmentation, analysts spend 25% on false positives, and teams with 16+ tools have 50% burnout. | RETIRED | Research owner | Exact primary sources and methods not established | 2026-07-29 | Only with primary studies | Remove the bundle and each number independently. |
| M-05 | The average surveyed organization uses 83 security tools. | VERIFIED | Research owner | SRC-IBM; survey of 1,000 executives | 2026-07-29 | 2026-10-27 | Attribute to the IBM IBV study; do not generalize to all organizations. |
| M-06 | Agent fleets doubled in one quarter; 38% of organizations run over 100 agents; 24.4% have full inter-agent visibility. | RETIRED | Research owner | Exact primary longitudinal source not established | 2026-07-29 | Only with primary study | Remove. |
| M-07 | Enterprises expose 150,000+ agent-linked resources and 82% were built by non-developers. | RETIRED | Research owner | Exact primary source not established | 2026-07-29 | Only with primary study | Remove. |
| M-08 | 38% of MCP servers have no active authentication controls. | UNVERIFIED | Research owner | Repeated in secondary material; original dataset and sampling not established | 2026-07-29 | 2026-08-29 | Prohibited until the original study is obtained and audited. |
| M-09 | Over-permissioning causes 61% of agent incidents and only 22% treat agents as independent identities. | RETIRED | Research owner | Exact primary source not established | 2026-07-29 | Only with primary study | Remove. |
| M-10 | Tool fragmentation and repeated integration work create a meaningful adoption opportunity for a unified workbench. | VALUE HYPOTHESIS | Product owner | SRC-IBM plus user research still required | 2026-07-29 | 2026-09-29 | Use as a problem hypothesis, not a measured market fact. |
| M-11 | SOVA adoption will occur in weeks because switching costs are zero. | VALUE HYPOTHESIS | Product owner | No adoption cohort | 2026-07-29 | After public alpha | Prohibited as a forecast. Track installation, retention, and contribution evidence. |
| M-12 | A public registry creates a self-reinforcing network effect and durable corpus advantage. | VALUE HYPOTHESIS | Product owner | No registry adoption data | 2026-07-29 | After registry pilot | State as strategy, not established moat. |

## Legal and standards claims

| ID | Controlled claim | Status | Owner | Evidence | Checked | Recheck | Public decision |
|---|---|---|---|---|---|---|---|
| L-01 | All EU AI Act enforcement powers “activate” on 2 August 2026. | RETIRED | Founder plus counsel | SRC-EU-FAQ; SRC-EU-LAW | 2026-07-29 | On legal change | The Act has phased dates; governance and GPAI rules applied earlier and some high-risk dates were extended. |
| L-02 | EU AI Act penalties can reach EUR 35 million/7%, EUR 15 million/3%, or EUR 7.5 million/1%, subject to category and entity rules. | PROVISIONAL | Founder plus counsel | SRC-EU-FAQ; SRC-EU-LAW | 2026-07-29 | 2026-08-29 | Cite the exact infringement category; obtain counsel before product compliance claims. |
| L-03 | EUR 15 million/3% is a specific penalty for failure to perform adversarial testing. | RETIRED | Founder plus counsel | SRC-EU-FAQ; SRC-EU-LAW | 2026-07-29 | On legal change | The simple dedicated-category wording is unsupported. |
| L-04 | Articles 12, 15, and 55 make SOVA output compliance proof. | RETIRED | Founder plus counsel | SRC-EU-LAW | 2026-07-29 | On legal change | SOVA may support evidence collection; applicability and conformity are context-specific legal questions. |
| L-05 | AI interaction logs must carry the same chain-of-custody properties as all security evidence from 2026. | RETIRED | Founder plus counsel | No universal legal authority located | 2026-07-29 | Only with jurisdiction-specific authority | Treat chain of custody as sound evidence engineering, not a universal legal rule. |
| L-06 | Apache-2.0 permits commercial use and redistribution while preserving licence/notice duties and withholding trademark rights. | VERIFIED | Governance owner | [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0); SRC-OSI | 2026-07-29 | 2027-01-29 | Allowed; not legal advice for a specific distribution. |
| S-01 | OpenTelemetry defines GenAI semantic-convention attributes. | VERIFIED | Evidence owner | SRC-OTEL | 2026-07-29 | 2026-08-29 | Pin a convention version; portions remain Development status. |
| S-02 | DSSE signs typed arbitrary payloads and Sigstore supports verifiable bundles. | VERIFIED | Evidence owner | SRC-DSSE; SRC-SIGSTORE | 2026-07-29 | 2026-10-27 | Build on these standards; signing authenticates bytes and signer context, not truth. |
| S-03 | SARIF 2.1.0 is an established interchange format for static-analysis results. | VERIFIED | Evidence owner | SRC-SARIF | 2026-07-29 | 2027-01-29 | Export findings to SARIF; do not force execution traces into SARIF. |
| S-04 | SPDX 3 includes profiles useful for software and AI supply-chain descriptions. | VERIFIED | Evidence owner | SRC-SPDX | 2026-07-29 | 2026-10-27 | Interoperate; do not invent a competing SBOM vocabulary. |
| S-05 | Selective-disclosure and redaction-preserving cryptographic proof are unoccupied ideas. | RETIRED | Research owner | SRC-SDJWT; SRC-BBS | 2026-07-29 | On new design | Existing standards occupy the general concept. SOVA can research trace-specific composition and usability. |
| S-06 | MITRE ATLAS and OWASP Agentic Top 10 provide relevant security taxonomies. | VERIFIED | Taxonomy owner | SRC-ATLAS; SRC-OWASP | 2026-07-29 | 2026-10-27 | Map to them; do not claim they are exhaustive or legally binding. |

## Comparative, novelty, and research claims

| ID | Controlled claim | Status | Owner | Evidence | Checked | Recheck | Public decision |
|---|---|---|---|---|---|---|---|
| C-01 | Unknown dormant-condition or sleeper-trigger search is unoccupied. | RETIRED | Research owner | SRC-ASB; SRC-TRIGGER; SRC-SLEEPER | 2026-07-29 | Never restore broadly | Direct counterexamples exist. Narrow future claims to a measured SOVA method and target class. |
| C-02 | No system addresses adaptive long-horizon, multi-turn, memory, or compositional agent attacks. | RETIRED | Research owner | SRC-AGENTLAB; SRC-STAC; SRC-ASB | 2026-07-29 | Never restore broadly | Compare against these systems rather than describing the area as empty. |
| C-03 | No tool connects attack, evidence, replay, attribution, and reporting in one workflow. | RETIRED | Research owner | SRC-AIR; SRC-HMA; dense adjacent prior art; no exhaustive universal proof is possible | 2026-07-29 | Never restore universally | AIR Blackbox and HackMyAgent occupy substantial parts of the proposed chain. Claim exact implemented workflow properties, not universal absence. |
| C-04 | Counterfactual agent-failure attribution is unaddressed. | RETIRED | Research owner | SRC-CAR; SRC-AGENTRACER | 2026-07-29 | Never restore broadly | Causal Agent Replay is a direct counterexample. Interoperate and compare. |
| C-05 | State-of-the-art failure attribution has about 29% exact accuracy. | RETIRED | Research owner | SRC-WHOWHEN reports materially different agent- and step-level figures | 2026-07-29 | Never restore as blanket number | Report benchmark, task, level, metric, and version separately. |
| C-06 | `.sova` is the first portable executable agent-vulnerability format. | UNVERIFIED | Format owner | No exhaustive format review; adjacent scenario and benchmark formats exist | 2026-07-29 | Before 1.0 or paper | Do not make historical priority claims. Demonstrate portability through independent implementations. |
| C-07 | Nobody reports semantic reproduction rates for agent vulnerabilities. | RETIRED | Research owner | Repeated-trial success rates are common; terminology alone is not novelty | 2026-07-29 | Never restore broadly | Define and validate SOVA’s exact metric without claiming category ownership. |
| C-08 | Scanner disagreement is high enough that execution-based adjudication adds value. | UNVERIFIED | Research owner | Gate 01-A not run; SRC-HMA reports a scanner-overlap figure that remains a project claim until reproduced | 2026-07-29 | After comparison | Measure overlap, unique findings, confirmation, and false positives first. |
| C-09 | Passive agent recorders are numerous and observability conventions exist. | VERIFIED | Research owner | SRC-OTEL; SRC-AIR; SRC-AGENTLENS; OpenInference and Phoenix repositories in the prior-art matrix | 2026-07-29 | 2026-08-29 | Interoperate; do not call recording an empty category. |
| C-10 | Existing red-team tools leave only screenshots and cannot produce structured evidence. | RETIRED | Research owner | SRC-HMA; current red-team tools export JSON/SARIF or structured run records | 2026-07-29 | Never restore broadly | Compare exact evidence fields and verification properties. |
| C-11 | Transitive capability mapping is under-served. | UNVERIFIED | Research owner | No complete mapping benchmark or market census | 2026-07-29 | 2026-08-29 | Keep as a research question. |
| C-12 | Phantom Fuzzer’s API/UI combination is unmatched. | RETIRED | Research owner | No exhaustive search; absolute comparison unsupported | 2026-07-29 | Never restore broadly | Treat any future implementation as a feature, not a priority claim. |
| C-13 | SOVA catches confirmed dormant or multi-turn defects that strong baselines miss. | UNVERIFIED | Research owner | Gate 01-A = NOT RUN | 2026-07-29 | After Gate 01-A | Public claim prohibited. |
| C-14 | SOVA’s counterfactual analysis identifies the responsible layer accurately. | UNVERIFIED | Research owner | Gate 01-B = NOT RUN | 2026-07-29 | After Gate 01-B | Public claim prohibited. |
| C-15 | VIPER-MCP combines code-guided analysis with dynamic exploit confirmation for MCP servers. | VERIFIED | Research owner | SRC-VIPER | 2026-07-29 | 2026-08-29 | Required baseline/prior art for MCP exploit confirmation. |
| C-16 | SOVA’s integrated artifact/evidence workflow is more useful than separate tools. | VALUE HYPOTHESIS | Product owner | No comparative usability study | 2026-07-29 | After alpha study | Test end-to-end completion time, evidence quality, and reproduction success. |
| C-17 | SOVA is the best, easiest, or most complete agent-security workbench. | VALUE HYPOTHESIS | Product owner | No predeclared usability comparison | 2026-07-29 | After alpha study | Aspirational only; no factual badge or table entry. |
| C-18 | Trigger search, semantic replay, evidence fusion, or causal attribution contains a patentable SOVA invention. | UNVERIFIED | Founder plus counsel | Prior art is substantial; no legal opinion | 2026-07-29 | Before mechanism disclosure | Hold mechanism-bearing disclosure; obtain qualified counsel. |

## Retired-claims ledger

The following phrasings must not return through README edits, talks, papers,
issues, demos, benchmark captions, or release notes:

1. “Conditional-trigger search is unoccupied” or “nobody hunts the sleeper.”
2. “No benchmark covers adaptive long-horizon or compositional agent attacks.”
3. “SOVA is the only system where the attacker and recorder are the same.”
4. “Nobody connects attack to evidence to forensics to compliance proof.”
5. “Counterfactual agent-failure attribution is unaddressed.”
6. “Attribution tops out at about 29% exact accuracy.”
7. “The reproduction rate is a metric nobody has.”
8. “Redaction-preserving verifiable evidence is an unoccupied idea.”
9. “Existing red-team tools leave only screenshots.”
10. “Phantom Fuzzer is unmatched.”
11. “All EU AI Act enforcement powers activate on 2 August 2026.”
12. “EUR 15 million/3% is the adversarial-testing-failure penalty.”
13. “AI logs became legal evidence in 2026 and therefore universally require a
    particular chain of custody.”
14. The unsupported 80%, 78%, 25%, 50%, 38%, 61%, 22%, fleet-growth,
    resource-count, and incident-story figures listed as retired above.
15. “SOVA proves a target safe,” “clean,” “unforgeable,” or universally
    deterministic.

## Replacement language

Use:

> SOVA OSS is being built as a local, integrated agent-security workbench that
> can import existing analysis, exercise authorized targets, capture portable
> evidence, and support verification and repeated reproduction. Its comparative
> detection and attribution claims are withheld until the predeclared
> experiments pass.

For conditional behavior, use:

> SOVA researches bounded search for conditional and long-horizon agent
> failures. This is an active field with strong prior art; SOVA will claim only
> measured improvements against named baselines.

For legal/compliance positioning, use:

> SOVA can help collect and organize technical evidence. It does not determine
> legal compliance, perform conformity assessment, or issue independent
> attestation.

## Master-document coverage map

This map prevents a claim family from disappearing merely because its wording
was grouped into one controlled claim.

| Master area | Claim IDs |
|---|---|
| 0.1-0.4 identity, value, and claim rules | P-01 to P-06; C-16; C-17 |
| 1.1 forensic incident and survey | M-01; M-02; L-05 |
| 1.2-1.4 plumbing, fragmentation, visibility | M-03 to M-10 |
| 1.5 compliance and penalties | L-01 to L-05 |
| 1.6 reproducibility | P-04; P-05; P-11; C-06; C-07 |
| 1.7 permission and identity | M-08; M-09 |
| 2-5 product positioning and “famous for” statements | P-01 to P-14; C-01 to C-04; C-13 to C-17 |
| 3 competitive map | C-01 to C-12; S-01 to S-06 |
| 6 command/capability descriptions | P-07 to P-14 |
| 7-9 adoption, daily use, and demos | P-08; P-09; M-10 to M-12; C-13; C-16; C-17 |
| 10 TRUSCOR boundary | P-02; P-06; L-06 |
| 11 architecture and evidence standards | P-03; P-10 to P-12; S-01 to S-06 |
| 12 governance and ethics | P-06; P-12; L-04; L-06 |
| 13 research agenda and revolutionary bets | C-01 to C-18; S-05 |
| 14-15 build order and launch narrative | P-07 to P-14; C-13; C-14; C-16; C-17 |
| 16 legacy claims register | C-01 to C-15; L-01 to L-05; M-01 to M-09; S-01 |
| Amendment A | P-02; P-12; M-12; L-06 |
| Amendment B | P-03; P-07 to P-10; P-12 |
| Amendment C | P-01 to P-03; P-08; P-12; M-12 |

## Change process

1. A public claim must cite one or more register IDs.
2. The exact claim wording must not exceed what the evidence supports.
3. The owner checks the source, date, methodology, scope, and conflicts.
4. Comparative results must cite a frozen protocol and immutable run bundle.
5. Legal claims require qualified counsel before a release relies on them.
6. New novelty claims require a current prior-art search and the publication/IP
   review.
7. A failed claim is marked **RETIRED** and retained in the ledger.
8. Pull requests update the register before changing public positioning.

This register is evidence governance, not a representation that SOVA has
implemented the planned capabilities.
