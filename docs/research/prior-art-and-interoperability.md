# SOVA OSS prior-art and interoperability matrix

- **Matrix version:** 1.0
- **Snapshot date:** 2026-07-29
- **Owner:** Gautam R. Patil
- **Next full recheck:** 2026-08-29

This is a decision matrix, not a claim that the listed field is exhaustive. It
answers two questions:

1. What already exists and therefore must constrain SOVA’s novelty language?
2. Should SOVA build, integrate, import, interoperate with, or deliberately skip
   each overlapping capability?

## Action vocabulary

| Action | Meaning |
|---|---|
| **Build** | Implement the SOVA-owned capability because it is part of the public instrument. |
| **Integrate** | Offer an optional, user-visible adapter or runner around the external project. |
| **Import** | Parse the project’s output into SOVA’s neutral finding/evidence model. |
| **Interoperate** | Exchange standard artifacts or run side by side without incorporating its code. |
| **Skip** | Deliberately do not rebuild or vendor that overlapping capability. |

These actions are not mutually exclusive. “Skip” usually means SOVA still
imports or interoperates with the existing implementation.

## Controlling conclusions

1. Conditional, dormant, adaptive, long-horizon, memory, and compositional
   attacks are active research areas. SOVA must not describe them as empty.
2. Counterfactual agent-failure attribution has direct prior art. SOVA must
   compare against intervention-based work, not claim the method category.
3. Static scanning, generic red-team probe libraries, observability collectors,
   browser/OS benchmark environments, signing envelopes, and analysis-result
   formats should not be rebuilt from zero.
4. SOVA’s defensible product position is the quality of the integrated loop:
   authorized execution, deterministic security oracles, portable artifacts,
   verifiable evidence, repeated reproduction, and cross-tool adjudication.
5. Any research moat must be earned by the frozen comparison. “First,” “only,”
   and “nobody” claims are not an acceptable substitute.

## Static MCP and skill scanning

| Project | What the primary source establishes | Overlap with SOVA | Decision |
|---|---|---|---|
| [Cisco MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner) | MCP tool/prompt/resource scanning with YARA, LLM, API, dependency, readiness, package, and behavioural-code modes. | Discovery and static findings. | **Integrate + import + skip** a duplicate general static scanner. Preserve engine identity and raw evidence. |
| [Snyk Agent Scan](https://github.com/snyk/agent-scan) | Discovers local agents, MCP servers, and skills and scans for prompt injection, sensitive-data, and malware risks. | Inventory and component risk findings. | **Integrate + import** experimental JSON with version pinning. Do not depend on unstable fields. |
| [NVIDIA SkillSpector](https://github.com/NVIDIA/skillspector) | Static analysis of agent skills and instructions. | Skill scanning. | **Import + interoperate**; use as a named baseline. |
| [Ant Group MCPScan](https://github.com/antgroup/MCP-Security) | MCP security scanning and related research artifacts. | MCP static/dynamic security surface. | **Interoperate** after a licence and output-schema review. |
| [HackMyAgent](https://github.com/opena2a-org/hackmyagent) | Project-documented static, semantic, behavioural-simulation, adaptive red-team, runtime, JSON, and SARIF capabilities. | Broad inventory, scanning, attack, runtime, and evidence overlap. | **Integrate + import + compare.** Treat project performance figures as claims until independently reproduced. Do not dismiss it as a narrow attacker. |

SOVA will build a neutral scanner-adapter contract, normalised finding model,
provenance capture, disagreement view, and execution-based adjudication. It will
not initially build another YARA engine, dependency scanner, malware service, or
generic LLM judge.

## Agent-mediated exploit and red-team tools

| Project | What the primary source establishes | Overlap with SOVA | Decision |
|---|---|---|---|
| [VIPER-MCP](https://arxiv.org/abs/2605.21392) | Code-guided taint analysis plus feedback-driven prompt evolution and dynamic exploit confirmation for MCP servers. | MCP exploit discovery and confirmation. | **Interoperate + compare.** Treat as required prior art. Do not reproduce its static-anchor method. Add an adapter if public code and licence permit. |
| [garak](https://github.com/NVIDIA/garak) | Extensible LLM vulnerability scanning with probes, detectors, harnesses, and reporting. | Probe libraries and model red teaming. | **Integrate + import + skip** rebuilding its broad probe catalogue. |
| [PyRIT](https://github.com/microsoft/PyRIT) | Orchestrated risk identification and multi-turn red-team workflows. | Attack orchestration and scoring. | **Integrate + import** selected runs; compare evidence completeness. |
| [promptfoo](https://github.com/promptfoo/promptfoo) | Declarative evaluation, red teaming, CI, and structured results. | One-pass dynamic baseline, evaluation, CI. | **Integrate + import** as the fixed-probe baseline. |
| [Inspect AI](https://github.com/UKGovernmentBEIS/inspect_ai) | Evaluation framework with tasks, solvers, scorers, logging, and sandbox support. | Evaluation harness and logs. | **Interoperate + import** rather than creating a second general evaluation framework. |
| [HackMyAgent](https://github.com/opena2a-org/hackmyagent) | Static/semantic scanning, behavioural simulation, adaptive red team, runtime protection, and structured output in one project. | Directly overlaps several planned SOVA verbs. | **Integrate + import + compare.** SOVA must demonstrate a better evidence/reproduction workflow rather than assume missing capability. |

SOVA will build the authorization envelope, bounded target driver, security
oracles, trace/evidence conversion, repeated confirmation, and cross-engine
adjudication. It may execute existing red-team libraries through adapters.

## Dynamic targets, sandboxes, and vulnerable-agent projects

| Project | What the primary source establishes | Licence/use note | Decision |
|---|---|---|---|
| [AgentDojo](https://github.com/ethz-spylab/agentdojo) | Dynamic agent environments for prompt-injection attacks and defences. | MIT; use a pinned local snapshot. | **Integrate + interoperate.** First representative public benchmark target. |
| [OWASP FinBot CTF](https://github.com/GenAI-Security-Project/finbot-ctf) | Deliberately vulnerable local financial-agent environment with agents, MCP servers, challenges, detectors, and evaluators. | Apache-2.0; local and non-destructive use only. | **Integrate.** First public vulnerable target and end-to-end demo environment. |
| [Agent Security Bench](https://github.com/agiresearch/ASB) | Agent attacks/defences including Plan-of-Thought backdoors and memory poisoning. | MIT; reproduce only selected licence-compatible fixtures. | **Interoperate + compare.** Import result summaries, not undocumented internals. |
| [AgentLAB](https://github.com/TanqiuJiang/AgentLAB) | Adaptive long-horizon intent hijacking, tool chaining, objective drift, task injection, and memory poisoning across many environments. | MIT at the checked revision; model/provider costs and nested data licences still require review. | **Interoperate + compare.** Strong long-horizon baseline. |
| [STAC](https://github.com/amazon-science/MultiTurnAgentAttack) | Sequential Tool Attack Chaining and a 483-case benchmark. | Repository states CC BY-NC 4.0 and is archived. Do not import into Apache distributions. | **Interoperate externally + compare.** Research-only runner; no vendoring. |

SOVA will build a small suite of synthetic, owned, deterministic fixtures
because hidden ground truth and negative controls are required. It will not
build a general cloud sandbox platform or copy third-party benchmark
environments into the repository without a recorded licence/provenance review.

## Passive recorders and observability

| Project or standard | What the primary source establishes | Decision |
|---|---|---|
| [OpenTelemetry core semantic conventions](https://opentelemetry.io/docs/specs/semconv/) and the separate [experimental GenAI repository](https://github.com/open-telemetry/semantic-conventions-genai) | Common telemetry attributes; the GenAI repository has no release and currently requires an exact commit pin. | **Build on + pin.** Use core `1.43.0`, mark the GenAI mapping experimental, and add SOVA evidence extensions instead of forking the vocabulary. |
| [OpenInference](https://github.com/Arize-ai/openinference) | Open instrumentation conventions and framework integrations for AI observability. | **Import + interoperate.** First passive-recorder baseline. |
| [Phoenix](https://github.com/Arize-ai/phoenix) | Open-source AI observability and evaluation platform. | **Import + interoperate.** Do not rebuild a general trace UI. |
| [Langfuse](https://github.com/langfuse/langfuse) | Open-source LLM observability, evaluation, prompt, and trace workflows. | **Import + interoperate.** Keep its licence/deployment boundary separate. |
| [AIR Blackbox](https://github.com/airblackbox/airblackbox) | Project-documented record, replay, enforcement, compliance scans, signed/tamper-evident records, and evidence export. | **Integrate + import + compare.** This is direct prior art for much of the proposed unified evidence chain; independently test its claims. |
| [AgentLens](https://github.com/agentkitai/agentlens) | MCP-native capture, hash-chained events, offline verification, and a queryable dashboard. | **Import + interoperate.** Do not claim tamper-evident agent recording is unique to SOVA. |
| [MakerChecker](https://www.makerchecker.ai/) | Project-documented capability scanning, segregation of duties, approval controls, and signed offline-verifiable logs. | **Track + interoperate** after its public repository, licence, and interfaces are pinned. |

SOVA will build trace normalization, security-specific observations,
provenance, redaction manifests, integrity verification, and forensics over
imported traces. It will skip a general-purpose telemetry collector backend and
general observability dashboard until evidence shows a SOVA-specific gap.

## Agent-security benchmarks and scenario collections

| Project | Relevant coverage | Decision |
|---|---|---|
| [Agent Security Bench](https://arxiv.org/abs/2410.02644) | Multiple agent attacks and defences, including backdoor and memory cases. | **Interoperate + compare.** |
| [AgentLAB](https://arxiv.org/abs/2602.16901) | Long-horizon attacks over user-agent-environment interaction. | **Interoperate + compare.** |
| [AgentDyn](https://arxiv.org/abs/2602.03117) | Open-ended dynamic tasks and prompt-injection cases. | **Interoperate** when artefacts and licence are verified. |
| [AgentDojo](https://arxiv.org/abs/2406.13352) | Dynamic prompt-injection environments with attack/defence evaluation. | **Integrate + compare.** |
| [STAC](https://arxiv.org/abs/2509.25624) | Sequential composition of individually innocuous tools. | **Interoperate externally + compare.** |
| [MCP Security Bench](https://arxiv.org/abs/2510.15994) | MCP-focused benchmark coverage. | **Interoperate** after artefact/licence verification. |
| [Open Agent Security Benchmark](https://github.com/opena2a-org/oasb) | 222 product-evaluation scenarios across AI, process, network, filesystem, enforcement, and multi-step surfaces with a product adapter. | **Integrate + run in full.** It evaluates security products rather than vulnerable agents, so report it separately from Gate 01-A target discovery. |

SOVA’s public `.sova` scenarios should be adapters or independently authored
translations with provenance, not silent copies. Results must retain benchmark,
scenario, model, configuration, licence, and revision identity.

## Task-failure and causal-attribution research

| Project | What it establishes | Decision |
|---|---|---|
| [Who & When](https://arxiv.org/abs/2505.00212) and [Who & When Pro](https://arxiv.org/abs/2607.09996) | Ground-truth agent/step failure-attribution benchmarks; accuracy depends strongly on level and benchmark. | **Interoperate + compare.** Use exact metric/level; never repeat a blanket “29%” figure. |
| [AgenTracer](https://arxiv.org/abs/2509.03312) | Automated agentic failure tracing. | **Compare** on a compatible held-out attribution set. |
| [Causal Agent Replay](https://arxiv.org/abs/2606.08275) | Intervention-based re-execution, contrastive effects, and Shapley-style interaction attribution. | **Interoperate + compare.** Direct counterexample to broad counterfactual-novelty claims. |
| [VerifyMAS](https://arxiv.org/abs/2605.17467) | Verification-oriented multi-agent failure analysis. | **Track + compare** where tasks overlap. |

SOVA will build a security-layer attribution interface and planted
ground-truth suite. It will not claim the general concept of counterfactual
replay. Any novel claim must identify a narrower security problem, method, and
measured result.

## Adversarial arenas and computer-use benchmarks

| Project | Relevant coverage | Decision |
|---|---|---|
| [RedTeamCUA](https://arxiv.org/abs/2505.21936) | Red teaming computer-use agents. | **Interoperate + compare later.** |
| [OSWorld](https://github.com/xlang-ai/OSWorld) | Real computer-task environment for multimodal agents. | **Integrate later.** Do not rebuild its OS environment. |
| [BrowserGym](https://github.com/ServiceNow/BrowserGym) | Browser-agent research and benchmark environment. | **Integrate later.** Use as a browser execution target. |
| [AdvCUA](https://arxiv.org/abs/2510.06607) | Adversarial computer-use-agent evaluation. | **Track + interoperate later.** |

Browser/computer testing is outside the first no-Atlas slice. SOVA will add
adapters after the evidence core and authorization boundary work without making
Atlas, OSWorld, or BrowserGym the trust root.

## Evidence, disclosure, compliance, and supply-chain ecosystems

| Standard/ecosystem | SOVA use | Decision |
|---|---|---|
| [DSSE](https://github.com/secure-systems-lab/dsse) | Typed signing envelope for arbitrary payloads. | **Build on.** No bespoke signature envelope. |
| [Sigstore bundles](https://docs.sigstore.dev/cosign/verifying/verify/) | Portable signature, certificate, and transparency-verification material. | **Interoperate.** Support offline verification with explicit trust inputs. |
| [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) | Static-analysis result export/import. | **Import + export.** Do not encode complete traces as SARIF. |
| [SPDX 3](https://spdx.dev/use/specifications/) | Software and AI supply-chain descriptions. | **Interoperate.** Reference components rather than inventing an SBOM. |
| [OpenTelemetry](https://opentelemetry.io/docs/specs/semconv/) | Event/trace vocabulary and propagation. | **Build on + pin.** Preserve unknown fields. |
| [RFC 9901 SD-JWT](https://www.rfc-editor.org/rfc/rfc9901.html) | Selective disclosure for JSON claims. | **Study + interoperate where appropriate.** General selective disclosure is prior art. |
| [W3C BBS cryptosuite](https://www.w3.org/TR/vc-di-bbs/) | Selective disclosure and unlinkable derived proofs for credentials. | **Study.** Do not claim the cryptographic concept; the specification is still a Candidate Recommendation. |
| [MITRE ATLAS](https://atlas.mitre.org/) | AI threat taxonomy. | **Map to.** Preserve SOVA-specific detail. |
| [OWASP Agentic Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | Agentic-risk taxonomy and guidance. | **Map to.** Not a verdict or legal standard. |
| [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) | Voluntary AI risk-management framework. | **Export supporting evidence mappings.** Never call a mapping certification. |
| [AIR Blackbox](https://github.com/airblackbox/airblackbox) | Compliance-oriented scanning, audit records, replay, and evidence export. | **Compare + import.** Do not assume SOVA is the first integrated compliance/evidence workflow. |

## Focused Topics 09–11 prior-art screen

The 2026-08-02 primary-source refresh materially limits broad novelty claims:

| Area | Strong primary sources | SOVA decision |
|---|---|---|
| Capability and permission graphs | [BloodHound](https://github.com/SpecterOps/BloodHound), [AWS IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-concepts.html), [W3C PROV-O](https://www.w3.org/TR/prov-o/), and [Agent-BOM](https://arxiv.org/abs/2605.06812) | Graph construction, transitive reach, effective permissions, and provenance are established. SOVA's separated declared/observed/inferred/refuted closures are an experimental hypothesis requiring a named-baseline ground-truth study. |
| Tool-definition drift | [MCP tools specification](https://modelcontextprotocol.io/specification/2025-06-18/server/tools) and [Microsoft MCP Security Gateway 1.0](https://microsoft.github.io/agent-governance-toolkit/specs/MCP-SECURITY-GATEWAY-1.0/) | Description/schema fingerprints and rug-pull alerts are ordinary engineering and `NO-GO` as standalone SOVA paper or patent claims. |
| Multi-role red teaming | [Co-RedTeam](https://arxiv.org/abs/2602.02164), [AutoRedTeamer](https://arxiv.org/abs/2503.15754), and [Petri](https://www.anthropic.com/research/petri-open-source-auditing) | Recon/plan/execute/evaluate/mutate roles and experience-guided iteration are direct prior art. SOVA implements them without claiming architecture novelty. |
| Adversarial judges | [JudgeDeceiver](https://arxiv.org/abs/2403.17710), [judge prompt-injection study](https://arxiv.org/abs/2505.13348), and [Instruction Hierarchy](https://arxiv.org/abs/2404.13208) | Raw transcript judging is an attack surface. SOVA's typed one-way evidence firewall is `GO-EXPERIMENT / HOLD-PAPER / HOLD-IP` pending attack, clean-utility, ablation, calibration, and independent-case results. |
| Delegated sessions | [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html), [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html), [SPIFFE Workload API](https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/), and [Playwright authentication](https://playwright.dev/docs/auth) | Scoped leases, delegated identity, token protection, and isolated browser state are established security practice, not a standalone invention. |

The focused patent-publication screen also found extensive access-graph,
multi-agent orchestration, retry/recovery, and delegated-credential claims.
No broad Topics 09–11 patent draft is justified. Private records retain the
publication numbers, preliminary overlap notes, prospectuses, kill criteria,
and founder/counsel review gates; no novelty-bearing private record is published
from this repository.

## Acquisition record for the first comparison

The following revisions were resolved from each public repository’s `HEAD` on
2026-07-29. A benchmark run must mirror these repositories into an isolated
research environment, verify the licence file and nested asset provenance, and
record a content digest before installing anything.

| Component | Pinned revision | Recorded licence/use boundary | Role |
|---|---|---|---|
| AgentDojo | `089ed468cf3ed0322acc66b0211f26d9d90dbf60` | MIT | Public dynamic target |
| OWASP FinBot CTF | `1450fc4d15cbe80dbaf52dde1df767dbc967e32e` | Apache-2.0 | Public vulnerable target |
| Agent Security Bench | `1f561dccf92d55302368fa67679b4ba9d9c8fdc4` | MIT | Backdoor/memory baseline |
| AgentLAB | `36f58e60c36bbd6d5b8e61d50d7db7d9ea7258d7` | MIT at repository root; nested assets still require review | Long-horizon baseline |
| STAC | `ddeede7a0042d108b819e35281135b0b0fabb4de` | CC BY-NC 4.0; external research use only | Compositional baseline |
| Cisco MCP Scanner | `94e61145a5bd6ae39eabcc52a686830e1ec73be0` | Apache-2.0 | Static baseline |
| Snyk Agent Scan | `dd057dc8db363678b3cfbe6b4012579002e9d32e` | Apache-2.0; output/API terms must be respected | Static baseline |
| NVIDIA SkillSpector | `34f60308522f45447cd343da0aad77bcea308ad4` | Recheck before installation | Skill-scanner baseline |
| garak | `0b51f87acda1c0ab22a88dff6fd304f3299c9ce4` | Recheck before installation | Red-team adapter candidate |
| PyRIT | `0d239528377dc3216f27d074a730551ab037185c` | Recheck before installation | Red-team adapter candidate |
| promptfoo | `ac8971fcfa961fa5fa96bcc4f527f5309b504997` | Recheck before installation | One-pass dynamic baseline |
| OpenInference semantic conventions 0.1.30 | `789d41974c08a9a13147977f28ef4142a07e2106` | Apache-2.0; PyPI Trusted Publishing attestation and source commit verified 2026-08-01 | Passive-recorder and interoperability baseline |
| Open Agent Security Benchmark | `5e4d4569573ddd8c1e4494ec23950a45cbdc9ca5` | Apache-2.0; verify nested corpus provenance | Security-product evaluation suite |
| HackMyAgent | `4837510cb3afefea93920ed311a1749651a78188` | Apache-2.0 | Integrated scanner/red-team baseline |
| AIR Blackbox | `e4184ab8c24f39c0027387704f2f8e27044c5f41` | Apache-2.0 | Integrated recorder/replay/evidence baseline |
| AgentLens | `406a8739ebdca7d200486b9eee6bf590a9633b66` | MIT | Passive recorder and integrity baseline |

The first runnable subset is legally and operationally scoped to:

- SOVA-owned synthetic fixtures;
- AgentDojo at the pinned MIT revision;
- OWASP FinBot CTF at the pinned Apache-2.0 revision;
- Cisco MCP Scanner and Snyk Agent Scan at their pinned Apache-2.0
  revisions;
- AgentLAB/ASB only after nested-data and dependency provenance is recorded.
- OASB, HackMyAgent, AIR Blackbox, and AgentLens at the pinned revisions after
  nested-data, dependency, install-script, and output-term review.

No live third-party service, public MCP server, production agent, real
credential, or outbound internet target belongs in the comparison.

## Fair-competition rule

SOVA may not:

- omit a stronger available baseline because it makes the result harder;
- compare against a tool outside the surface it claims to measure;
- convert an unavailable baseline into a weaker home-made surrogate without
  saying so;
- count scanner disagreement as scanner error without execution evidence;
- count an LLM judge alone as exploit confirmation;
- use unpublished answer keys, tuned budgets, or target-specific prompts for
  SOVA while denying them to a method whose documented workflow requires them;
- describe imported capability as SOVA invention.

Every result must name the project, exact revision, licence/use boundary,
configuration, model, provider, cost, duration, and any deviation from its
documented standard run.

## Topic 04-05 capsule and trace prior art

Review snapshot: 2026-07-30.

The `.sova`/`.sova-trace` implementation deliberately composes established
mechanisms. It makes no broad novelty claim for packaging, recording,
content-addressing, signing, replay, or reproducibility.

| Primary source | Established capability | SOVA consequence |
|---|---|---|
| [Inspect AI eval logs](https://inspect.aisi.org.uk/eval-logs.html) | Incremental evaluation logs, binary/container storage, deduplication, compression, run configuration | Compare portability, size, random access, and replay semantics; do not claim rich agent eval logs are new |
| [MLflow tracing](https://mlflow.org/docs/latest/genai/tracing/) | OTel-compatible model, agent, tool, retriever, and memory tracing | Import with a fidelity report rather than replace general observability |
| [OpenTelemetry core semantic conventions 1.43.0](https://opentelemetry.io/docs/specs/semconv/) | Versioned cross-system telemetry conventions; GenAI moved to a separate unreleased repository | Pin core tag/commit, pin the experimental GenAI repository by commit, and preserve unknown source attributes |
| [OpenInference 0.1.30](https://pypi.org/project/openinference-semantic-conventions/) | AI-specific span semantics and integrations | First passive interoperability target |
| [RO-Crate 1.3](https://www.researchobject.org/ro-crate/specification/1.3/index.html) and [W3C PROV-O](https://www.w3.org/TR/prov-o/) | Research-object packaging and provenance | Export/reuse concepts; SOVA remains execution- and evidence-aware |
| [OCI descriptors](https://github.com/opencontainers/image-spec/blob/main/descriptor.md) | Media type, digest, size, content addressing | Reuse descriptor pattern; OCI distribution remains optional |
| [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md), [DSSE](https://github.com/secure-systems-lab/dsse), and [Sigstore bundles](https://docs.sigstore.dev/about/bundle/) | Typed attestations, type-bound signatures, portable verification material | No bespoke signature envelope; trust policy remains explicit |

Patent records are prior-art signals, not a legal freedom-to-operate opinion:

| Record | Theme |
|---|---|
| [US8032831B2](https://patents.google.com/patent/US8032831B2/en) | Historical workflow capture and visual replay |
| [US9170915B1](https://patents.google.com/patent/US9170915B1/en) | Workflow-history replay to reconstruct application state |
| [US8578340B1](https://patents.google.com/patent/US8578340B1/en) | Program execution recording and replay of nondeterministic events |
| [US10802822B2](https://patents.google.com/patent/US10802822B2/en) | Reproducible ML using environment, data, code, configuration, and hashes |
| [US11829853B2](https://patents.google.com/patent/US11829853B2/en) | Model-run provenance, dependencies, and reproducible execution |
| [US10540624B2](https://patents.google.com/patent/US10540624B2/en) | Provenance-aware application execution and recorded subsequences |
| [US20170032151A1](https://patents.google.com/patent/US20170032151A1/en) | Event-log tamper detection with hashes and signatures |
| [US11295031B2](https://patents.google.com/patent/US11295031B2/en) | Chained tamper-resistant event records |
| [US11368307B1](https://patents.google.com/patent/US11368307B1/en) | Multiparty log authenticity and ordering verification |

The research gap is narrower and remains unproven: whether one small typed
AI-behavior capsule can preserve enough procedure, environment, trace,
evaluation, and provenance meaning for useful controlled re-execution and
measured semantic reproduction across different agent runtimes. Any paper or
patent claim waits for implementation evidence, strong baselines, quantitative
experiments, limitations, private review, and qualified counsel.

## Topics 15-17 causal, adjudication, and composition prior art

Review snapshot: 2026-08-03.

This public record documents only established baselines and negative claim
boundaries. It intentionally excludes private invention hypotheses, claim
charts, unpublished experiment designs, and counsel material.

### Causal forensics

| Primary source | Established capability | SOVA consequence |
|---|---|---|
| [Causal Agent Replay](https://arxiv.org/abs/2606.08275) | Structural-causal agent replay, step interventions, stochastic outcome effects, confidence intervals, and interacting-step credit | Counterfactual agent replay and interaction attribution are direct prior art |
| [DoVer](https://arxiv.org/abs/2512.06749) | Intervention-driven hypothesis validation and explicit treatment of multiple distinct repairs | SOVA cannot assume or claim one unique responsible agent/step |
| [REFLECT](https://arxiv.org/abs/2606.09071) | Diagnosis-specific patching, controlled replay, and outcome-flip feedback into attribution | Patch-and-rerun causal validation is established |
| [TraceElephant](https://aclanthology.org/2026.acl-long.912/) | Full execution traces, reproducible environments, and comparison with partial observation | Missing-input/context handling and full-trace baselines are required |
| [Who&When Pro](https://arxiv.org/abs/2607.09996) | Large controlled fault-injection attribution corpus | Small same-team fixtures cannot support a state-of-the-art claim |

The public Topic 15 implementation is an evidence-bounded engineering
foundation. Its five deterministic cases validate supported and abstaining
paths; they do not establish real-system causal accuracy, novelty, or
superiority.

### Scanner adjudication

| Primary source | Established capability | SOVA consequence |
|---|---|---|
| [When Scanners Lie](https://arxiv.org/abs/2603.14633) | Measures evaluator instability and disagreement in LLM red-teaming | Scanner disagreement is already a direct empirical research topic |
| [VIPER-MCP](https://arxiv.org/abs/2605.21392) | Code-guided MCP analysis plus end-to-end dynamic exploit confirmation | Dynamic confirmation for agent-tool findings is direct prior art |
| [Trust but Verify](https://www.usenix.org/conference/usenixsecurity25/presentation/huang-szu-chun) | Compares vulnerability-tagging services against independent experiments | Execution-backed scanner assessment is established |
| [SARIF 2.1.0 plus Errata 01](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) | Interoperable static-analysis results and result identity | Import/export and result normalization are standards-based engineering |
| [US8935794B2](https://patents.google.com/patent/US8935794B2/en) | Dynamic unit-test validation of static-analysis findings | A broad dynamic-confirmation patent claim is not justified |

Topic 16 can support a useful comparative paper only after a representative,
licensed scanner-disagreement dataset and safe execution observations exist.
No public resolution-rate or scanner-ranking claim is currently permitted.

### Composition search

| Primary source | Established capability | SOVA consequence |
|---|---|---|
| [SCR-Bench](https://arxiv.org/abs/2606.15242) | Agent skills that are benign in isolation but harmful along capability, trust, or authorization composition paths | Composition-only agent-skill risk is direct prior art |
| [AgentThread](https://arxiv.org/abs/2606.28690) | Formal protocol checks, executable counterexamples, and failures emerging under protocol composition | Cross-protocol composition failure is direct prior art |
| [NIST ACTS](https://csrc.nist.gov/projects/automated-combinatorial-testing-for-software/) and [NIST SP 800-142](https://doi.org/10.6028/NIST.SP.800-142) | Pairwise/t-wise and sequence combinatorial testing, coverage, and fault localization | Pairwise, t-wise, and ordered-interaction search are mature methods |
| [Delta Debugging](https://www.st.cs.uni-saarland.de/papers/tse2002/) | Minimization of failure-inducing inputs/differences | Element removal and chain minimization are established |
| [US11010282B2](https://patents.google.com/patent/US11010282B2/en) | Constraint-aware n-wise tests, failure-neighborhood expansion, and fault localization | Broad constrained composition-localization claims are heavily occupied |
| [US11663113B2](https://patents.google.com/patent/US11663113B2/en) | Runtime reprioritization of tests after a failure | Adaptive/risk-like test ordering is occupied |

The public Topic 17 fixture proves only that the reference implementation can
find and minimize one planted composition-only effect. Risk-guided superiority,
real-system yield, novelty, and patentability remain unverified. Public SOVA
must compare with these sources rather than claim an empty category.

## Unresolved names from the planning source

The source planning document also named `unworldly`, `halo-record`,
`SkillReact`, `DVAA`, `AIVS`, `DoomArena`, `HackWorld`, and `DeepTeam`. Topic 01
did not find enough unambiguous primary identity, repository, licence, and
version evidence for every name to pin them safely. They are therefore
**UNVERIFIED REFERENCES**, not omitted competitors and not evidence of absence.

Before a paper or benchmark claims full coverage of the named planning set:

1. resolve the exact project/repository for each name;
2. record its revision, licence, maintained status, and actual capability;
3. add it to this matrix or record why it is out of scope;
4. version the comparison protocol if it becomes a required baseline.
