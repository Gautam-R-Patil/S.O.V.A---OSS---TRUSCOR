<!-- status: implemented -->

# P3 security-adapter and evidence-normalization validation

- **Date:** 2026-08-27
- **Branch:** `codex/universal-target-foundation`
- **Gate:** P3-01 through P3-10
- **Result:** implementation complete; repository-wide release validation passed

## Delivered boundary

P3 adds one SOVA-owned admission and execution boundary around external security
tools. The implementation contains:

- a 21-entry immutable catalog: 12 promoted adapters, eight constrained adapters,
  and one Nmap legal hold;
- exact version, licence, source/release, platform, target-predicate, capability,
  effect/network, parser, output, resource, privacy, and provenance contracts;
- runtime SHA-256 binding of operator-supplied executable bytes plus captured
  version evidence, target profile/generation, configuration, ruleset, and
  disclosure decisions;
- shell-free execution through the existing `process.exec` executor capability and
  authorization kernel;
- bounded JSON, JSONL, and entity/DTD-forbidding XML normalization into unconfirmed
  observations with raw-artifact digests;
- separate infrastructure, parser, partial-output, authorization, executable-drift,
  and cleanup states; and
- four inert CLI operations for catalog export, descriptor inspection, planning,
  and offline normalization. Effectful execution is available only through the
  Python API with a live authorization session and executor.

The normative behavior and non-claims are in the
[adapter specification](../specifications/security-tool-adapters-and-normalization-0.1.md).
The version, licence, privacy, update, and legal decisions are in the
[P3 research refresh](../research/p3-security-adapter-research-2026-08-27.md).

## Admission matrix

| Tier | Adapters | Admission result |
|---|---|---|
| Promoted | ZAP 2.17.0; Nuclei 3.11.1 with templates 10.4.7/`83234ce`; Schemathesis 4.24.3; PyRIT 1.0.1; garak 0.16.0; promptfoo 0.122.0; Trivy 0.73.0; Syft 1.50.0; Grype 0.116.1; OSV-Scanner 2.4.0; Gitleaks 8.30.1; Semgrep 1.164.0 | Dedicated descriptor and parser; policy-routed owned-fixture success, failure, and reproduction matrix |
| Constrained | ffuf 2.1.0; httpx 1.9.0; testssl.sh 3.2.3; sqlmap 1.10; mitmproxy 12.2.3; zgrab2 1.0.0; generic MCP stdio; generic HTTP | Present but requires explicit per-call opt-in; generic producer claims begin untrusted |
| Legal hold | Nmap, operator-supplied | No install, redistribution, or runner execution pending qualified NPSL/Npcap review |

No upstream source code, templates, rules, payloads, datasets, or prose were copied
or vendored. All catalog entries point to operator-supplied tools. Floating versions,
implicit downloads, and auto-update are not an installation mechanism.

## Checklist evidence

| IDs | Evidence |
|---|---|
| P3-01 | `AdapterDescriptor`, `ResourceBounds`, `PrivacyDefaults`, and `adapter-descriptor-0.1.0.schema.json` reject incomplete, unbounded, unpinned, or provenance-free descriptors. |
| P3-02 | `build_security_adapter_proposal` and `run_security_adapter` bind the exact request to the executor capability generation and existing authorization session. Accepted scanner result exits only permit parsing; they never confirm a finding. |
| P3-03 | `RawArtifact`, `NormalizedObservation`, and `AdapterRunReport` preserve parser, executable, descriptor, target, configuration, ruleset, raw-output, trace, infrastructure, and cleanup bindings. |
| P3-04 | Runtime executable/version evidence and local config/rules inputs are SHA-256 checked before execution and included in the authorization request and trace. Nuclei templates are catalog-pinned separately. |
| P3-05 | Twelve promoted catalog records route to twelve dedicated normalizers. Gitleaks secret/match values and Semgrep code/metavars do not enter normalized metadata. |
| P3-06 | Six named tools plus zgrab2 and generic MCP/HTTP producers are constrained and cannot run without explicit opt-in. |
| P3-07 | Nmap is `legal-hold`; proposal construction fails before executor negotiation, even when constrained execution is requested. |
| P3-08 | Generic MCP stdio and HTTP envelopes mark schemas, summaries, and evidence references untrusted and cannot self-promote trust. |
| P3-09 | Telemetry, remote generation, uploads, implicit pulls, auto-update, and unreviewed templates default off. Network/provider proposals require an allowed decision matching destination, target, ID, and digest. |
| P3-10 | Every promoted adapter runs twice on an owned deterministic executor fixture for semantic reproduction, plus timeout, partial output, cleanup failure, and version-drift cases. Additional tests cover malformed roots, JSONL/XML limits, DTD/entities, trust inflation, parser failure, authority denial, executable drift, provider exceptions, output collisions, and pin mismatches. |

## Validation receipts

| Gate | Result |
|---|---|
| Full mandatory repository suite | `2,360 passed, 30 skipped in 418.25s`; required combined statement/branch coverage passed at `95.06%` |
| Optional skips | 30 capability-gated browser, CUA, MELRA, Docker, gVisor, Codex-login, or Windows-symlink lanes; none were reported as passes |
| Focused P3 defensive contract suite | `73 passed` |
| Focused P3 runner suite | `72 passed` |
| CLI parser-to-handler execution audit | `144/144`; no unexecuted command |
| Ruff format and lint | `645 files already formatted`; `All checks passed!` |
| Mypy strict repository check | `Success: no issues found in 459 source files` |
| Lock and generated artifacts | `uv lock --check` resolved 62 packages; glossary and taxonomy checks passed |
| Dependency audit | OSV audit of locked direct and development requirements: no known vulnerabilities found |
| Credential-free acceptance lab | passed; `coreAcceptancePassed=True`; correctly retained `stable1Ready=False` |
| Wheel and sdist | built `sova_oss-0.1.0a0`; isolated wheel smoke returned `sova 0.1.0a0` |
| P3 package resources | descriptor, observation, and run-report schemas present in both wheel and sdist |
| Repository policy and public boundary | both passed; 762 tracked or unignored files scanned |
| Patch whitespace | `git diff --check` passed before the evidence-record update and is rerun at closeout |

## Evidence interpretation and remaining limits

The owned fixtures validate SOVA's descriptor, parser, authority, trace, cleanup,
failure, and semantic-reproduction contracts. They do not establish live
interoperability with every upstream binary, effectiveness against real targets,
vulnerability coverage, absence of false negatives, production isolation, or
independent security review. Scanner output remains an observation with
`findingConfirmed=false` and `independentlyReproduced=false` until later evidence
gates promote it.

P4 has not started. Oracle calibration, finding promotion, measured sensitivity and
specificity, independent fresh-target reproduction, and multidimensional coverage
accounting remain P4 work. P5 isolation and P6 blinded launch validation also remain
open.
