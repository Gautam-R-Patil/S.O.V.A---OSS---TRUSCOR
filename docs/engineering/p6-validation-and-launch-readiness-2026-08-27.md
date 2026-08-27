<!-- status: implemented -->

# P6 validation and launch-readiness record

- **Date:** 2026-08-27
- **Branch:** `codex/universal-target-foundation`
- **Gate:** P6-01 through P6-11
- **Result:** local P6 machinery accepted; P6 launch exit gate remains open

## Delivered boundary

P6 adds strict contracts for an eight-target-class, four-lane blinded evaluation;
five provenance- and loss-reporting external benchmark adapter boundaries; exact
expected-run and metric accounting; a ten-control Registry beta readiness policy;
bounded deterministic local Registry backup, verification, and empty-root restore;
and a five-review exact-release hold ledger. The subsequent operator integration
adds strict signed evidence ingestion and one exact-candidate launch dossier that
recomputes all three ledgers, binds actual manifest/claims bytes, requires an
out-of-band trust-policy digest, enforces distinct role keys and independent-review
separation, and performs no publication action. A deterministic assembler now
combines separately governed inputs without pretending that assembly verifies
signatures. Its output now carries exact recomputed evaluation, Registry, review,
and external-gate summaries with deterministic hold reasons instead of only a
generic hold flag.

The normative behavior is in the
[P6 specification](../specifications/blinded-validation-registry-and-launch-0.1.md).
Source selection, licences, safety limits, and non-adoptions are in the
[P6 research record](../research/p6-blinded-validation-and-launch-research-2026-08-27.md).

## Checklist evidence

| ID | State | Evidence |
|---|---|---|
| P6-01 | Open; machinery implemented | The protocol requires exact target, lane, provider, budget, seed, repetition, scoring, exclusion, failure, and answer-key-custody commitments and forbids an embedded answer key. A real study has not yet been frozen before result generation. |
| P6-02 | Open | Candidate, baseline, scripted, and weak-model lanes plus multiple provider families are mandatory, but no live provider/model comparison was run. |
| P6-03 | Open | All eight target classes are mandatory and exact expected tuples are enforced. No blinded owned/licensed field-target suite was run. |
| P6-04 | Implemented | Candidate adapters for Inspect AI/Inspect Evals, AgentDojo, OASB, XBEN/PentestGPT-style cases, and EthiBench require accepted licence, revision digest, authorization receipt, source identity, and loss reporting; they do not import raw cases, answer keys, or upstream truth. |
| P6-05 | Open | Baseline lanes are represented and drift is rejected, but no actual matched-budget scanner/tool/agent comparison was run. |
| P6-06 | Implemented | The ledger reports workflow/surface coverage, confirmed/not-observed/false-positive/inconclusive/infrastructure/blocked/unsupported outcomes, reproductions, precision, cost, latency, containment, missing/duplicate/out-of-scope runs, and provider/model/harness contrasts without a causal superiority claim. |
| P6-07 | Partially implemented | The readiness gate covers identity, moderation, malware and secret screening, rate/DDoS control, encrypted backup, restore, rollback, incident response, and monitoring. The included local snapshot/restore is bounded and deterministic but deliberately unencrypted and never qualifies as a production receipt. No public Registry is deployed. |
| P6-08 | Partially satisfied | Current-tree tests, static checks, dependency audit, declared runtime-licence review, deterministic builds, package-resource checks, isolated-wheel smoke, SBOM, checksums, and public-boundary checks pass. `release dossier` now requires a signed exact-final-commit check receipt and independently recomputes its candidate bindings. Exact-final-commit CI/provenance and staged review still must run after the release commit exists. |
| P6-09 | Open; verifier implemented | Role-scoped DSSE ingestion rejects unknown keys, identity/role drift, shared role keys, synthetic receipts, internal/independent overlap, and overlap between the two independent reviewers. No real founder, independent technical, independent isolation, legal/licence/disclosure, or security review receipt exists for the candidate. |
| P6-10 | Partially satisfied | Repository README, changelog, claims register, founder matrix, Registry operations docs, and launch checklist distinguish machinery from evidence. The separately hosted [TRUSCOR website](https://truscor.org/) contains broader SOVA Engine/autonomous rating language and requires separate founder/publication/legal evidence review. No release-controlled website or paper source is tracked here. |
| P6-11 | Open | The release ledger correctly remains on hold. No tag, push, package publication, public Registry launch, or release announcement was performed. |

## Deterministic acceptance

The deterministic pre-dossier P6 acceptance fixture remains reproducible. Its
current execution produced:

`sha256:18d8806803330b3f81a56488005eb4813ba702ec56f1fd710d9114d5c3febf6b`

The receipt reports `localImplementationAcceptancePassed=true` and
`p6ExitGatePassed=false`. It also fixes all-vulnerabilities, blinded-field,
live-provider, strongest-baseline, public-Registry, external-review, tag, and
publication claims to `false`.

Supporting deterministic digests:

- evaluation report: `sha256:40a60ed58d4fc489c1701f89fbf111c302a289894e66f542249f85b654ed5807`;
- Registry readiness: `sha256:00d412e4fa10ae0ff5f3e5551174311d3ce99aa6d9efd40f748d7477fa87ffd2`;
- release-gate ledger: `sha256:25575499d01de1fb5a8c05ed11ff97fb4ca79b9b43c40de541a7e9289e250d40`.

## Validation receipts

| Gate | Result |
|---|---|
| Focused P6 and Registry-backup tests | `54 passed`; combined validation/backup statement-branch coverage `97.72%` |
| Full repository suite | `2,549 passed`, `30 skipped`, zero failed in `876.47s` |
| Full combined statement/branch coverage | `95.12%`; mandatory 95% gate passed |
| Full Ruff format and lint | `712 files already formatted`; all checks passed |
| Full strict mypy | no issues in `514` source/test files |
| CLI parser-to-handler execution audit | `148/148`; no unexecuted command |
| Repository policy and public boundary | passed; `861` tracked or unignored files scanned by each gate |
| Dependency vulnerability audit | strict OSV audit: no known vulnerabilities found |
| Runtime licence metadata | ten runtime components declare Apache-2.0, BSD-3-Clause, MIT, MIT-0, or PSF-2.0 compatible expressions |
| Current working-tree distributions | two fixed-epoch builds were byte-identical: wheel `43c00e64ed0aa58e9f3d2933e5e8855f44d792b88118f8562f6e09e5dc26d298`; sdist `37aa86e09e4b9498d4a98cd5e7e3c18add03614402713811495f349aa789f418`. These are not final-release hashes until the release commit and hosted provenance exist |
| P6 package resources | all thirteen P6 and launch schemas were present in the rebuilt wheel |
| Isolated-wheel smoke | installed 11 packages and returned `sova 0.1.0a0` |
| Local SBOM | CycloneDX 1.6 runtime SBOM, 10 components, digest `sha256:7c0b232e416da442d2e09ada04c48632ec55f1ed8afc2396bf4e96d659bf4b3d` |
| Local checksum verification | four declared files; no missing, undeclared, or mismatched files; manifest digest `sha256:88ada2d378c0f7da3b92b81165e1dda90f5d9369d11a9ac29e02dd2d91d3c934` |

## Evidence interpretation

These receipts establish the local protocol, adapter, accounting, Registry-policy,
recovery-tool, review-ledger, packaging, and regression behavior. They do not
establish broad pentest performance, expert equivalence, exhaustive discovery,
production isolation, a production Registry, independent validation, legal
clearance, or permission to publish. P6 launch completion requires the real and
external receipts listed above for one exact release commit and artifact set.
