<!-- status: implemented -->

# P6 validation and launch-readiness record

- **Date:** 2026-08-27
- **Branch:** `codex/universal-target-foundation`
- **Gate:** P6-01 through P6-11
- **Result:** local P6 machinery accepted; P6 launch exit gate remains open

## Delivered boundary

P6 adds strict contracts for an eight-target-class, four-lane blinded evaluation;
exclusive canonical protocol freezing; deterministic non-executing work orders for
every lane/target/repetition tuple; strict observation-ledger evaluation; five
provenance- and loss-reporting external benchmark adapter boundaries; exact
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
| P6-01 | Open; operator machinery implemented | The protocol requires exact target, lane, provider, budget, seed, repetition, scoring, exclusion, failure, and answer-key-custody commitments and forbids an embedded answer key. The freeze command validates the expected release commit and exclusively writes canonical bytes only after a no-results assertion; the work-order compiler expands the complete matrix without answer-key or execution authority. A real study has not yet been frozen before result generation, and the local assertion is not independent timestamp/custody proof. |
| P6-02 | Open | Candidate, baseline, scripted, and weak-model lanes plus multiple provider families are mandatory, but no live provider/model comparison was run. |
| P6-03 | Open | All eight target classes are mandatory and exact expected tuples are enforced. No blinded owned/licensed field-target suite was run. |
| P6-04 | Implemented | Candidate adapters for Inspect AI/Inspect Evals, AgentDojo, OASB, XBEN/PentestGPT-style cases, and EthiBench require accepted licence, revision digest, authorization receipt, source identity, and loss reporting; they do not import raw cases, answer keys, or upstream truth. |
| P6-05 | Open | Baseline lanes are represented and drift is rejected, but no actual matched-budget scanner/tool/agent comparison was run. |
| P6-06 | Implemented | The ledger reports workflow/surface coverage, confirmed/not-observed/false-positive/inconclusive/infrastructure/blocked/unsupported outcomes, reproductions, precision, cost, latency, containment, missing/duplicate/out-of-scope runs, and provider/model/harness contrasts without a causal superiority claim. |
| P6-07 | Partially implemented | The readiness gate covers identity, moderation, malware and secret screening, rate/DDoS control, encrypted backup, restore, rollback, incident response, and monitoring. The included local snapshot/restore is bounded and deterministic but deliberately unencrypted and never qualifies as a production receipt. No public Registry is deployed. |
| P6-08 | Partially satisfied | Current-tree tests, static checks, Python and Rust dependency audits, declared runtime-licence review, deterministic Python and static-mediator builds, package-resource checks, isolated-wheel smoke, separate uv/Cargo SBOMs, exact five-file candidate checksums, and public-boundary checks pass. The candidate workflow builds, signs, and provenance-attests the mediator with the Python distributions. `release dossier` still requires a signed exact-final-commit check receipt and recomputes its bindings. Exact-final-commit hosted CI/provenance and staged review must run after the release commit exists. |
| P6-09 | Open; verifier implemented | Role-scoped DSSE ingestion rejects unknown keys, identity/role drift, shared role keys, synthetic receipts, internal/independent overlap, and overlap between the two independent reviewers. No real founder, independent technical, independent isolation, legal/licence/disclosure, or security review receipt exists for the candidate. |
| P6-10 | Partially satisfied | Repository README, changelog, claims register, founder matrix, Registry operations docs, and launch checklist distinguish machinery from evidence. The separately hosted [TRUSCOR website](https://truscor.org/) contains broader SOVA Engine/autonomous rating language and requires separate founder/publication/legal evidence review. No release-controlled website or paper source is tracked here. |
| P6-11 | Open | The release ledger correctly remains on hold. No tag, push, package publication, public Registry launch, or release announcement was performed. |

## Deterministic acceptance

For a real study, keep target inputs, authorization receipts, provider credentials,
answer keys, and observations outside the public checkout. The operator sequence is:

```text
python scripts/freeze_p6_protocol.py protocol-input.json frozen-protocol.json --expected-release-commit <commit> --ack-no-results-observed
python scripts/compile_p6_work_orders.py frozen-protocol.json work-orders.json
# authorized operators execute every work order and produce a signed observation ledger
python scripts/evaluate_p6_observations.py frozen-protocol.json observations.json evaluation-report.json
```

None of these commands supplies target authority, provider credentials, independent
answer-key custody, or permission to publish.

The deterministic pre-dossier P6 acceptance fixture remains reproducible. Its
current execution produced:

`sha256:7d2486d1b71e757a526760fbc381a9735cae7d950752c4a2242f7c020fbc4187`

The receipt reports `localImplementationAcceptancePassed=true` and
`p6ExitGatePassed=false`. It also fixes all-vulnerabilities, blinded-field,
live-provider, strongest-baseline, public-Registry, external-review, tag, and
publication claims to `false`.

Supporting deterministic digests:

- complete 32-run work-order set: `sha256:ac1f34465584427f8eb3ff6777f49e483d9bb01b5aff9c2f792e014708b6537a`;
- evaluation report: `sha256:40a60ed58d4fc489c1701f89fbf111c302a289894e66f542249f85b654ed5807`;
- Registry readiness: `sha256:00d412e4fa10ae0ff5f3e5551174311d3ce99aa6d9efd40f748d7477fa87ffd2`;
- release-gate ledger: `sha256:25575499d01de1fb5a8c05ed11ff97fb4ca79b9b43c40de541a7e9289e250d40`.

## Validation receipts

| Gate | Result |
|---|---|
| Focused P6 and Registry-backup tests | `54 passed`; combined validation/backup statement-branch coverage `97.72%` |
| Full repository suite | `2,644 passed`, `30 skipped`, zero failed in `498.58s` |
| Full combined statement/branch coverage | `95.12%`; mandatory 95% gate passed |
| Full Ruff format and lint | `733 files already formatted`; all checks passed |
| Full strict mypy | no issues in `534` source/test files |
| CLI parser-to-handler execution audit | `149/149`; no unexecuted command |
| Repository policy and public boundary | passed |
| Dependency vulnerability audit | unchanged Python lock retains its strict passing OSV audit; `cargo-audit 0.22.2` scanned 58 mediator dependencies against 1,233 RustSec advisories with zero findings and no ignores |
| Runtime licence metadata | ten Python runtime components declare Apache-2.0, BSD-3-Clause, MIT, MIT-0, or PSF-2.0 expressions; all 57 non-root Cargo packages report Apache-2.0, MIT, Unicode-3.0, or Unlicense expressions with no missing field |
| Current working-tree distributions | two fixed-epoch builds were byte-identical. Exact artifact digests are kept in the external candidate checksum/provenance record because this validation document is included in the sdist. They are not final-release artifacts until the release commit and hosted provenance exist |
| Package resources | all `60` schemas, including the P5 network/host/mediator and P6 work-order contracts, were present in the rebuilt wheel and sdist |
| Isolated-wheel smoke | installed 11 packages and returned `sova 0.1.0a0` |
| Local SBOMs | CycloneDX 1.6 Python runtime SBOM: 10 components, `sha256:7c0b232e416da442d2e09ada04c48632ec55f1ed8afc2396bf4e96d659bf4b3d`; Cargo locked-closure SBOM: 57 components, `sha256:98e8c97b17df8f8ec62ca62a21098ef21eafb2aa56f6c3e715aeb1326ee32220` |
| Local checksum verification | five declared files—the wheel, sdist, static mediator, and two SBOMs—with no missing, undeclared, or mismatched files. The external candidate manifest carries the non-circular final artifact and manifest digests |

## Evidence interpretation

These receipts establish the local protocol, adapter, accounting, Registry-policy,
recovery-tool, review-ledger, packaging, and regression behavior. They do not
establish broad pentest performance, expert equivalence, exhaustive discovery,
production isolation, a production Registry, independent validation, legal
clearance, or permission to publish. P6 launch completion requires the real and
external receipts listed above for one exact release commit and artifact set.
