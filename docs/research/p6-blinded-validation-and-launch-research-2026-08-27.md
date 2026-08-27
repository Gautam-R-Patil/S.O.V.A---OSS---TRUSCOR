<!-- status: implemented -->

# P6 blinded-validation, Registry, and launch research refresh

- **Date:** 2026-08-27
- **Purpose:** select compatible evaluation and operational architecture without
  inheriting upstream claims or copying target content into SOVA

## Adopted sources and boundaries

| Source | High-confidence use | Licence/provenance boundary |
|---|---|---|
| [Inspect AI evaluation logs](https://inspect.aisi.org.uk/eval-logs.html) and [Inspect Evals](https://github.com/UKGovernmentBEIS/inspect_evals) | Complete per-run logs, explicit scorer output, and a loss-reporting Sample import boundary. | Inspect Evals is MIT. SOVA imports bounded case fields and hashes raw input/answer content; it does not claim Inspect certification or copy its task catalog. |
| [AgentDojo](https://github.com/ethz-spylab/agentdojo) | Separate user-task utility from injection-task security and bind suite/task identities. | MIT; API is explicitly under development. SOVA marks the compatibility shape as candidate and does not import upstream scores as truth. |
| [OASB](https://github.com/opena2a-org/oasb) and [OASB-1](https://oasb.ai/oasb-1) | Import auditable control identity, requirement, and procedure while preserving the distinction between control evidence and certification. | Apache-2.0. An imported control or passing local check is not an OASB certification. |
| [XBOW validation benchmarks](https://github.com/xbow-engineering/validation-benchmarks) | Pinned, isolated web target identity and ground-truth commitment compatible with XBEN/PentestGPT-style runners. | Apache-2.0, intentionally vulnerable, and canary-marked as evaluation-only. Raw cases and answer keys stay outside SOVA artifacts. |
| [PentestGPT](https://github.com/GreyDGL/PentestGPT) | Named agent baseline that may run the same authorized XBEN cases under equal budgets. | MIT. SOVA does not adopt its reported success rate, prompts, or model results; those require fresh matched runs. |
| [EthiBench](https://github.com/ethiack/ethibench) | Repeated open-ended target evaluation, finding/ground-truth commitments, explicit false positives, and one-to-one match/adjudication concepts. | MIT. LLM semantic matches remain proposals until calibration and human adjudication; upstream ground truth is version-specific. |

## Architecture decisions

1. One `EvaluationProtocol` freezes exact target revisions, authorization,
   answer-key commitments, provider/model/harness lanes, per-run budgets, scoring
   rules, exclusions, failure rules, metrics, seed, repetitions, and release commit.
2. P6 requires all eight SOVA target classes plus candidate, named baseline,
   scripted, and weak-model lanes across at least two model-provider families and
   a same-provider/model candidate/baseline harness pair.
3. `EvaluationObservation` preserves confirmed, not-observed, false-positive,
   inconclusive, infrastructure-failure, blocked, and unsupported outcomes.
4. Reports expose workflow and surface denominators, confirmed/reproduced findings,
   precision, infrastructure failures, action/input/output/time/cost budget use and
   exceedances, latency, and containment separately.
5. Harness contrasts require the same provider/model with different harnesses and
   remain descriptive; the code never promotes them to causal or expert-equivalence
   claims.
6. External adapter outputs contain digests and declared losses, not raw task or
   answer-key content, and require an authorization receipt plus accepted licence.
7. Registry readiness needs ten exact production receipts from policy-authorized
   issuers. Synthetic, non-production, or unauthorized-issuer receipts can test the
   gate but cannot satisfy it.
8. Release readiness needs founder, independent technical, independent isolation,
   legal/licence/disclosure, and security receipts bound to the exact commit and
   artifact manifest. No code path tags or publishes automatically.

## Registry operational decision

The existing digest-pinned, non-root, read-only Compose blueprint and loopback
Python service remain a starting point. The shared bearer token is acceptable for
bounded local/operator use but is not sufficient Internet identity. Production beta
requires a separately reviewed identity-aware layer, moderator roles, exact malware
engine/signature bindings, secret screening, edge and application rate controls,
encrypted off-host backups, restore and rollback exercises, incident response, and
alert escalation. The local deterministic snapshot utility deliberately reports
that it is unencrypted and not a production receipt.

## Explicit non-adoptions

- No proprietary XBOW architecture, service, dataset beyond user-supplied pinned
  authorized fixtures, or performance claim is copied.
- No static benchmark result is treated as broad field performance.
- No LLM judge can be the sole vulnerability oracle; P4 calibration, decisive
  evidence, and independent reproduction remain required.
- No synthetic target/provider/reviewer receipt is relabelled as external evidence.
- No public Registry deployment, tag, push, PyPI publication, or release is executed
  by the local P6 acceptance script.

## Remaining evidence dependency

The repository can implement and test the protocol, adapters, accounting,
operations policy, backup/restore mechanics, and release ledger locally. It cannot
self-create credentials for multiple independent providers, undisclosed licensed
targets, an Internet operator, independent reviewers, or legal clearance. Those are
mandatory external receipts, not engineering tasks that should be simulated.
