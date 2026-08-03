<!-- status: experiment -->

# Topics 15–17 engineering validation

## Scope and evidence state

This record covers the public engineering implementation completed on
2026-08-03. It does not close the later prior-art, paper, patent, independent
review, or real-system research gates.

| Roadmap area | Specification | Implementation | Verification |
|---|---|---|---|
| 15.1 reconstruction | `forensics-0.1.md` | `sova.forensics.reconstruct` | causal, clock, missing-parent, redaction, external and native trace tests |
| 15.2 hypotheses | `forensics-0.1.md` | `CausalLayer`, explicit unknown/multiple states | support, contradiction, confound, impossible and inconclusive tests |
| 15.3 counterfactual method | ADR-0019 | paired trials, trace links, Wilson intervals and abstention | clean, stochastic, confounded, incomplete and non-reproduced-baseline tests |
| 15.4 validation | `forensics-0.1.md` | five-case fixture and passive-frequency baseline | 0.4 raw top-one; 1.0 selective; 0.4 coverage; 1.0 predeclared decision accuracy |
| 15.5 output | forensic and attribution mappings | reconstruction-first CLI plus separate attribution command | schema and CLI tests; no blame flag/limitations |
| 16.1 evidence | `evidence-adjudication-disclosure-0.1.md` | `sova.evidence` bundle and renderers | schema, malformed input, watermark and report-view tests |
| 16.2 interoperability | ADR-0020 | SARIF 2.1 projection/import, component identifiers, trace references | scanner provenance/location and malformed SARIF tests |
| 16.3 adjudication | ADR-0020 | inert plan and four bounded terminal states | confirmed, false-positive-under-test, not-observed and inconclusive tests |
| 16.4 disclosure | ADR-0020 | gate-bound local package and redacted preview | no-send/no-publish, unsafe-state and preview tests |
| 16.5 reports/disputes | evidence specification | four report views and lifecycle extension data | renderer and schema tests |
| 17.1 graph | `composition-testing-0.1.md` | typed nodes/edges and recursive secret rejection | round-trip and hostile graph tests |
| 17.2 search | ADR-0021 | pairwise, bounded t-wise, risk-path and trigger-order strategies | deterministic strategy, budget and stopping tests |
| 17.3 evidence/attribution | ADR-0021 | fresh-observation reduction, incident-edge removal and portable capsule fragment | element necessity and capsule/trace integration tests |
| 17.4 exit fixture | composition specification | planted memory→agent→sink sequence | constituent-negative, chain-positive, minimized and reproduced result |

## Deterministic results

- Complete final repository suite: 619 passed and one optional Codex lane
  transparently skipped because this machine was not logged in.
- Required branch coverage gate: 95% minimum; final measurement was 95.22%.
- Attribution fixture: five labeled cases, two correctly supported clean
  single-layer cases, and three correct abstentions for confounded, stochastic,
  or missing-sensor cases. Raw top-one accuracy is 0.4; selective accuracy and
  predeclared decision accuracy are 1.0; support coverage is 0.4.
- Composition fixture: the ordered three-node chain is positive, each node is
  negative alone, and every retained node/edge is necessary under removal tests.
- Evidence/disclosure: machine and human outputs retain the self-assessment
  boundary; the prepared disclosure records `externalMessageSent=false` and
  `published=false`.

## Unresolved research gates

- Topic 15 has no real-system or independently labeled attribution accuracy and
  no strongest-published-method comparison beyond the transparent passive
  baseline.
- Topic 16 has no representative real scanner-disagreement dataset or measured
  resolution rate.
- Topic 17 has no real-system yield comparison against random, pairwise, and
  exhaustive feasible baselines.
- No novelty, superiority, paper-readiness, or patentability claim is made.
  Those screens begin only after the founder-requested build phase is accepted.
