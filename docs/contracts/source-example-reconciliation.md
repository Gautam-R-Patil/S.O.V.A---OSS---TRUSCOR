<!-- status: decision -->

# Source-example reconciliation

The project vision uses several overlapping examples. Topic 03 resolves them
through the canonical artifact and vocabulary decisions.

| Vision example | Canonical interpretation |
|---|---|
| Agent configuration declaration | Target manifest or referenced native configuration, never `.sova` |
| Portable exploit or regression test | `.sova` scenario; it is not a vulnerability verdict |
| One execution record | `.sova-trace`; evidence, not a finding |
| Hidden sleeper behavior | Conditional/dormant taxon plus explicit conditions, trigger hypothesis, runs, observations, and finding |
| “No behavior seen in 60 seconds” | `not-observed` with exact coverage, budget, stop, and limitations; never clean or safe |
| “Reproduced 8/10” | Semantic reproduction result with numerator, eligible denominator, exclusions, method, context, and uncertainty |
| Static and dynamic scanners disagree | Preserved source verdicts plus `scanner-disagreement` adjudication state |
| Capability map | Declared/observed/inferred/unknown graph and frozen coverage denominator, not authorization |
| Standard attack run | Complete active `sova.attack` profile at one exact taxonomy and methodology version |
| User-selected attack subset | Custom, non-standard, non-comparable profile |
| Forensic explanation | Reconstruction and hypothesis; attribution requires intervention/counterfactual evidence and confidence |
| Fixed vulnerability | Remediation state changes to `fixed`; historical evidence remains |
| Corrected or split finding | New finding identity plus `superseded` relationship; no silent rewrite |
| Public registry item | Inert metadata pointing to immutable content and lifecycle records |
| SOVA self-assessment | Operator-generated evidence, never a TRUSCOR attestation or certificate |
| Atlas execution | Optional executor/adapter context only; SOVA owns authorization, evidence, taxonomy, lifecycle, and interpretation |

These mappings cover the examples needed by later schemas without deciding
their field layouts early.
