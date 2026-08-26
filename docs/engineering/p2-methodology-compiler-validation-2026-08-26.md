<!-- status: implemented -->

# P2 methodology compiler and playbook-library validation

- **Date:** 2026-08-26
- **Branch:** `codex/universal-target-foundation`
- **Gate:** P2-01 through P2-14
- **Result:** implementation complete; repository-wide release validation recorded below

## Delivered

P2 adds a SOVA-owned planning layer on the P1 `TargetProfile` and intake report:

- six strict experimental JSON Schemas for playbooks, libraries, policies,
  observations, plans, and signed submissions;
- a 74-playbook Apache-2.0 SOVA-native library spanning six domains;
- licence-separated, version-pinned relationship mappings to 11 methodology,
  verification, threat, weakness, and attack-pattern sources;
- deterministic target/policy selection, dependency closure, total/per-phase
  budgets, explicit exclusion reasons, three schedulers, seven bounded scores, and
  six distinct phases;
- observation-bound replanning that may change only status and scores;
- DSSE Ed25519 contribution integrity plus the existing local Registry scanner and
  human-review gates; and
- eight CLI operations using the same contracts as the Python API.

The normative behavior and non-claims are in the
[methodology specification](../specifications/methodology-compiler-and-playbook-library-0.1.md).

## Checklist evidence

| IDs | Evidence |
|---|---|
| P2-01, P2-05 | `contracts.py`, `playbook-0.1.0.schema.json`, and `methodology-plan-0.1.0.schema.json` make every required playbook field and all six phases mandatory. |
| P2-02–P2-04 | `compiler.py` binds profile/policy/library/intake digests, computes dependency closure and budgets, emits explicit exclusions and deterministic scores, and rejects replanning changes to task contracts or authority. |
| P2-06 | `library.py` pins NIST, PTES, WSTG, ASVS, OWASP API, AISVS, AITG, Agentic, ATLAS, CWE, and CAPEC versions/links and marks them reference-only. |
| P2-07–P2-12 | `playbook-seeds-0.1.0.json` expands into 14 web, 16 API, 11 network/host/cloud, 9 source/package/binary, 12 AI/model, and 12 agentic contracts. |
| P2-13 | Every expanded playbook requires limitations plus false-positive and false-negative risks. Provenance rejects copied external prose/datasets and secret-shaped values. |
| P2-14 | `contribution.py` canonicalizes, signs, verifies, and stages the playbook/submission through `registry.contribution.prepare_contribution`; identity, moderation, upload, PR, and messaging claims remain false. |

## Positive, negative, and inconclusive fixtures

The compiler integration matrix covers web, API, network/host/cloud,
source/package/binary, AI/model, and agentic profiles. For every class:

- a complete owned intake report schedules every applicable playbook and all six
  phases;
- denying the domain foundation records `policy-denied` and
  `dependency-excluded` instead of silently dropping tests; and
- omitting the intake report leaves discovery planned and downstream phases
  explicitly blocked.

Additional adverse fixtures reject target/policy/report digest mismatch, plan
digest tampering, effect expansion, missing/cyclic playbook dependencies, secret
material, unsafe policy claims, changed target generations, unknown observation
playbooks, signature/digest tampering, mismatched licences, and unconfirmed
contributions.

## Validation receipts

| Gate | Result |
|---|---|
| Focused P2 contracts/compiler/contribution/CLI/schema parity | `35 passed in 103.69s` |
| Fail-closed intake and methodology edge suite | `50 passed in 10.49s` |
| Ruff format and lint | `636 files already formatted`; `All checks passed!` |
| Mypy strict repository check | `Success: no issues found in 452 source files` |
| Full mandatory repository suite | `2,180 passed, 30 skipped in 855.33s`; `95.00%` combined statement/branch coverage |
| CLI parser-to-handler execution audit | `140/140`; no unexecuted command |
| Lock and generated artifacts | `uv lock --check` resolved 62 packages; glossary and taxonomy checks passed |
| Wheel and sdist P2 resource inspection | all six schemas and the native playbook catalog present |
| Repository policy and public-boundary scans | both passed; 750 tracked or unignored files scanned |
| Patch whitespace | `git diff --check` passed |

## Reuse and provenance result

No external source code, prompt corpus, payload corpus, playbook prose, test
template, or standards dataset was copied into P2. The methodology library is
SOVA-native. The standards/catalog fields are relationship mappings and HTTPS
references. Mature scanners and agent frameworks remain P3 adapters or P6
benchmarks under the decisions in the
[OSS adoption ledger](../research/oss-architecture-adoption-ledger-2026-08-26.md).

## Limits and next gate

P2 plans a finite methodology and exposes evidence gaps. It does not execute ZAP,
Nuclei, Schemathesis, PyRIT, garak, promptfoo, SBOM, static-analysis, network, or
other tools; P3 owns those adapters and normalized raw observations. P4 owns oracle
calibration, independent reproduction, and measured false-positive/miss evidence.
P5 and P6 isolation, broad blinded validation, independent review, and public
launch gates remain open.
