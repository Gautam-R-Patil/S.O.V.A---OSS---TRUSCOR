<!-- status: implemented -->

# Methodology compiler and playbook library 0.1

## Scope

This specification defines SOVA's native security-playbook contract, pinned
reference library, deterministic methodology compiler, observation-bound
replanning, and signed community contribution staging. It consumes the
[`TargetProfile`](./universal-target-intake-0.1.md) and optional universal-intake
report produced by P1. It plans work; it does not execute a test or authorize an
effect.

The normative JSON Schema 2020-12 artifacts are:

- `sova.playbook` and `sova.playbook-library`;
- `sova.methodology-policy` and `sova.methodology-plan`;
- `sova.methodology-observations`; and
- `sova.playbook-submission`.

All are experimental version `0.1.0`. Canonical JSON SHA-256 digests bind target,
policy, library, playbook, plan, observation set, and optional intake report.

## Playbook contract

A playbook contains an ID and semantic version, domain, title, objective, target
predicates, dependency IDs, prerequisites, supported discovery inputs, technique
and finite procedure, allowed effect classes, tool capability requirements,
variants, one proposed oracle, decisive and supporting evidence requirements,
fail-closed stop rules, cleanup and cleanup verification, framework mappings,
risk/cost inputs, tags, evidence limitations, false-positive and false-negative
risks, and origin/authorship/licence provenance.

Portable playbooks cannot embed secret-shaped material, copied third-party prose,
or third-party datasets. Framework entries are relationship mappings with pinned
catalog versions and immutable or versioned HTTPS references; they are not imported standards content and
do not imply endorsement. The P2 parser permits only
`calibrationStatus: unvalidated-proposal`. P4 owns oracle calibration and promotion.

The built-in `0.1.0` library contains 74 Apache-2.0 SOVA-native playbooks:

| Domain | Count | Primary classes |
|---|---:|---|
| Web | 14 | session/authentication, authorization, input, logic/state, browser, files, SSRF, deserialization, race, cache/proxy, TLS/privacy, resilience |
| API | 16 | object/function/property authorization, authentication, resources, workflows, inventory, downstream consumption, GraphQL, gRPC, WebSocket, webhook, federation, mTLS |
| Network/host/cloud | 11 | service/configuration, credentials, segmentation, privilege, IAM, Kubernetes, containers, secrets, management surfaces, supply chain |
| Source/package/binary | 9 | dependency/SBOM, secret, SAST, build/release, configuration, fuzzing, hardening, isolated package behavior |
| AI/model | 12 | injection, leakage, unsafe output, agency/tool abuse, poisoning, denial of service, evasion, grounding, privacy, supply chain |
| Agentic | 12 | tool authority, MCP/A2A identity/consent, memory, plugins, cross-agent trust, delegation, confused deputy, goal/state manipulation, audit bypass |

## Reference mapping boundary

The library pins NIST SP 800-115 Final (2008), PTES web edition retrieved
2026-08-26, OWASP WSTG 4.2, ASVS 5.0.0, API Security Top 10 2023, AISVS 1.0 at
commit `78775233666a2022dcfb82037e5e029116955c00`, AI Testing Guide 1.0 at commit
`006e4e9ee060f2ca2176037499b824e47af5360e`, OWASP Agentic Top 10 2026, MITRE
ATLAS 2026.07, CWE 4.20, and CAPEC 3.9. Their licence/terms fields state
reference-only use. SOVA stores
native objectives and procedures rather than copying source prose or datasets.

## Policy and authority

The policy binds exactly one target-profile digest and declares:

- a total cost budget and a budget for all six phases;
- one deterministic scheduler;
- allowed effect classes; and
- denied and required playbook IDs.

`humanApprovalRequired` is always true. Policy claims are fixed false for execution
authorization, model authority expansion, and target-scope expansion. A compiled
plan intersects policy effects with each immutable playbook contract. Discovery,
hypothesis, and reporting are restricted to passive observe/read effects. No plan
is an authority receipt; execution still requires current proof of control, target
generation, human approval, an admitted executor, containment appropriate to the
effect, budgets, stop rules, cleanup, and an evidence sink.

## Deterministic compilation

The compiler selects playbooks whose target predicates intersect the declared
profile. It records target-kind mismatch, policy denial, unavailable effects,
budget exhaustion, excluded dependencies, and unavailable required playbooks as
explicit exclusions. Dependencies are scheduled before their consumers. A
playbook is admitted only when its complete six-phase cost fits both total and
per-phase budgets; the compiler never admits a partial playbook group.

Every scheduled playbook produces exactly one task in this order:

1. discovery;
2. hypothesis;
3. confirmation;
4. reproduction;
5. remediation validation; and
6. reporting.

A task depends on the preceding phase of the same playbook and the same phase of
its playbook dependencies. Missing relevant input or attack-surface evidence is a
precondition gap. Discovery remains planned; dependent phases are `blocked`, never
reported as passed or clean.

The compiler emits bounded integer scores for risk, reachability, novelty, state
coverage, dependency exposure, evidence gap, and combined priority. Available
schedulers are identifier baseline, risk-first baseline, and evidence-gap-balanced.
All sort ties end in the playbook identifier, so identical canonical inputs produce
byte-identical plans and task IDs.

## Replanning

An observation set binds the exact target-profile digest, previous-plan digest,
source-artifact digests, playbook and phase, evidence digest, and target-generation
digest. Outcomes remain distinct: `observed`, `not-observed`, `inconclusive`,
`blocked`, and `infrastructure-failure`.

Replanning may change only task status and scores. It cannot add/remove tasks,
effects, tools, evidence requirements, preconditions, dependencies, budgets,
execution conditions, exclusions, policy/library/target bindings, or oracle status.
Observations for an unplanned playbook, changed target generation, or different
parent plan fail closed.

## Signed community review

`sova methodology contribute` canonicalizes and schema-validates a playbook, signs
it in a one-signature DSSE envelope with a raw Ed25519 contributor key, includes
the public key and `included-key-integrity-only` trust policy, re-verifies the
payload and semantic contract, and sends the playbook plus submission document
through the existing local Registry contribution scanner and gates.

The included key establishes content integrity only. Publisher identity remains
false; human review and moderation remain mandatory. Staging performs no upload,
pull request, external message, execution, or public disclosure.

## CLI

```text
sova methodology library-export LIBRARY.json
sova methodology playbook-validate PLAYBOOK.json
sova methodology policy-create PROFILE.json POLICY.json
sova methodology compile PROFILE.json POLICY.json PLAN.json [--intake-report REPORT.json]
sova methodology observations-template PLAN.json OBSERVATIONS.json --source-artifact-digest sha256:...
sova methodology replan PROFILE.json POLICY.json PLAN.json OBSERVATIONS.json NEXT.json
sova methodology keygen PRIVATE.key PUBLIC.key
sova methodology contribute PLAYBOOK.json SPEC.json PRIVATE.key PUBLIC.key STAGING --confirm
```

Key files and contribution staging are local operator material and must not be
committed. Re-running any command against an existing destination fails rather than
overwriting it.

## Non-claims

The library is a finite initial methodology, not a professional tester's complete
accumulated knowledge. Compilation does not prove workflow/surface completeness,
vulnerability absence, oracle reliability, scanner truth, weak-model expertise,
arbitrary-target compatibility, or safe hostile-agent execution. P3 through P6
remain separate implementation and evidence gates.
