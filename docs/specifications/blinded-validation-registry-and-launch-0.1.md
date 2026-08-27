<!-- status: implemented -->

# Blinded validation, Registry beta, and launch specification 0.1

## 1. Scope

This specification defines the P6 preregistration, external benchmark import,
complete-run metric ledger, Registry operational readiness, and exact-release
approval boundary. It does not authorize target execution or publication.

## 2. Frozen evaluation protocol

A valid protocol MUST bind:

- one or more blinded, owned or licensed targets in each of web, API, package,
  OCI, network, desktop, AI model/agent, and MCP/A2A classes;
- input digest, source revision, licence, authorization receipt, containment
  backend, and answer-key commitment for every target;
- candidate, named baseline, scripted, and weak-model lanes;
- at least two declared model-provider families, exact model/harness/configuration
  identities, and one matched candidate/baseline model pair that changes the
  harness rather than the model;
- action, wall-time, input, output, and cost budgets per run;
- repetitions, seed, scoring-rules digest, exclusions, failure rules, answer-key
  custodian, release commit, and the complete metric contract.

Raw answer keys MUST NOT appear in the protocol. Changing any bound field creates a
new digest and therefore a new protocol.

## 3. Observation ledger

Every `(lane, target, repetition)` tuple MUST have at most one observation. Unknown,
duplicated, or wrong-protocol observations MUST be rejected. Missing observations
MUST be listed. Not-observed, false-positive, inconclusive,
infrastructure-failure, blocked, and unsupported are first-class results and MUST
NOT be converted to passes.

The report MUST expose, by lane and target class:

- workflow and surface numerators and denominators;
- action, input-byte, output-byte, wall-time, and cost use plus every exceeded
  preregistered budget;
- reported, confirmed, reproduced, and false-positive findings;
- precision and reproduction ratios without division-by-zero fabrication;
- infrastructure failures, duration, cost, and containment pass/fail/not-measured;
- provider, model, harness, lane kind, missing runs, limitations, and exact
  evidence digests.

Any budget exceedance or failed containment check makes the result
`incomplete-or-inconclusive`. The report MUST NOT claim all vulnerabilities,
generality, expert equivalence, causal harness contribution, or independent
replication from local completion.

## 4. External adapters

The Inspect AI, AgentDojo, OASB, XBEN/PentestGPT, and EthiBench adapters are
candidate compatibility boundaries. Each import MUST require an accepted licence,
pinned source-revision digest, target authorization receipt, input digest,
answer-key commitment, and declared conversion loss. It MUST NOT import upstream
scores as SOVA truth or embed raw task/answer content in the normalized artifact.

## 5. Registry beta

A `RegistryBetaPolicy` MUST bind the exact release and image digests, identity
issuer/audience, authorized operational-receipt issuers, moderator roles, malware engine/version/signatures, encrypted
backup destination and RPO/RTO, rollback image, incident runbook/owner, and rate
limit. Readiness requires unique passing production receipts for authentication,
moderation, malware screening, secret screening, rate/DDoS controls, backup,
restore, rollback, incident response, and monitoring/escalation.

Missing, failed, synthetic, non-production, unauthorized-issuer, wrong-policy, or wrong-artifact
receipts MUST keep `liveBetaReady=false`.

## 6. Backup and restore

The local Registry snapshot MUST be deterministic, atomically no-overwrite at publication,
bounded, traversal-safe, symlink-free, manifest-complete, and digest-verified.
Verification and restore MUST operate on the same single in-memory archive
snapshot so path replacement cannot change bytes after verification.
Restore MUST target an existing empty directory and write each file exclusively.
Because the utility does not encrypt, its receipt MUST state that it is not a
production backup or restore receipt. Operator encryption and an off-host restore
exercise remain mandatory.

## 7. Release gate

The exact release commit and artifact manifest MUST receive separate founder,
independent technical, independent isolation, legal/licence/public-disclosure, and
security receipts. Independent gates MUST identify independent reviewers. Every
receipt MUST be real, non-synthetic, passing, and exact-artifact-bound.
Receipt issuer and signature/trust-chain validation occurs before construction of
these typed ledger records; the pure policy evaluator is not an identity provider
or signature verifier and its unsigned JSON output is not an attestation.

P5 production isolation, blinded field validation, live Registry readiness,
deterministic release checks, public blinded results, and public limitations MUST
all pass. Otherwise status is `hold` and tagging/publishing is forbidden. The gate
evaluator MUST NOT itself push, tag, deploy, or publish.
