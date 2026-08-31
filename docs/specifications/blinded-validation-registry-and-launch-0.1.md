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

`scripts/freeze_p6_protocol.py` validates the complete derived protocol, requires
an explicit operator assertion that no results have been observed, binds the
expected release commit, writes canonically with exclusive creation, and never
executes a target. The assertion is not an independent timestamp or custody proof.
`scripts/compile_p6_work_orders.py` deterministically expands every
`(lane, target, repetition)` tuple into a budgeted work order with a derived seed,
target-authorization digest, and containment backend. Work orders carry neither an
answer-key commitment nor execution/publication authority. Provider-, baseline-,
and target-specific operators remain responsible for executing each authorized
order and returning evidence-bound observations.

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

`scripts/evaluate_p6_observations.py` accepts one frozen protocol and one canonical,
digest-valid observation ledger, rejects cross-protocol binding, exclusively writes
the recomputed report, and returns a nonzero status for incomplete or inconclusive
results. It does not repair, discard, or rerun observations.

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

The exact release commit, artifact manifest, claims register, and canonical public
claims snapshot MUST receive separate founder,
independent technical, independent isolation, legal/licence/public-disclosure, and
security receipts. Independent gates MUST identify independent reviewers. Every
receipt MUST be real, non-synthetic, passing, and exact-artifact-bound.

The public claims snapshot MUST cover exactly the README, documentation, demo,
website, paper, Registry, and release-notes surfaces. Each surface binds its exact
content digest, locator, review state, and limitations. Its derived readiness is
true only when all seven surfaces are reviewed and reconciled. The release
candidate and dossier bind the raw canonical snapshot bytes; a missing, changed,
held, or wrong-commit snapshot keeps publication on hold.
Receipt issuer and signature/trust-chain validation occurs before construction of
these typed ledger records; the pure policy evaluator is not an identity provider
or signature verifier and its unsigned JSON output is not an attestation.

P5 production isolation, blinded field validation, live Registry readiness,
deterministic release checks, public blinded results, and public limitations MUST
all pass. Otherwise status is `hold` and tagging/publishing is forbidden. The gate
evaluator MUST NOT itself push, tag, deploy, or publish.

### 7.1 Signed launch dossier

The operator-facing release path is `sova release dossier`. It MUST consume one
strict, digest-bound launch bundle; the exact artifact-manifest bytes; the exact
claims-register bytes; the exact canonical public-claims-snapshot bytes; the
expected release commit; and a launch-trust-policy digest obtained out of band. A
trust policy carried only inside the evidence bundle is not a trust root.

The trust policy MUST bind the release commit, artifact-manifest digest, release-
candidate digest, raw Ed25519 public keys, named principals, organizations, and
all nine roles: evaluation custodian, Registry operator, P5 isolation operator,
release operator, founder, independent technical reviewer, independent isolation
reviewer, legal/licence/public-disclosure reviewer, and security reviewer.
Each role MUST have a distinct trusted principal and key. The independent technical
and isolation principals MUST be separate from every internal principal by name
and organization and MUST be separate from one another. This is a structural
conflict check, not legal identity verification.

Observation-ledger, Registry-operation, launch-gate, and review documents MUST be
canonical JSON inside single-signature DSSE envelopes. The dossier verifier MUST:

- reject an unpinned policy, unknown key, invalid signature, role mismatch,
  signer/receipt identity mismatch, duplicate receipt, or non-canonical payload;
- reconstruct the typed protocol, observations, Registry policy and receipts,
  release candidate, reviews, and P5/field-validation/final-check gate receipts;
- recompute evaluation, Registry-readiness, and release-gate reports instead of
  trusting nested `ready`, `pass`, or content-digest claims;
- bind the candidate to the actual manifest and claims-register bytes and require
  exact commit/digest agreement across the protocol, policy, candidate, reviews,
  and launch gates;
- require the complete gate-specific control set and exact environment label for
  dedicated Linux/KVM isolation, blinded owned/licensed field validation, and
  exact-final-commit CI; and
- emit an inert `sova.launch-dossier`. Even a `ready` dossier MUST set
  `automaticPublishPerformed=false`; tagging, pushing, deployment, and publication
  remain separate explicitly authorized operations.

The dossier MUST include compact evaluation, Registry-control, review, and external-
gate summaries derived from the recomputed reports. A hold result MUST include a
sorted, unique `holdReasons` list that identifies every observed missing, failed,
synthetic, non-production, unauthorized, non-independent, inconclusive, or false
gate state. A ready result MUST have an empty hold-reason list.

`sova release assemble-evidence` MAY construct the bundle deterministically from
separate strict inputs and repeated receipt envelopes. Assembly MUST validate every
unsigned typed document and envelope shape, MUST NOT assert that signatures were
verified, and MUST perform no network, tag, push, deploy, or publication action.
Only `release dossier` evaluates the signatures and release gates.

Key possession and policy pinning do not legally verify a person's identity,
organization, independence, licence opinion, or evidence truth. The dossier states
that limitation explicitly.
