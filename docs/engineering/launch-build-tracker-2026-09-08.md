<!-- status: planned -->

# SOVA OSS launch build tracker

**Opened:** 2026-09-08
**Tracks:** every remaining task between the current tree and the public launch.
**Authority:** this file tracks *work*. It does not define scope. The
[universal-security launch checklist](./universal-security-launch-checklist-2026-08-26.md)
is the controlling gate ledger and every task below cites one of its IDs. Where the
two disagree, the checklist wins and this file is wrong.

## How to read this

Every task has an owner. That is the whole point of this file: you should be able to
open it and see, in ten seconds, what is waiting on me and what is waiting on you.

| Owner | Meaning |
|---|---|
| **CLAUDE** | I can do it now with no external dependency |
| **FOUNDER** | Only you can do it — money, credentials, authority, a decision, or a signature |
| **EXTERNAL** | A third party must do it — a reviewer, a volunteer implementer, counsel |
| **BLOCKED** | I do it, but only after a FOUNDER or EXTERNAL item lands first |

A task is checked only when its stated evidence exists. "It works on my machine" is
not evidence. "Code exists," "tests pass," and "the claim is cleared" stay separate
states, exactly as the controlling checklist requires.

## Live status

| | Count |
|---|---|
| Checklist items complete | 65 |
| Checklist items open and launch-blocking | 15 |
| Checklist items deferred to the Engine/research track | 4 |
| **Launch denominator** | **65 / 80 = 81%** |

Deferred items (P6-01, P6-02, P6-03, P6-05) are excluded from the denominator
because the 2026-09-08 rescope moved them off the OSS launch path. They are not
done, and they still block every comparative and field-performance claim.

### Where the 15 launch-blocking items sit

| Waiting on | Items |
|---|---|
| CLAUDE (I can start now) | P7-01, P7-02, P7-03, P7-04, P7-06, and the preparation half of P6-08 and P6-10 |
| FOUNDER | P5-01, P6-07, P6-09, P6-10, P6-11, plus ratifying P7-02 |
| EXTERNAL | P5-10, P6-09, P7-05 |
| BLOCKED behind a host | P5-03, P5-09 |

### Baseline at the time of writing

Established 2026-09-08 on a clean run, out-of-repo temp root, nothing concurrent:

- 2,649 passed, 29 capability-gated skips, **zero failures**, 7m13s
- 95.11% combined statement/branch coverage
- 149/149 CLI parser-to-handler paths
- Ruff clean across 734 files; strict mypy clean across 534
- Repository policy and public-boundary scans PASS at 900 files
- P4/P5/P6 deterministic acceptance digests reproduce exactly

Rerun the affected gates after every production change. Do not carry these numbers
to a different commit.

---

## P7-01 — Installable distribution

**Gate:** a person who has never seen this repository can install SOVA and run it.
Nothing else in the ecosystem matters until this is true.

| | Task | Owner | Evidence required |
|---|---|---|---|
| ☐ | Confirm the `sova-oss` name is available and unclaimed on PyPI | CLAUDE | Registry lookup recorded |
| ☐ | Create the PyPI project and enable Trusted Publishing (OIDC) for this repository | FOUNDER | Publisher configured; no long-lived token anywhere |
| ☐ | Add a tag-gated publish workflow with manual approval | CLAUDE | Workflow refuses to run without an explicit dispatch |
| ☐ | Dry-run publish to TestPyPI | CLAUDE | TestPyPI artifact URL |
| ☐ | Clean-environment install on Windows | CLAUDE | `sova --version` and `sova doctor` output |
| ☐ | Clean-environment install on Linux (WSL Ubuntu) | CLAUDE | same, on Linux |
| ☐ | Clean-environment install on macOS | EXTERNAL | same, from a machine we do not have |
| ☐ | `docs/guides/installation.md` matches observed behavior exactly | CLAUDE | Doc diff |
| ☐ | README install block matches | CLAUDE | Doc diff |

---

## P7-02 — API and schema stability contract

**Gate:** a downstream author can tell what they are allowed to build against.

> **Waiting on a decision from you.** Recommended split: freeze `.sova`,
> `.sova-trace`, the 61 schemas, and the CLI leaf surface. Leave the Python API
> experimental. That commits you to exactly what the conformance kit already tests
> and leaves the internals free to move.

| | Task | Owner | Evidence required |
|---|---|---|---|
| ☐ | Ratify the frozen/experimental split | FOUNDER | Recorded decision |
| ☐ | Write `docs/governance/api-stability.md` | BLOCKED | Doc exists and is linked from README |
| ☐ | Enumerate the frozen surface: artifact contracts, schema list, CLI leaves, exit codes | BLOCKED | Explicit list, not a description |
| ☐ | Enumerate the experimental surface | BLOCKED | Explicit list |
| ☐ | Deprecation policy and notice period, consistent with ADR-0002 | BLOCKED | Doc section |
| ☐ | Align `pyproject.toml` version and Development Status classifier with the statement | BLOCKED | The metadata no longer contradicts the contract |
| ☐ | Extend `test_cli_surface_audit.py` so a frozen CLI leaf cannot silently disappear | BLOCKED | Failing test when a frozen leaf is removed |
| ☐ | Update the README status block | BLOCKED | Doc diff |

---

## P7-03 — Adapter execution through the CLI

**Gate:** a contributor can run an admitted tool without writing Python. Execution
must stay impossible without an authority decision, and a normalized result must
still never become an automatic finding.

| | Task | Owner | Evidence required |
|---|---|---|---|
| ☐ | Design the `sova adapter run` argument surface | CLAUDE | Design note in the adapter specification |
| ☐ | Route execution through `AuthorityEnvelope` + `ActionIntent` | CLAUDE | Refusal test with no live authorization |
| ☐ | Bind containment selection through `ContainmentGate` | CLAUDE | Backend recorded in the trace |
| ☐ | Gate any external data transfer behind the disclosure gate | CLAUDE | Denied-by-default test |
| ☐ | Emit a signed trace covering the run | CLAUDE | Trace verifies offline |
| ☐ | Normalize output to observations with `findingConfirmed: false` | CLAUDE | Assertion test |
| ☐ | Adverse matrix: timeout, partial output, corrupt output, version drift, cleanup | CLAUDE | One test per class |
| ☐ | CLI parser-to-handler audit stays at 100% | CLAUDE | `audit_cli_coverage.py` pass |
| ☐ | Update `docs/guides/command-reference.md` and the adapter specification | CLAUDE | Doc diff |

---

## P7-04 — Contributor path proven end to end

**Gate:** somebody other than us can extend SOVA and get their work reviewed.

| | Task | Owner | Evidence required |
|---|---|---|---|
| ☐ | Write `docs/guides/building-on-sova.md` | CLAUDE | Covers all 8 extension kinds and the executor contract |
| ☐ | Add a second reference extension at a different plug point from the existing oracle | CLAUDE | Runs through `sova extension run` |
| ☐ | Add an extension starter template under `examples/extensions/` | CLAUDE | Copyable skeleton |
| ☐ | Full round trip: author a playbook, keygen, sign, stage, review, resolve | CLAUDE | Recorded run of every step |
| ☐ | Link the guide from `CONTRIBUTING.md` and the README | CLAUDE | Doc diff |

---

## P7-05 — Independent implementation of the format

**Gate:** the only real proof `.sova` is a substrate and not one program's file
layout. Needs roughly one day from one competent stranger.

| | Task | Owner | Evidence required |
|---|---|---|---|
| ☐ | Export the conformance kit and verify its self-check | CLAUDE | Kit digest |
| ☐ | Write the implementer brief: what to build, what to run, what to report | CLAUDE | Brief exists |
| ☐ | Find a volunteer implementer | FOUNDER | Named person |
| ☐ | Receive and record the result, including every vector that failed | EXTERNAL | Report recorded verbatim, failures retained |

---

## P7-06 — Community-module safety triage

**Gate:** the registry cannot open to offensive AI-security content without a named
human responder and a rehearsed process. Someone *will* submit a working exploit.

| | Task | Owner | Evidence required |
|---|---|---|---|
| ☐ | Write `docs/governance/community-module-triage.md` | CLAUDE | Doc exists |
| ☐ | Intake screening checklist | CLAUDE | Doc section |
| ☐ | Dual-use review criteria bound to `DUAL_USE_POLICY.md` | CLAUDE | Doc section |
| ☐ | Fix the contribution secret-scan gap: JSON-escaped secrets currently evade `_SECRET` in `registry/contribution.py` | CLAUDE | Regression test proving `{"payload": "{\"token\": \"…\"}"}` is caught |
| ☐ | Locate and test the no-unpatched-payload enforcement point in code | CLAUDE | Test |
| ☐ | Name the responder and the response target | FOUNDER | Named person, stated hours |
| ☐ | Takedown procedure | CLAUDE | Doc section |
| ☐ | Rehearse the process once against a synthetic submission | CLAUDE | Recorded rehearsal |

---

## P5-01, P5-03, P5-09, P5-10 — Production isolation

**Gate:** one dedicated Linux/KVM host unlocks three of these four. Everything below
the first row is written, tested, and waiting for hardware.

| | Task | Owner | Evidence required |
|---|---|---|---|
| ☐ | Provide a dedicated patched Linux/KVM host, or authority to provision one | FOUNDER | Reachable as `ssh sova-worker`; private key never enters chat or Git |
| ☐ | Configure the SSH alias locally | FOUNDER | `ssh -G sova-worker` resolves a real host |
| ☐ | **P5-01** Run the read-only host preflight | BLOCKED | Green `sova.worker-host-preflight-receipt` |
| ☐ | **P5-01** Fill the worker policy with exact observed paths and SHA-256 pins | BLOCKED | No `REPLACE_WITH_*` placeholder remains |
| ☐ | **P5-01** Provision with `--apply --ack-dedicated-host` | BLOCKED | Explicit mutation authorization recorded first |
| ☐ | **P5-03** Execute one live Firecracker microVM through the exact jailer lifecycle | BLOCKED | `sova.firecracker-execution-receipt` |
| ☐ | **P5-09** Run the positive control plus all ten malicious-guest classes | BLOCKED | Eleven case receipts binding execution, network, raw evidence, cleanup |
| ☐ | **P5-09** Compile the exact-host receipt from real observed cases only | BLOCKED | `sova.worker-exact-host-acceptance-receipt` |
| ☐ | **P5-10** Independent isolation review of the exact measured configuration | EXTERNAL | Signed receipt; reviewer must not overlap any internal role |

Negative results and incomplete cleanup are recorded as failures. No escape-
impossibility claim is ever made.

---

## P6-07 — Registry beta deployment

| | Task | Owner | Evidence required |
|---|---|---|---|
| ☐ | Provide cloud account, domain, and TLS | FOUNDER | Infrastructure exists |
| ☐ | Name the operations owner and incident responder | FOUNDER | Named person |
| ☐ | Run the immutable-image preflight | BLOCKED | Preflight pass |
| ☐ | Deploy the hardened blueprint | BLOCKED | Service reachable |
| ☐ | Exercise all ten readiness controls: identity, moderation, malware and secret screening, rate/DDoS, encrypted backup, restore, rollback, monitoring, key rotation, incident response | BLOCKED | `sova.registry-operational-receipt` per control |
| ☐ | Independent security review of the public service | EXTERNAL | Signed review |

---

## P6-08 — Final-commit release evidence

Runs **last**, on the exact release commit, after every other gate is green. Any
source or public-copy change invalidates it and forces a recompute.

| | Task | Owner | Evidence required |
|---|---|---|---|
| ☐ | Select the exact release commit | FOUNDER | Commit SHA |
| ☐ | Full tests, static checks, dependency/licence/secret audits from a clean checkout | BLOCKED | Signed `deterministic-release-checks` receipt |
| ☐ | Deterministic build, isolated-wheel smoke, SBOMs, checksums | BLOCKED | Byte-identical rebuild |
| ☐ | Hosted CI provenance attestation | BLOCKED | Attestation URL |
| ☐ | Recompute the candidate and dossier with an out-of-band trust-policy pin | BLOCKED | Dossier reports no hold reason |

---

## P6-09 — Five role-separated reviews

The verifier rejects shared role keys and any internal/independent overlap. **I am
structurally ineligible for every row here.** Start asking now — this is the longest
pole and it runs in parallel with all build work.

| | Task | Owner | Evidence required |
|---|---|---|---|
| ☐ | Founder acceptance | FOUNDER | Signed role-scoped receipt |
| ☐ | Independent technical validation | EXTERNAL | Signed receipt, no internal overlap |
| ☐ | Independent isolation review | EXTERNAL | Distinct from the technical reviewer |
| ☐ | Legal / licence / public-disclosure review | EXTERNAL | Qualified counsel; none assigned yet |
| ☐ | Security sign-off | EXTERNAL | Signed receipt |

---

## P6-10 — Public claims reconciliation

Replacement copy is already written in the
[reconciliation packet](./p6-public-claims-reconciliation-2026-08-31.md).

| | Task | Owner | Evidence required |
|---|---|---|---|
| ☐ | Approve the exact replacement copy for all seven surfaces | FOUNDER | Recorded approval |
| ☐ | Deploy the approved wording to truscor.org | FOUNDER | Served response captured, not a search snippet |
| ☐ | Check the GitHub repository description and social preview for retired claim language | CLAUDE | Recorded current text |
| ☐ | Freeze README, documentation, demo, Registry, release-note bytes for the release commit | BLOCKED | Digests |
| ☐ | Bind the exact cleared paper, or an explicit no-paper release notice | FOUNDER | Decision recorded |
| ☐ | `sova release dossier` reports `publicClaimsReconciled=true` | BLOCKED | Dossier output |

---

## P6-11 — Publication

Every action on this row is separate and each needs its own explicit authorization
from you, on the day. Nothing here happens automatically.

| | Task | Owner |
|---|---|---|
| ☐ | Push the branch | FOUNDER |
| ☐ | Tag the release | FOUNDER |
| ☐ | Create the GitHub release | FOUNDER |
| ☐ | Publish the package | FOUNDER |
| ☐ | Deploy the Registry publicly | FOUNDER |
| ☐ | Change the website | FOUNDER |
| ☐ | Announce | FOUNDER |
| ☐ | Independently re-verify the published artifacts after release | CLAUDE |

---

## Tracker changelog

| Date | Change |
|---|---|
| 2026-09-08 | Opened. Baseline recorded. Registry backup `MemoryError` fixed under P6-07 (commit `6f9418d`). Controlling checklist rescoped to the OSS infrastructure release; P7 added; P6-01/02/03/05 deferred to the Engine/research track. |
