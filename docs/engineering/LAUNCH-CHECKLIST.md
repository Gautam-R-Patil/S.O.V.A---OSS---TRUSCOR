<!-- status: planned -->

# SOVA OSS — the launch checklist

**Opened:** 2026-09-08
**This is the list.** Everything between the code as it stands today and SOVA OSS
being publicly launched. Twelve phases, numbered in the order we do them.

Tick a box only when the evidence in its row exists. Not "it works" — the actual
receipt, digest, URL, or signature named in the row.

---

## How to read this

| Owner | Meaning |
|---|---|
| **ME** | I do it now. No dependency. |
| **YOU** | Only you can — money, credentials, a decision, a signature, an authorization. |
| **OTHER** | A third party — a reviewer, counsel, a volunteer. |
| **WAITING** | I do it, but a YOU or OTHER row above has to land first. |

**Phases 1-6 are my build work and run in sequence.**
**Phases 7, 8 and 9 are yours and other people's — start them NOW, today, because
they run in parallel with everything I build and they are the long poles.**
Phases 10-12 come last and only after everything above is green.

### Progress

| Phase | | Owner mix | Done |
|---|---|---|---|
| 1 | Make it installable | ME + YOU | ☐ 0/9 |
| 2 | Declare what is stable | YOU decides, ME writes | ☐ 0/8 |
| 3 | Finish the toolkit | ME | ☐ 0/9 |
| 4 | Open the contributor path | ME | ☐ 0/5 |
| 5 | Prove the format stands alone | ME + OTHER | ☐ 0/4 |
| 6 | Make contributions safe to accept | ME + YOU | ☐ 0/8 |
| 7 | Prove the isolation | YOU + OTHER | ☐ 0/9 |
| 8 | Deploy the Registry | YOU + OTHER | ☐ 0/7 |
| 9 | Get independently reviewed | YOU + OTHER | ☐ 0/5 |
| 10 | Reconcile every public claim | YOU + ME | ☐ 0/8 |
| 11 | Final release evidence | WAITING | ☐ 0/5 |
| 12 | Launch | YOU | ☐ 0/8 |
| | **Total** | | **0 / 85** |

### Where the code stands today

Verified 2026-09-08 on a clean run: **2,649 tests pass, 29 capability-gated skips,
zero failures**, 95.11% combined coverage, 149/149 CLI paths, Ruff and strict mypy
clean, repository policy and public-boundary scans pass. The engineering is
essentially done — this list is almost entirely evidence, distribution, and people.

---

## Phase 1 — Make it installable

*Nobody can use SOVA today. There is no install path. Nothing else on this list
matters until this is true.*

- [ ] **1.1** Confirm the `sova-oss` name is free on PyPI — **ME** — lookup recorded
- [ ] **1.2** Create the PyPI project, enable Trusted Publishing (OIDC) for this repo — **YOU** — publisher configured, no long-lived token anywhere
- [ ] **1.3** Add a tag-gated publish workflow with manual approval — **ME** — workflow refuses to run without explicit dispatch
- [ ] **1.4** Dry-run publish to TestPyPI — **WAITING** — TestPyPI artifact URL
- [ ] **1.5** Clean-environment install on Windows — **ME** — `sova --version` + `sova doctor` output
- [ ] **1.6** Clean-environment install on Linux (WSL Ubuntu) — **ME** — same, on Linux
- [ ] **1.7** Clean-environment install on macOS — **OTHER** — same, from a Mac we don't have
- [ ] **1.8** `docs/guides/installation.md` matches observed behavior exactly — **ME** — doc diff
- [ ] **1.9** README install block matches — **ME** — doc diff

---

## Phase 2 — Declare what is stable

*People cannot build on a surface whose stability is undeclared. Your version string
currently says `0.1.0a0` / "Pre-Alpha", which tells everyone not to bother.*

- [ ] **2.1** Decide the frozen surface — **YOU** — recommended: freeze `.sova`, `.sova-trace`, the 61 schemas and the CLI leaves; leave the Python API experimental
- [ ] **2.2** Write `docs/governance/api-stability.md` — **WAITING** — doc exists, linked from README
- [ ] **2.3** Enumerate the frozen surface explicitly — **WAITING** — an actual list, not a description
- [ ] **2.4** Enumerate the experimental surface explicitly — **WAITING** — actual list
- [ ] **2.5** Deprecation policy and notice period, consistent with ADR-0002 — **WAITING** — doc section
- [ ] **2.6** Align `pyproject.toml` version + Development Status with the statement — **WAITING** — metadata stops contradicting the contract
- [ ] **2.7** Extend `test_cli_surface_audit.py` so a frozen CLI leaf cannot vanish silently — **WAITING** — test fails when a frozen leaf is removed
- [ ] **2.8** Update the README status block — **WAITING** — doc diff

---

## Phase 3 — Finish the toolkit

*Admitted tools can only be executed from Python today. A contributor cannot run ZAP
or Nuclei from the CLI. That is the "one tool" gap.*

- [ ] **3.1** Design the `sova adapter run` argument surface — **ME** — design note in the adapter spec
- [ ] **3.2** Route execution through the authority kernel — **ME** — refusal test with no live authorization
- [ ] **3.3** Bind containment selection — **ME** — backend recorded in the trace
- [ ] **3.4** Gate external data transfer behind the disclosure gate — **ME** — denied-by-default test
- [ ] **3.5** Emit a signed trace for the run — **ME** — trace verifies offline
- [ ] **3.6** Normalize output to observations, never auto-findings — **ME** — `findingConfirmed: false` assertion
- [ ] **3.7** Adverse matrix: timeout, partial output, corrupt output, version drift, cleanup — **ME** — one test per class
- [ ] **3.8** CLI parser-to-handler audit stays at 100% — **ME** — `audit_cli_coverage.py` pass
- [ ] **3.9** Update the command reference and adapter specification — **ME** — doc diff

---

## Phase 4 — Open the contributor path

*This is the ecosystem. One example extension is not a contributor path.*

- [ ] **4.1** Write `docs/guides/building-on-sova.md` — **ME** — covers all 8 plug points and the executor contract
- [ ] **4.2** Add a second reference extension at a different plug point — **ME** — runs through `sova extension run`
- [ ] **4.3** Add a copyable extension starter template — **ME** — skeleton under `examples/extensions/`
- [ ] **4.4** Full round trip: author a playbook → keygen → sign → stage → review → resolve — **ME** — every step recorded
- [ ] **4.5** Link the guide from `CONTRIBUTING.md` and the README — **ME** — doc diff

---

## Phase 5 — Prove the format stands alone

*The only real proof `.sova` is a substrate and not one program's file layout. Costs
one competent stranger about a day.*

- [ ] **5.1** Export the conformance kit, verify its self-check — **ME** — kit digest
- [ ] **5.2** Write the implementer brief: what to build, run, and report — **ME** — brief exists
- [ ] **5.3** Find a volunteer implementer — **YOU** — named person
- [ ] **5.4** Record the result including every vector that failed — **OTHER** — report kept verbatim, failures retained

---

## Phase 6 — Make contributions safe to accept

*The registry will receive working offensive AI-security modules. It cannot open
without a named human responder and a rehearsed process.*

- [ ] **6.1** Write `docs/governance/community-module-triage.md` — **ME** — doc exists
- [ ] **6.2** Intake screening checklist — **ME** — doc section
- [ ] **6.3** Dual-use review criteria bound to `DUAL_USE_POLICY.md` — **ME** — doc section
- [ ] **6.4** Fix the contribution secret-scan gap — **ME** — JSON-escaped secrets currently evade `_SECRET` in `registry/contribution.py`; regression test proving `{"payload": "{\"token\": \"…\"}"}` is caught
- [ ] **6.5** Locate and test the no-unpatched-payload enforcement point — **ME** — test
- [ ] **6.6** Name the responder and the response target — **YOU** — named person, stated hours
- [ ] **6.7** Takedown procedure — **ME** — doc section
- [ ] **6.8** Rehearse the whole process once against a synthetic submission — **ME** — recorded rehearsal

---

## Phase 7 — Prove the isolation  ⚡ START NOW

*Everything below row 7.2 is already written, tested and waiting for hardware. One
host unlocks three gates. This runs in parallel with Phases 1-6.*

- [ ] **7.1** Provide a dedicated patched Linux/KVM host, or authority to provision one — **YOU** — reachable as `ssh sova-worker`; the private key never enters chat or Git
- [ ] **7.2** Configure the SSH alias locally — **YOU** — `ssh -G sova-worker` resolves a real host
- [ ] **7.3** Run the read-only host preflight — **WAITING** — green host-preflight receipt
- [ ] **7.4** Fill the worker policy with exact observed paths and SHA-256 pins — **WAITING** — no `REPLACE_WITH_*` placeholder remains
- [ ] **7.5** Provision with `--apply --ack-dedicated-host` — **WAITING** — explicit mutation authorization recorded first
- [ ] **7.6** Execute one live Firecracker microVM through the exact jailer lifecycle — **WAITING** — execution receipt
- [ ] **7.7** Run the positive control plus all ten malicious-guest classes — **WAITING** — eleven case receipts binding execution, network, raw evidence, cleanup
- [ ] **7.8** Compile the exact-host receipt from real observed cases only — **WAITING** — exact-host acceptance receipt
- [ ] **7.9** Independent isolation review of the exact measured configuration — **OTHER** — signed receipt; reviewer must not overlap any internal role

Negative results and incomplete cleanup are recorded as failures. No
escape-impossibility claim is ever made.

---

## Phase 8 — Deploy the Registry  ⚡ START NOW

*Built and loopback-proven, never deployed. For a community platform the module hub
is the product. Longest build-side pole: 3-6 weeks of real ops.*

- [ ] **8.1** Provide cloud account, domain and TLS — **YOU** — infrastructure exists
- [ ] **8.2** Name the operations owner and incident responder — **YOU** — named person
- [ ] **8.3** Run the immutable-image preflight — **WAITING** — preflight pass
- [ ] **8.4** Deploy the hardened blueprint — **WAITING** — service reachable
- [ ] **8.5** Exercise all ten readiness controls — **WAITING** — identity, moderation, malware/secret screening, rate+DDoS, encrypted backup, restore, rollback, monitoring, key rotation, incident response; one operational receipt each
- [ ] **8.6** Restore drill from a real backup — **WAITING** — restored service verified
- [ ] **8.7** Independent security review of the live public service — **OTHER** — signed review

---

## Phase 9 — Get independently reviewed  ⚡ START NOW

*All five must be role-separated; the verifier rejects shared keys and internal
overlap. **I am structurally ineligible for every row here.** Longest pole overall —
ask people today.*

- [ ] **9.1** Founder acceptance — **YOU** — signed role-scoped receipt
- [ ] **9.2** Independent technical validation — **OTHER** — signed receipt, no internal overlap
- [ ] **9.3** Independent isolation review — **OTHER** — must be a different person from 9.2
- [ ] **9.4** Legal / licence / public-disclosure review — **OTHER** — qualified counsel; none assigned yet
- [ ] **9.5** Security sign-off — **OTHER** — signed receipt

---

## Phase 10 — Reconcile every public claim

*The replacement copy is already written and waiting in the reconciliation packet.
truscor.org currently claims autonomous enterprise testing and actuarial risk
ratings that this codebase does not support.*

- [ ] **10.1** Approve the exact replacement copy for all seven surfaces — **YOU** — recorded approval
- [ ] **10.2** Deploy the approved wording to truscor.org — **YOU** — served response captured, not a search snippet
- [ ] **10.3** Check the GitHub repo description and social preview for retired claim language — **ME** — current text recorded
- [ ] **10.4** Freeze README, docs, demo, Registry and release-note bytes for the release commit — **WAITING** — digests
- [ ] **10.5** Bind the cleared paper, or an explicit no-paper release notice — **YOU** — decision recorded
- [ ] **10.6** Revise the README heading "The headline capability: find the sleeper" — **ME** — sleeper search is a shipped mechanism, not the OSS headline claim; the body text below it is already correctly hedged and stays
- [ ] **10.7** Add a claims-register row governing the OSS↔Engine capability boundary — **ME** — controls the exact wording of "OSS ships the mechanism, Engine has the tuned quality, OSS makes no parity claim"; no register row covers this today
- [ ] **10.8** `sova release dossier` reports `publicClaimsReconciled=true` — **WAITING** — dossier output

---

## Phase 11 — Final release evidence

*Runs last, on the exact release commit, after everything above is green. Any source
or public-copy change invalidates it and forces a recompute.*

- [ ] **11.1** Select the exact release commit — **YOU** — commit SHA
- [ ] **11.2** Full tests, static checks, dependency/licence/secret audits from a clean checkout — **WAITING** — signed deterministic-release-checks receipt
- [ ] **11.3** Deterministic build, isolated-wheel smoke, SBOMs, checksums — **WAITING** — byte-identical rebuild
- [ ] **11.4** Hosted CI provenance attestation — **WAITING** — attestation URL
- [ ] **11.5** Recompute the candidate and dossier with an out-of-band trust-policy pin — **WAITING** — dossier reports zero hold reasons

---

## Phase 12 — Launch

*Every row is a separate action needing its own explicit authorization from you, on
the day. Nothing here ever happens automatically.*

- [ ] **12.1** Push the branch — **YOU**
- [ ] **12.2** Tag the release — **YOU**
- [ ] **12.3** Create the GitHub release — **YOU**
- [ ] **12.4** Publish the package — **YOU**
- [ ] **12.5** Deploy the Registry publicly — **YOU**
- [ ] **12.6** Change the website — **YOU**
- [ ] **12.7** Announce — **YOU**
- [ ] **12.8** Independently re-verify the published artifacts after release — **ME**

---

## What SOVA OSS claims, and what it does not

**SOVA OSS ships the complete mechanism.** Recon, mapping, exploration,
methodology, adapters, oracles, evidence, reproduction, replay — and
conditional-trigger ("sleeper") search. It genuinely attempts all of it, sleeper
discovery included. Every one of those paths is open, auditable and extensible.
Nothing is stubbed out or held back.

**What it does not claim is quality.** Being *excellent* at sleeper discovery is
the product of accumulated tuning and learned intelligence, and under
[ADR-0003](../decisions/0003-open-source-and-proprietary-boundary.md) that stays
with the proprietary SOVA Engine. So the OSS claims exactly this and no more:

- it implements the mechanism, end to end, in the open;
- it is the foundation others fork and specialize into very good testers;
- it makes **no parity claim** with SOVA Engine, and no claim to find 99% or 100%
  of what a tuned tester would find.

**The constraint that keeps this honest.** ADR-0003 requires the public project to
be *non-crippled* and forbids hiding an essential implementation behind an account,
feature flag, proprietary plugin or network call. The Engine's advantage must
therefore be learned intelligence and accumulated work applied *on top of* the open
mechanism — never a mechanism removed from the OSS to widen the gap. Stripping
capability out of the public tree to flatter the closed product would violate the
constitution and forfeit exactly the contributor trust the ecosystem runs on.

**Therefore not on this list:** the blinded multi-provider study, matched
scanner/agent baselines, and the eight-class field-target run. Those measure
detection *performance*, which is an Engine and research claim. They remain
mandatory before any comparative, superiority, coverage or field-performance
statement — including any statement that SOVA finds what other tools miss — but
they do not block this release. Recorded formally in the
[controlling gate ledger](./universal-security-launch-checklist-2026-08-26.md),
which remains the machine-readable ledger that receipts and the release dossier
cite. This file is the plan; that file is the ledger.

---

## Changelog

| Date | Change |
|---|---|
| 2026-09-08 | Opened. Clean green baseline established (2,649 pass / 0 fail). Registry backup `MemoryError` fixed, commit `6f9418d`. Launch rescoped to the infrastructure release, commit `f5085c5`. |
