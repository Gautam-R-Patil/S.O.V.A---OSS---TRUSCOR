<!-- status: claim -->

# SOVA OSS — Full Session Change Report

**Date compiled:** 2026-08-24
**Scope:** every file touched in this working tree since the last commit (`e985467`, 2026-08-21), across the entire conversation — planning docs, new source modules, modified core modules, and new tests.
**Status:** all changes are **uncommitted** (working tree only). Nothing in this report has been pushed or merged.

---

## 1. Executive summary

This session built out the "SOVA Engine" from a single-agent, browser-only tool into the founder's full vision: **authorized multi-agent swarms that can drive a browser, a desktop (computer-use), a terminal/host-process, and a disposable file workspace in one run, with adversarial/stress testing, an evidence trail, and default-on contribution to a community registry** — all gated behind proof-of-control and human approval.

**Totals:**

| | Count |
|---|---|
| Files changed (modified) | 11 |
| Files added (new) | 64 |
| **Total files touched** | **75** |
| New lines in new source files (`src/`) | ~14,650 |
| New lines in new tests | ~11,750 |
| New lines in planning docs | ~2,080 |
| Net insertions in modified tracked files | 1,368 (−38) |
| **Approx. total lines added this session** | **~29,800** |
| Unit tests passing at last full gate | **1680 passed, 3 skipped** |
| CLI command handlers | 116 → **121** |

Work was done in two deliberate phases at the user's request: **Phase 1** (architecture/planning, done on Opus) produced two handoff documents that resolved every hard design question up front; **Phase 2** (mechanical build-out, done on Sonnet) implemented against those documents task-by-task with a lint/type/test gate after each one.

---

## 2. Planning documents (new)

### `docs/engineering/last-mile-launch-implementation-plan-2026-08-21.md` (1,316 lines)

The Phase-1 architecture document. States four founder decisions as ground truth and designs the implementation against the **existing** codebase (a "ground truth" table lists every load-bearing symbol already in place, so nothing gets rebuilt by accident):

1. **Swarm** = parallel isolated sessions (own browser context + own workspace each) + a shared redacted blackboard + a coordinator that merges everything into one `.sova`. Always ask the operator how many agents.
2. **Computer use** = wire **MELRA** for desktop computer-use only; browser stays on Playwright, terminal stays on the restricted local executor, files stay on the workspace executor.
3. **Guardrails stay but must not cap capability** — once control is proven and authorization granted, the engine must be able to do anything a real test needs (click/drag/type/scroll/settings/forms/messages) on the authorized target, including adversarial/jailbreak-style missions. This is where the **guarded irreversible opt-in** on `AuthorityEnvelope` was designed (Workstream C.3) — irreversible effects stay blocked by default; an explicit `allow_irreversible=True` plus proven self/explicit ownership plus a forced DESTRUCTIVE approval unlocks them.
4. **Arena** = records every action/intent from both sides of a match into `.sova`, and **contributes to the SOVA registry by default** (`--no-contribute` is the opt-out), via an HTTP client to a self-hosted registry service with a local git-PR fallback that never pushes or opens anything on its own.

### `docs/engineering/sova-engine-completion-buildplan-2026-08-21.md` (767 lines)

The Phase-2 execution plan — five self-contained tasks (6 through 10), each with exact files, signatures, invariants, tests, and a gate to pass before moving on. Its status table now shows every founder-vision capability as **Done**, and it records the final gate result (1680 tests, 3 skipped, clean ruff/mypy) plus one real bug found and fixed during Task 9 (see §6).

---

## 3. New source modules (29 files, ~14,650 lines)

### 3.1 The Executor Chamber — the trusted multi-agent coordinator core

| File | Lines | What it is |
|---|---|---|
| `src/sova/community/executor_chamber.py` | 2,351 | The largest new module. The trusted coordinator that runs authorized multi-agent missions: validates one typed planner action at a time, binds it to the current observation and exact executor generation, gets a fresh authorization decision, serializes intersecting mutations, and records independently-checked outcomes. Planner models are **proposal-only** — they never see executor objects, workspace paths, or secrets. Key types: `ExecutorChamberBudget`, `ExecutorChamberGrant`, `ExecutorChamberParticipant`, `ExecutorChamberCase`, `ChamberObservation`, `ChamberVerification`, `ChamberOracleResult`, `ChamberActionCodec`/`ChamberDeterministicOracle` (Protocols), `ProjectionFieldOracle`, `ExecutorChamberEnvironment` (Protocol), `ChamberAuthorizationController`, and the top-level `run_executor_chamber`. |
| `src/sova/community/executor_chamber_config.py` | 682 | Strict, side-effect-free portable parsing/validation of a chamber document into the dataclasses above (`ExecutorChamberAuthorityPolicy`, `DeclaredOciParticipant`, `ValidatedExecutorChamberGrant/Model/Document`) — `validate_executor_chamber_document`, `parse_executor_chamber_document`, `run_executor_chamber_document`. |
| `src/sova/community/executor_engine.py` | 670 | The single-run heterogeneous engine on top of the chamber. `EngineSurfaceGeneration` (a closable, contract-hashing surface handle), `ExecutorEngineRuntime` (owns codec routing by `grant.codec_id`, and — the key safety property — **rejects aliased executors across phases and rejects contract-digest drift** between discovery and reproduction runs), `run_executor_engine_document`. |
| `src/sova/community/executor_engine_full.py` | 275 | Composes browser + workspace + an optional MELRA computer surface + an optional one reviewed host process, under one proof-of-control gate. `MelraComputerBackendSpec` (deliberately has **no** `identity_digest` field — see the Task-9 bug in §6), `run_full_capability_web_engine`. |
| `src/sova/community/executor_engine_runtime_config.py` | 446 | Strict parsing of a declarative "additional runtime surfaces" document (disposable workspace + explicitly-acknowledged shell-free host-process templates) into an `ExecutorEngineRuntimeSurfaceBuilder`. |
| `src/sova/community/executor_surfaces.py` | 1,001 | Concrete built-in surface generators: `workspace_surface_generation`, `browser_surface_generation`/`browser_codec_factory`, `computer_surface_generation`/`computer_codec_factory`, `melra_computer_surface_generation`, `process_surface_generation`/`process_codec_factory`, `gvisor_process_surface_generation`/`oci_process_codec_factory`, plus `ExactProcessSurfaceSpec`/`ExactOciProcessSurfaceSpec`. |
| `src/sova/community/live_executor_engine.py` | 486 | The authorized live-web composition entry point most CLI commands call: `run_live_web_executor_engine`. Accepts `additional_surface_factory`/`additional_codec_factories`/`additional_surface_contract_digest` — the extension seam every other engine (full-capability, swarm) is built on without touching this file's core logic. |

### 3.2 The Swarm package — concurrent multi-agent runs

`src/sova/community/swarm/` (new package, 7 files, ~1,258 lines):

| File | Lines | What it is |
|---|---|---|
| `__init__.py` | 33 | Package exports: `SwarmBlackboard`, `SwarmCoordinator`/`AgentRunResult`, `SwarmMessage`/`SwarmMessageKind`, `SwarmArtifacts`/`run_web_swarm`, `StressReport`/`run_stress_profile`, `SwarmWorkerSpec`/`run_swarm_worker`. |
| `blackboard.py` | 123 | `SwarmBlackboard` — thread-safe, redaction-checked, **hash-chained** shared message board. In-memory only; durable evidence comes from the coordinator embedding the full transcript into a signed trace. |
| `message.py` | 116 | `SwarmMessage`/`SwarmMessageKind` — the typed, bounded, pre-redaction-checked message contract every blackboard post must satisfy. |
| `coordinator.py` | 423 | `SwarmCoordinator.seed()` (differentiates each worker's objective with a bounded prior-findings summary) and `.merge()` (folds every worker's artifacts into one `.sova`); `_observer_participant` injects an inert 2nd participant so a 1-agent swarm still satisfies the chamber's 2–8 participant minimum. |
| `runtime.py` | 154 | `run_web_swarm` — `ThreadPoolExecutor`-based concurrency, each worker gets its own isolated single-agent engine run (own browser context, own disposable workspace); `SwarmArtifacts`. |
| `worker.py` | 207 | `run_swarm_worker` — one swarm agent: a thin wrapper around the unchanged `run_live_web_executor_engine`, plus `_BlackboardBridge`, a one-directional live event→`SwarmMessage` extraction bridge (workers cannot inject messages back into a running peer). |
| `stress.py` | 202 | `run_stress_profile` — the bounded "stress testing" profile. Hard, non-operator-raisable ceilings: `_MAX_AGENTS = 8`, `_MAX_REPETITIONS = 25`, `_MAX_TOTAL_INTERACTIONS = 128` (deliberately below `8×25=200` so it's an independent real ceiling, not one implied by the other two — this diverges from the plan's original 200, see §6). Builds **one** offensive battery mission folding every selected adversarial tactic's payloads, then delegates to `run_web_swarm(..., offensive=True)`. Explicitly **not** request flooding. |

### 3.3 Runtime surface & contract layer (9 files, ~5,950 lines)

`src/sova/runtime/` — the low-level typed contracts and codecs the engine composes:

| File | Lines | What it is |
|---|---|---|
| `action_codecs.py` | 1,134 | Fail-closed codecs turning untrusted model JSON into bounded `ActionRequest`s: `ComputerActionCodec` (with `ReviewedComputerTarget`, `ComputerIdentityBinding`), `BrowserActionCodec`, `WorkspaceActionCodec`, `ProcessActionCodec`, `OciProcessActionCodec`. |
| `bound_environment.py` | 1,093 | `BoundExecutorChamberEnvironment` — the concrete trusted environment for one session-bound chamber run; owns the immutable target/session generation, the exact capability→executor registry, and the disposable workspace. Also `LazyStdioExecutor`-adjacent guards (`_GuardedExecutor`, `_OpaqueSecretProvider`) and per-call integrity/backend-record assertions. |
| `browser_surface.py` | 653 | `ManagedPlaywrightBrowserSurface` — the concrete session-bound Playwright executor and its `_SessionBoundBrowserExecutor` adapter. |
| `computer_surface.py` | 458 | `ManagedComputerSurface` — session-bound computer executor + `ComputerSurfaceSnapshot`; converts a callback's target list into immutable reviewed locators **before** planner output can select one. |
| `environment_builder.py` | 269 | `build_bound_executor_environment` — trusted-coordinator API turning already-admitted executor objects + operator-attested target metadata into immutable generation bindings; `TargetEnvironmentAdmission`, `BackendAdmission`. |
| `managed_surfaces.py` | 542 | `LazyStdioExecutor` (starts a pinned MCP backend only after the chamber owns its workspace; fails closed unless the live backend's contract exactly matches what was advertised), `CompositeObservationSource`, `EvidenceSatisfactionPolicy`/`PolicyEvidenceVerifier`. |
| `melra_computer.py` | 386 | The narrowed MELRA desktop computer-use wrapper: `MelraComputerExecutor`, `melra_computer_lazy_executor`, `_parse_inspect_elements` (per-element capability = element flags ∩ operator ceiling), `MelraComputerSnapshotSource`. **`computer.inspect`'s real provider-output shape is still flagged provisional** — pinned against a fake transport in unit tests only (see §7, unresolved). |
| `target_environment.py` | 413 | Immutable `TargetInstance`/`SessionEnvelope`/`BackendGeneration`/`CapabilityGeneration` contracts describing an already-admitted target — no launching, no secrets. |
| `unified_execution.py` | 1,005 | Session-affine action admission: `BoundActionProposal`, `CapabilityBinding`, `ExecutionGrant`, `MutationScheduler` (deterministic resource-conflict scheduling), `CoordinatorEventEvidenceSink`/`SingleCoordinatorSink`. |

### 3.4 Registry contribution (3 files, ~416 lines)

| File | Lines | What it is |
|---|---|---|
| `src/sova/registry/auto_contribute.py` | 112 | `auto_contribute_after_run` — default-on, explicitly opt-out-able (`enabled=False`) contribution of a run's `.sova`/`.sova-trace`. Disclosed contribution, not silent telemetry: reuses the same redaction/secret/malware/schema gates as manual uploads and always returns a full report of what was or wasn't contributed and why. |
| `src/sova/registry/client.py` | 184 | `RegistryClient`/`RegistryEndpoint` — stdlib-only HTTP client for the operator-run, loopback-bound registry service (`health`, `submit_capsule_and_trace`, `submission_status`, `wait_until_terminal`). |
| `src/sova/registry/pr_contribution.py` | 120 | `prepare_pr_contribution` — the local-only git-PR fallback. Renders a branch name, commit message, and PR body next to an already-staged contribution directory. **Never runs `git push` or opens a PR** — every git/hosting action is left to the human operator. |

### 3.5 Safety, executors, and adversarial missions (3 files, ~1,115 lines)

| File | Lines | What it is |
|---|---|---|
| `src/sova/safety/profiles.py` | 162 | `full_capability_authority` and `DEFAULT_FULL_CAPABILITY_ACTIONS` — a pre-scoped authority **convenience constructor**, not new trust logic; every profile still passes through the same `AuthorityEnvelope.__post_init__` invariants and the same per-action kernel checks as any hand-built authority. |
| `src/sova/executors/workspace.py` | 653 | `WorkspaceExecutor` (move/read/write/delete inside a disposable workspace, with move preimage verification) and `ExactProcessExecutor` (one reviewed host-process template, exact argv-prefix only). |
| `src/sova/live/adversarial_missions.py` | 300 | The curated adversarial/red-team mission library: `AdversarialTactic`, `adversarial_tactic`/`adversarial_tactic_ids`, `build_adversarial_mission`. Every tactic builds an `offensive=True` mission mapped to an existing `sova.attack` taxonomy entry (validated at build time), attacks instruction-following/grounding (never credential-shaped text, so it also passes the mission builder's own secret screen), and is forced through DESTRUCTIVE human approval + proof-of-control before it can run. |

---

## 4. Modified tracked files (11 files, +1,368/−38 lines)

This is where the CLI surface and a significant **authorization-binding security hardening** landed.

### 4.1 `src/sova/cli.py` (+798 net lines)

Four new subcommands under `sova engine`:

- **`engine validate`** — effect-free validation of a chamber document (no executors started, no provider calls made).
- **`engine run-web`** — the original single-agent authorized browser+workspace run, now also accepting `--runtime-surfaces` for declarative additional surfaces.
- **`engine swarm-web`** — N concurrent agents (2–8 by default; `--allow-large-swarm` to raise), each isolated, sharing one blackboard.
- **`engine full-web`** — one agent, browser+workspace+**optional MELRA computer** (`--melra-node/-cli/-policy/-pid/-window-id/-mutations`)+**optional one reviewed host process** (`--process-template-id/--process-executable/--process-argv-prefix/--trusted-host-process`).
- **`engine stress-web`** — the bounded adversarial "stress" profile (`--entry-url` required, `--agents`, `--repetitions` ≤25, `--tactics`); always forces `allow_large_swarm=False` so the stress ceiling can never be operator-raised.

All four share `_add_contribution_arguments` (`--no-contribute`, `--registry-url`, `--registry-token`, `--contributor-name/-identity`) and the new `_contribute_run_evidence` helper, which contributes to the registry **on by default** after a run — and is designed so a contribution-side failure (bad gate, unreachable service) is reported alongside the run's output but can **never** turn an otherwise-successful run into a CLI failure.

### 4.2 `src/sova/executors/runner.py` (+140 net lines) — authorization request-binding hardening

This is the most security-significant tracked-file change. It closes a gap where an authorization decision could, in principle, be reused to authorize a different (substituted) request:

- New `canonical_action_request_mapping`/`canonical_action_request_digest` — a canonical, complete digest of every executable field of an `ActionRequest`.
- `action_intent_for_step` now takes an actual `request` (defaulting to the canonical scenario step) and **raises if its digest doesn't match** the canonical expected request; it also accepts `participant_id`, `session_id`, `observation_digest`, and computes a `capability_generation` digest that must match if one is supplied.
- `run_capsule` now: builds the request digest before authorizing; after getting a decision, **verifies the decision's bound digests exactly match the intent's** (`decision.request_digest`, `.participant_id`, `.session_id`, `.observation_digest`, `.capability_generation`) and fails the step (`authorization-decision-binding-mismatch`) if not; and — critically — **re-checks the request's digest again right before dispatch** and fails (`request-mutated-after-authorization`) if the request was mutated between authorization and execution. This is a TOCTOU-style protection specifically relevant to computer-use/CUA-style executors, where a mismatch between what a human approved and what actually gets typed/clicked would otherwise be silent.

### 4.3 `src/sova/safety/authorization.py` (+~100 net lines) — the kernel side of the same hardening

- `ActionIntent` gains `request_digest`, `participant_id`, `session_id`, `observation_digest`, `capability_generation` — all optional, but **fail closed as a group**: if a request digest is present, `capability_generation` must be too; if any of participant/session/observation is present, all three must be; every digest field must be a valid lowercase SHA-256.
- `AuthorityEnvelope` gains `allow_irreversible: bool = False` (the guarded opt-in from the launch plan) — and it's rejected outright if `ownership == "legal-offline"` (an offline legal-acquisition authority can never unlock irreversible effects).
- `AuthorizationKernel.decide`: `intent.irreversible` is now only blocked when `not authority.allow_irreversible`; when irreversible **is** allowed, it further requires `ownership` to be `"self"` or `"explicit"` (`irreversible-requires-proven-ownership`) — so an unproven or third-party authority still cannot unlock irreversible effects even with the flag set. Also rejects a mismatched `participant_id` against the authority's subject. `_approval_level` now also forces DESTRUCTIVE for any `irreversible` intent (not just `offensive`/`DESTRUCTIVE` effect).
- `AuthorizationDecision` carries the same five binding fields through to its `to_mapping()` output as an `executionBinding` block, so every executor sees an auditable, complete binding — this is what `_CuaStyleAuthorizationExecutor` in the new integration test asserts against.

### 4.4 `src/sova/registry/contribution.py` (+~40 net lines) — archive-content scanning

Previously the malware/secret scanners only ever saw the **raw, still-compressed** bytes of a `.sova`/`.sova-trace` package — meaning a secret or executable payload hidden *inside* the zip archive would sail through undetected. New `_scan_archive_members` opens the archive and scans every **decompressed** member's content against the same executable-magic and secret-pattern checks, with independent per-member (64 MB) and total-decompressed (256 MB) size caps to prevent a zip-bomb from being used to exhaust memory during the scan. `.sova-trace` files are now recognized and schema-verified the same way `.sova` capsules already were.

### 4.5 `src/sova/live/__init__.py`, `src/sova/registry/__init__.py`, `src/sova/safety/__init__.py`

Pure re-export wiring for the new modules above (`adversarial_tactic(_ids)`/`build_adversarial_mission`, `RegistryClient`/`RegistryEndpoint`/`auto_contribute_after_run`/`prepare_pr_contribution`, `DEFAULT_FULL_CAPABILITY_ACTIONS`/`full_capability_authority`).

### 4.6 Test-support and test files modified

- `tests/support/authorization.py` — `authorize_synthetic_steps` now accepts the same four optional binding kwargs, threaded into every synthetic `action_intent_for_step` call.
- `tests/integration/test_executor_vertical_slice.py` (+146 lines) — new `_CuaStyleAuthorizationExecutor` fixture plus two new tests: one proves a legitimate request gets an `allowed` decision with a fully-populated `executionBinding`; the other (`test_runner_rejects_approved_request_after_input_substitution`) proves that approving one scenario and then running a **different** (input-substituted) one is rejected with `approval-scope-mismatch` and the executor is never even called.
- `tests/unit/test_safety_authorization.py` (+91 lines) — direct kernel-level tests of the same substitution protection (request digest, participant, session, observation, capability generation each independently substitutable → each independently rejected) and of malformed/incomplete-binding fail-closed behavior.
- `tests/unit/test_cli_surface_audit.py` — handler count assertion updated `116 → 121`.

---

## 5. New tests (33 files, ~11,750 lines)

### 5.1 Unit tests (30 files)

| Area | Files |
|---|---|
| Chamber / engine core | `test_executor_chamber.py`, `test_executor_chamber_config.py`, `test_executor_engine.py`, `test_executor_engine_full.py`, `test_executor_engine_runtime_config.py`, `test_executor_surfaces.py`, `test_bound_environment.py`, `test_environment_builder.py`, `test_managed_surfaces.py`, `test_unified_execution_core.py`, `test_unified_action_codecs.py` |
| Browser / computer surfaces | `test_browser_surface.py`, `test_computer_surface.py`, `test_melra_computer.py`, `test_oci_process_surface.py` |
| Swarm | `test_swarm_blackboard.py`, `test_swarm_coordinator.py`, `test_swarm_message.py`, `test_swarm_runtime.py`, `test_swarm_worker.py`, `test_swarm_stress.py` |
| Workspace / process executors | `test_workspace_executor.py` |
| Authorization / authority profiles | `test_full_capability_authority.py`, `test_irreversible_optin.py` |
| Adversarial missions | `test_adversarial_missions.py` |
| Registry / contribution | `test_registry_auto_contribute.py`, `test_registry_client.py`, `test_registry_contribution_archive_scan.py`, `test_registry_pr_contribution.py` |
| CLI wiring | `test_cli_contribution_wiring.py` |

### 5.2 Integration tests (3 files) — **environment-gated live conformance lanes, not yet run**

| File | Gate | What it proves against a real backend |
|---|---|---|
| `test_real_browser_swarm.py` | `SOVA_RUN_REAL_BROWSER=1` | `run_web_swarm` really launches N independent browser contexts concurrently, each under its own loopback proof-of-control, and really merges them into one `swarm.sova` capsule + coordinator trace. |
| `test_real_melra_computer.py` | `SOVA_RUN_MELRA=1` + `SOVA_MELRA_NODE`/`SOVA_MELRA_CLI` | Drives the narrowed SOVA MELRA wrapper (`melra_computer_lazy_executor`/`MelraComputerSnapshotSource`) against a **real** MELRA instance — the one place the provisional `computer.inspect` output-shape assumption gets checked outside a fake transport. |
| `test_real_full_capability.py` | both of the above together | Proves the full composition (contract-digest pinning, session-identity derivation for the computer surface, admission of a fourth codec) wires together against real subprocesses at once — not any one surface's mutation algebra end-to-end (that's covered elsewhere). |

All three use a scripted model that stops on its first turn — they validate wiring/composition, not planner behavior.

---

## 6. Bugs found and fixed during this session

1. **Computer-surface identity-binding bug (Task 9, the most significant).** `executor_engine_full.py`'s composed computer surface could never actually bind at runtime: `ManagedComputerSurface.bind()` requires, for a `window`-kind surface, that `TargetInstance.process_id`/`window_handle_digest` are populated *and* that `session.identity_digest` equals the surface's own `identity_digest` — but `run_live_web_executor_engine` never populated those `TargetInstance` fields, and derives session identity internally. **Fix:** added opt-in `additional_target_process_id`/`_process_start_digest`/`_window_handle_digest` passthrough params to `run_live_web_executor_engine` (every existing caller leaves them `None`, so no prior behavior changed), and removed `identity_digest` from `MelraComputerBackendSpec` in favor of `_session_identity_digest()`, which mirrors the engine's own identity formula exactly. This was found by reasoning through what the live integration test would actually exercise — unit tests alone could not have surfaced it.
2. **`_MAX_TOTAL_INTERACTIONS` was unreachable.** The plan specified `200`, but `_MAX_AGENTS(8) × _MAX_REPETITIONS(25) = 200` exactly, so the ceiling could never independently trigger. Lowered to **128** — a deliberate, documented deviation from the original plan.
3. **Contribution scanner blind spot.** The malware/secret scan on `.sova`/`.sova-trace` uploads only ever inspected raw compressed bytes; a payload hidden inside the archive would pass unnoticed. Fixed with `_scan_archive_members` (§4.4) — found and fixed as part of this session's hardening pass, with `test_registry_contribution_archive_scan.py` added specifically to cover it.
4. **Authorization request-substitution gap.** Nothing previously bound an authorization decision to the *exact* request content, participant, session, and observation that produced it — so a decision computed for one action could, in principle, be replayed against a different (substituted) request. Closed via the request/capability-generation binding described in §4.2/§4.3.

---

## 7. What is *not* yet verified (the one open pre-launch item)

The three environment-gated integration tests in §5.2 have **never been run** — they require Node, Playwright, and a MELRA build, none of which are available in this environment. Until they run:

- MELRA's `computer.inspect` provider-output shape remains **provisional** (flagged directly in `src/sova/runtime/melra_computer.py`'s docstring) — pinned only against a fake transport in unit tests. If the real shape differs, `_parse_inspect_elements` (and its unit tests) need a contained adjustment.
- The concurrent real-browser swarm launch and the full four-surface composition have not been proven against real subprocesses.

**To close this out**, on a machine with the toolchain installed:
```
SOVA_RUN_REAL_BROWSER=1 pytest tests/integration/test_real_browser_swarm.py
SOVA_RUN_MELRA=1 SOVA_MELRA_NODE=<path> SOVA_MELRA_CLI=<path> pytest tests/integration/test_real_melra_computer.py
SOVA_RUN_REAL_BROWSER=1 SOVA_RUN_MELRA=1 SOVA_MELRA_NODE=<path> SOVA_MELRA_CLI=<path> pytest tests/integration/test_real_full_capability.py
```

## 8. Repository state

- **Last commit:** `e985467` — "feat: harden browser swarm evidence and OCI planners" (2026-08-21 01:24:17 +0530).
- Everything described in this report (all 75 files) is **currently uncommitted** in the working tree. Nothing has been committed or pushed this session.
- Last full verification gate (recorded 2026-08-21): `ruff check` clean, `ruff format --check` clean (403 files), `mypy src` clean (226 files), `pytest tests/unit` → **1680 passed, 3 skipped**, `pytest tests/integration --collect-only` → 148 tests collected.
