<!-- status: planned -->

# SOVA OSS — Last-Mile Launch Implementation Plan

> **Tracking update (2026-08-26):** this historical implementation plan is
> superseded for launch tracking by the
> [universal-security launch checklist](./universal-security-launch-checklist-2026-08-26.md).
> Its detailed design remains implementation history; its dates and completion
> language are not current launch claims.

**Author intent:** close the four gaps between the current build and the founder's
vision so SOVA OSS can be launched publicly. This document is written to be handed
to a builder AI. It is deliberately concrete: exact files, exact class/function
signatures, exact integration seams into existing code, and exact acceptance tests.

**Date:** 2026-08-21
**Controlling founder decisions captured for this plan:**

1. **Swarm** = *parallel isolated sessions + shared blackboard*. N agents, each with
   its own browser context and its own disposable workspace, run **concurrently**,
   share findings through a redacted, trace-recorded message bus, and a coordinator
   merges everything into one `.sova`. Always ask the operator how many agents.
2. **Computer use** = wire **MELRA for desktop computer-use only**. Browser stays on
   the already-validated Playwright MCP surface; terminal stays on SOVA's
   `RestrictedLocalExecutor`; files stay on `WorkspaceExecutor`.
3. **Guardrails** stay, but must not cap capability. Once the operator proves control
   of a target and grants authorization, the engine must be able to navigate, click,
   drag, type, scroll, change settings, submit forms, send messages/emails **on that
   authorized target**, and run adversarial (jailbreak / hallucination-induction)
   missions. Proof-of-control admission and human batch approval are preserved; a new
   explicit opt-in unlocks irreversible effects for owned targets.
4. **Arena** = a safe environment + recording chamber that supports: (a) our agent vs
   another agent, (b) an external agent vs a platform, recording **every action and
   intent from both sides** into `.sova`. Runs **contribute to the SOVA registry by
   default** (opt-out with `--no-contribute`), via an HTTP client to the self-hosted
   registry service, with a git-PR fallback.

---

## 0. Ground truth: what already exists (do not rebuild these)

The builder must read these before writing code. Each is a load-bearing seam this
plan attaches to.

| Concern | Existing symbol / file | Notes |
|---|---|---|
| Executor boundary | `Executor` Protocol, `Capability`, `ActionRequest`, `ActionOutcome`, `ExecutionContext`, `CancellationToken`, `SideEffect`, `OutcomeStatus`, `FailureCause` in `src/sova/executors/contract.py` | Every backend implements this. **Do not change the Protocol.** |
| Single-run engine | `ExecutorEngineRuntime`, `EngineSurfaceGeneration`, `run_executor_engine_document` in `src/sova/community/executor_engine.py` | Owns one fresh heterogeneous environment; turn-based. |
| Live web engine | `run_live_web_executor_engine` in `src/sova/community/live_executor_engine.py` | Already exposes `additional_surface_factory`, `additional_codec_factories`, `additional_surface_contract_digest`. **This is how computer/terminal surfaces attach with no core change.** |
| Surface builders | `browser_surface_generation`, `workspace_surface_generation`, `computer_surface_generation`, `computer_codec_factory`, `process_surface_generation`, `process_codec_factory`, `ExactProcessSurfaceSpec` in `src/sova/community/executor_surfaces.py` | `computer_surface_generation` and `computer_codec_factory` **already exist** — they just need a real backend + wiring. |
| Computer surface | `ManagedComputerSurface(executor, kind, identity_digest, snapshot, ...)` in `src/sova/runtime/computer_surface.py` | Accepts **any** `Executor` exposing `computer.snapshot`/`computer.inspect` + `computer.click` + `computer.type`. `_ADMITTED_ACTIONS` is the algebra to extend for scroll/drag/keyboard. |
| MELRA adapter | `MelraExecutorAdapter` (`src/sova/mcp/adapter.py:1205`, `execute` at 1480), `MelraTaskState` (117), `MCPExecutorAdapter` (373), `CuaDriverExecutorAdapter` (968) | **MELRA is already wrapped.** Receipt `MELRA_AUDIT_RECEIPT` in `src/sova/mcp/receipts.py` proves only *file* effects today; computer conformance is unproven and unwired. |
| Chamber (turn-based swarm today) | `run_executor_chamber`, `_run_phase` (sequential `for round: for participant:`), `ChamberObservation`, `ExecutorChamberGrant`, `ExecutorChamberArtifacts` in `src/sova/community/executor_chamber.py` | `maxActionsPerTurn: 1`. This is the per-environment loop the swarm workers reuse. |
| Authorization kernel | `AuthorizationKernel`, `AuthorityEnvelope`, `Scope`, `EffectClass` (OBSERVE/READ/MUTATE/EXTERNAL/DESTRUCTIVE), `EffectBudget`, `BudgetLedger` (thread-safe), `ActionIntent`, `ApprovalBatchChallenge`/`approve_batch`, `ControlProof`, `validate_control_proof` in `src/sova/safety/authorization.py` | `_approval_level`: MUTATE→NORMAL, EXTERNAL→EXTERNAL, offensive/DESTRUCTIVE→DESTRUCTIVE. **`intent.irreversible` is hard-blocked** (`"irreversible-effect-prohibited"`). Batch approval already lets one human review cover many intents. |
| Providers (the "agent") | `ProviderRoleModel`, `ProviderRoleRouter`, `ProviderAdapter` + `OpenAIAdapter`/`AnthropicAdapter`/`OpenRouterAdapter`/`OllamaAdapter`, `ModelRequest`, `ModelResult`, `UrllibTransport` in `src/sova/providers/core.py` and `runtime.py`; `RoleModel` protocol in `src/sova/runtime` | **Each swarm agent is one `ProviderRoleModel`.** "Same copy architecture, N times." Blocking urllib IO → threads give real parallelism. |
| Two-agent arena | `run_agent_arena`, `AgentArenaCase`, `AgentArenaMatch` (challenger/defender/judge), `_safe_transfer` (redacts inter-agent messages) in `src/sova/community/agent_arena.py`; multi-topology `chamber.py` | Records prompts/responses/inter-agent messages/oracle/judge into `.sova-trace` + `.sova`. |
| Registry | `preview_contribution`/`prepare_contribution` (local staging only, `uploadPerformed: False`) in `src/sova/registry/contribution.py`; `sync_registry` (local mirror copy) in `sync.py`; self-hostable service in `service.py`; `index.py`, `model.py`, `adapters.py` | **No upload client exists.** The "connection" to the registry is the real missing piece. |
| Trace + capsule | `TraceWriter` (`src/sova/trace/writer.py`), `Redactor` (`src/sova/trace`), event kinds (`src/sova/trace/kinds.py`), `build_capsule` (`src/sova/capsule`) | Signed, hash-chained, redacted event log + `.sova` capsule. Reuse verbatim. |

**Guiding constraints for every workstream (do not violate):**

- Never remove proof-of-control admission (`verified_browser_control`, `ControlProof`,
  `validate_control_proof`). Full capability is unlocked *by authorization*, not by
  bypassing it.
- Planner/agent models never receive executor objects, process handles, workspace
  paths, profile paths, secret providers, or raw credentials — only redacted
  observations and declarative grants. Preserve this in the swarm.
- Every action and every inter-agent message is recorded into a signed trace before
  it takes effect / crosses to another agent.
- No arbitrary-target autonomy: a run still requires an authorized target + human
  batch approval of the action scope. "Ask how many agents" is a UX prompt, not a
  removal of the authorization gate.

---

## Workstream A — Concurrent agent swarm with inter-agent communication

**Goal:** N identical SOVA agents test the *same authorized target* concurrently,
each in its own isolated environment, sharing intel through a recorded blackboard,
with a coordinator that seeds work and merges results into one `.sova`.

**Design principle:** a swarm is *the existing single-agent engine, run N times in
parallel, plus a communication + coordination layer*. Do **not** make the hardened
`_run_phase` chamber loop concurrent internally (that would race one shared session).
Instead each worker owns a fresh single-agent engine run (its own browser context +
workspace), exactly as `ExecutorEngineRuntime` already produces.

### A.1 New module: `src/sova/community/swarm/__init__.py` + files

Create a `swarm` subpackage:

```
src/sova/community/swarm/
  __init__.py
  blackboard.py        # shared, thread-safe, redacted, trace-recorded message bus
  message.py           # typed inter-agent message contract
  worker.py            # SwarmWorker: wraps one single-agent engine run
  coordinator.py       # SwarmCoordinator: seed, spawn, collect, merge
  runtime.py           # SwarmRuntime: thread pool, budget, lifecycle
  report.py            # aggregate swarm .sova + swarm-report.json assembly
```

### A.2 `message.py` — inter-agent communication protocol

Typed, minimal, JSON-canonical. This is the "seamless communication and data
transfer" contract.

```python
from dataclasses import dataclass
from enum import StrEnum

class SwarmMessageKind(StrEnum):
    OBSERVATION   = "observation"    # "I saw X on page Y"
    HYPOTHESIS    = "hypothesis"     # "endpoint Z may be injectable"
    FINDING       = "finding"        # "confirmed: role leakage via ..."
    TASK_CLAIM    = "task-claim"     # "I am taking subtarget /admin"
    TASK_RELEASE  = "task-release"
    HELP_REQUEST  = "help-request"   # "need a second agent on this flow"
    STATUS        = "status"         # heartbeat / progress

@dataclass(frozen=True, slots=True)
class SwarmMessage:
    id: str                 # "swarm-msg:" + sha of (author, seq, payload)
    author_agent_id: str
    seq: int                # per-author monotonic
    kind: SwarmMessageKind
    refs: tuple[str, ...]   # message ids / capsule ids / locator refs it responds to
    payload: dict           # already-redacted structured content (bounded size)
    posted_unix_ms: int     # passed in; DO NOT call time in a way that breaks replay determinism in tests
    def canonical_mapping(self) -> dict: ...
    @property
    def digest(self) -> str: ...   # sha256 of canonical_mapping
```

**Rules:** payload is bounded (reuse the 256 KiB projection ceiling pattern from
`computer_surface.py`). `refs` must reference existing message/capsule ids. Every
`SwarmMessage` is passed through `Redactor` (as in `agent_arena._safe_transfer`)
**before** it is admitted to the board — a message that produces redaction
disclosures is rejected, never silently scrubbed.

### A.3 `blackboard.py` — shared, thread-safe, hash-chained board

```python
class SwarmBlackboard:
    def __init__(self, *, redactor: Redactor, max_messages: int = 4096,
                 max_bytes: int = 32 * 1024 * 1024) -> None: ...
    def post(self, message: SwarmMessage) -> str:
        # 1. redact payload; reject on disclosure
        # 2. verify refs exist
        # 3. append under lock; extend a hash chain (prev_digest -> this digest)
        # 4. return chain position digest
    def read(self, *, since_seq_by_author: dict[str, int] | None = None,
             kinds: tuple[SwarmMessageKind, ...] | None = None) -> tuple[SwarmMessage, ...]:
        # snapshot read under lock; agents poll for new messages addressed to the swarm
    def transcript(self) -> tuple[SwarmMessage, ...]: ...   # for the coordinator trace
    def chain_head_digest(self) -> str: ...
```

Concurrency: one `threading.RLock`; append-only; a monotonic `seq`; a running
`prev -> curr` digest chain so the coordinator can prove the message order was not
rewritten. This mirrors the trace hash-chain idiom already used in `TraceWriter`.

**Recording both sides:** every `post()` writes a `sova.inter-agent.sent` event to
the posting agent's `TraceWriter`, and every `read()` that delivers a message writes
`sova.inter-agent.received` to the reading agent's trace (event kinds already used in
`agent_arena.py`). The board's full transcript is also written to the coordinator's
own `.sova-trace`.

### A.4 `worker.py` — one agent = one isolated single-agent engine run

```python
@dataclass(frozen=True, slots=True)
class SwarmWorkerSpec:
    agent_id: str                 # "agent-01" ...
    persona: str                  # short role/persona label, varies behavior + seed
    model: RoleModel              # a ProviderRoleModel (or ScriptedModel in tests)
    mission: SemanticBrowserMission
    chamber_document: dict        # a ONE-participant executor chamber doc for this worker

class SwarmWorker:
    def __init__(self, spec, *, blackboard, shared_budget: BudgetLedger,
                 target, package_runner, browser_executable, approval_context,
                 secret_resolver, provider_calls_authorized,
                 event_observer, cancellation) -> None: ...
    def run(self, destination: Path) -> ExecutorChamberArtifacts:
        # Builds ITS OWN engine run via run_live_web_executor_engine(...) into
        # destination/agents/<agent_id>/. Own browser context + own workspace are
        # produced automatically by ExecutorEngineRuntime (fresh per run).
        # Before/after each planner turn: worker reads new blackboard messages and
        # injects them (redacted) into its planner context; posts its own
        # observations/findings back to the board.
```

Key implementation detail: the worker reuses `run_live_web_executor_engine` **as-is**
for isolation and evidence, but wraps the participant's `RoleModel` in a
`BlackboardAwareRoleModel` decorator (A.5) so that inter-agent context flows in and
out at each model call without touching the engine core.

### A.5 `BlackboardAwareRoleModel` — the comms injection point (in `worker.py`)

```python
class BlackboardAwareRoleModel:      # implements the RoleModel protocol
    def __init__(self, inner: RoleModel, *, agent_id, blackboard, trace_writer): ...
    def respond(self, request: ModelRequest) -> ModelResult:
        incoming = self._blackboard.read(since_seq_by_author=self._cursor)
        # append a redacted, bounded "swarm intel" section to request context
        augmented = self._augment(request, incoming)      # record inter-agent.received
        result = self._inner.respond(augmented)
        outgoing = self._extract_messages(result)          # parse structured post intents
        for msg in outgoing:
            self._blackboard.post(msg)                     # record inter-agent.sent
        return result
```

This is why "each agent is nothing but the same copy": the only swarm-specific code
is this thin decorator plus the board. The rest is the existing per-agent engine.

### A.6 `runtime.py` — concurrency, isolation, aggregate budget

```python
def run_web_swarm(
    target: TargetManifest,
    base_mission: SemanticBrowserMission,
    *,
    agent_count: int,                       # asked from operator; validated 1..max
    personas: tuple[str, ...] | None,       # optional per-agent persona labels
    models: tuple[RoleModel, ...],          # one per agent (or one template cloned)
    destination: Path,
    package_runner: Path,
    browser_executable: Path,
    approval_batch: ApprovalBatchChallenge, # ONE human review covers the whole swarm
    approval_tokens: tuple[ApprovalToken, ...],
    control_proof: ControlProof,
    secret_resolver: Callable[[str], str | None],
    provider_calls_authorized: bool,
    swarm_budget: EffectBudget,             # aggregate ceiling across all agents
    max_concurrency: int = 8,
    offensive: bool = False,
    cancellation: CancellationToken | None = None,
    event_observer: Callable[[str, dict], None] | None = None,
) -> SwarmArtifacts: ...
```

Implementation:
- Validate `agent_count` (`1 <= n <= hard_cap`, default hard_cap 8; higher requires an
  explicit `--allow-large-swarm` operator flag surfaced by the CLI).
- Build one `SwarmBlackboard` and one shared `BudgetLedger(swarm_budget)`; **each
  worker also gets its own per-agent `EffectBudget`** so a single agent cannot exhaust
  the swarm. Both ledgers are thread-safe (`BudgetLedger` already locks).
- Spawn workers with `concurrent.futures.ThreadPoolExecutor(max_workers=min(agent_count, max_concurrency))`.
  Threads (not asyncio) because executors and provider calls are synchronous/blocking
  IO — threads yield real parallelism during network + browser waits.
- Each worker writes into `destination/agents/<agent_id>/`. A worker failure is
  isolated: it is recorded (`sova.swarm.agent-failed`) and does not abort peers;
  `cancellation` propagates to all workers.
- Wall-clock and aggregate cost enforced via the shared ledger + a swarm-level
  deadline derived from `swarm_budget.max_duration_ms`.

### A.7 `coordinator.py` — seed, collect, merge

```python
class SwarmCoordinator:
    def seed(self, base_mission, agent_count, personas) -> tuple[SwarmWorkerSpec, ...]:
        # Divide the objective: same target, differentiated by persona/sub-scope/seed.
        # Post initial TASK_CLAIM hints to the board so agents don't fully collide.
    def merge(self, agent_artifacts: tuple[ExecutorChamberArtifacts, ...],
              board: SwarmBlackboard) -> SwarmArtifacts:
        # 1. Collect each agent's findings/capsules.
        # 2. Dedup findings by (taxonomy, locator, effect) — reuse the finding
        #    identity rules already in evidence/ and forensics/.
        # 3. Emit a coordinator .sova-trace embedding the full board transcript
        #    (chain head digest included) + per-agent trace references.
        # 4. Build ONE aggregate swarm capsule `swarm.sova` via build_capsule.
```

### A.8 Output shape (`report.py` → `SwarmArtifacts`)

```
destination/
  agents/agent-01/...            # full per-agent engine artifacts (trace, capsule, report)
  agents/agent-02/...
  coordinator.sova-trace         # signed; embeds board transcript + chain head
  swarm.sova                     # aggregate capsule (merged, deduped findings)
  swarm-report.json              # { agentCount, personas, perAgentSummaries[],
                                 #   mergedFindings[], boardMessageCount,
                                 #   boardChainHead, budgetUsed, contribution{...} }
```

### A.9 CLI (`src/sova/cli.py`) — "always ask how many agents"

Add subcommand `sova engine swarm-web` (sibling to existing `sova engine run-web`):

- `--agents N` optional. **If omitted, prompt interactively**: `How many agents should
  join the swarm? [2-8]: `. Non-interactive (no TTY) with no `--agents` → error asking
  for the flag (never silently default in automation).
- `--personas a,b,c` optional; if fewer than N, cycle/auto-generate.
- `--allow-large-swarm` to exceed the default cap of 8.
- Reuse existing web target/mission/proof/approval flags from `run-web` /
  `arena swarm-web`. The single batch-approval prompt covers the whole swarm's action
  scope (A.6).
- Wire to `sova.community.swarm.runtime.run_web_swarm`.

### A.10 Tests (Workstream A)

- `tests/unit/test_swarm_blackboard.py`: concurrency (post/read under threads), hash
  chain integrity, redaction rejection, ref validation, size caps.
- `tests/unit/test_swarm_message.py`: canonical digest stability, bounded payload.
- `tests/unit/test_swarm_worker.py`: `BlackboardAwareRoleModel` injects received
  intel and posts sent intel; records `inter-agent.sent/received` events; uses
  `ScriptedModel` (no network).
- `tests/integration/test_web_swarm_scripted.py`: 3 scripted agents over a **loopback
  self-owned fixture** (reuse `live/fixture_web.py`), assert: isolated workspaces
  (distinct dirs, no cross-write), one merged `swarm.sova`, deduped findings,
  coordinator trace verifies offline, aggregate budget enforced, one-agent failure
  does not abort the swarm.
- `tests/integration/test_web_swarm_real_browser.py` (gated by `SOVA_RUN_REAL_BROWSER=1`):
  2 agents, installed Chrome, loopback fixture; assert both browser contexts are
  distinct and both traces verify.

**Acceptance criteria (A):** N concurrently-running agents, each with an isolated
browser context + workspace, exchange redacted messages recorded in both directions,
and produce one merged, offline-verifiable `swarm.sova`; operator is always asked for
the agent count; per-agent and aggregate budgets both hold; a worker crash is
contained.

---

## Workstream B — Computer use via MELRA (desktop click/type/scroll/drag) + wire terminal/file into the engine

**Goal:** make desktop computer-use actually work end-to-end through MELRA, and make
the engine able to combine browser + computer + terminal + file surfaces in one run so
agents "click around, try different buttons," including the native desktop.

**Why this is small:** `computer_surface_generation`, `computer_codec_factory`, and
`ManagedComputerSurface` already exist and already plug into the live engine via
`additional_surface_factory`. `MelraExecutorAdapter` already exists. The work is a
thin MELRA-backed computer `Executor` + lifecycle + wiring + conformance proof.

### B.1 New module: `src/sova/runtime/melra_computer.py`

Implement an `Executor` (the `contract.py` Protocol) that speaks to MELRA's computer
adapter through the existing `MelraExecutorAdapter` / `MCPExecutorAdapter`.

```python
class MelraComputerExecutor:            # implements Executor
    """Desktop computer-use backend over the MELRA MCP stdio server.

    Exposes exactly the reviewed computer algebra: computer.snapshot,
    computer.click, computer.type (+ optional computer.scroll, computer.drag,
    computer.key once B.6 extends the admitted algebra).
    """
    name = "sova-melra-computer"
    def __init__(self, adapter: MelraExecutorAdapter, *, window_binding: ...): ...
    def capabilities(self) -> tuple[Capability, ...]:
        # side_effect: snapshot=READ, click/type/scroll/drag/key=MUTATE
        # evidence: ("pre-action-screenshot-digest","post-action-screenshot-digest",
        #            "ui-tree-digest") — MELRA returns receipts; map into EvidenceReference
    def execute(self, request, context, cancellation) -> ActionOutcome:
        # 1. Translate ActionRequest.action -> MELRA computer op via melra_plan/melra_execute
        #    (or the harness-tool aliases browser_click-style; use the governed
        #     melra_plan -> melra_execute -> melra_receipt path for evidence).
        # 2. MELRA performs pointer/keyboard/screenshot on the bound window.
        # 3. Normalize MELRA receipt -> ActionOutcome(status, side_effect, output,
        #    evidence=(EvidenceReference(pre/post screenshot, ui tree)), verification=
        #    "melra-computer-post-action-observation").
```

The `CapabilityExecutionBroker._verify` in `mcp/broker.py` already special-cases
`"melra-result-defense-in-depth-only"`; add/keep a distinct verification label for
computer post-action observation so screenshots are treated as observation, not proof.

### B.2 Snapshot callback for `ManagedComputerSurface`

`ManagedComputerSurface` needs a `ComputerSnapshotCallback` returning a
`ComputerSurfaceSnapshot(projection, reviewed_targets)`. Implement in the same module:

```python
def melra_computer_snapshot(adapter, *, window_binding) -> ComputerSnapshotCallback:
    def snapshot() -> ComputerSurfaceSnapshot:
        # Call MELRA capability/observation to get a screenshot + accessibility/UI tree.
        # Convert UI elements into ReviewedComputerTarget(reference, actions, locator).
        # projection = redactable dict {screenshotDigest, uiSummary, ...}
    return snapshot
```

`reviewed_targets` are the only things a planner may select (the surface converts them
into immutable reviewed locators). This preserves "planner never gets raw handles."

### B.3 MELRA lifecycle manager: `src/sova/runtime/melra_process.py`

Mirror the existing `src/sova/mcp/cua_driver.py` pattern (real `subprocess.Popen`
lifecycle) for MELRA's stdio server:

```python
class MelraServerProcess:
    """Launch/monitor/teardown the MELRA MCP stdio server for one session."""
    def __init__(self, *, node_runner: Path, melra_home: Path, mode: str = "enforced",
                 telemetry_off: bool = True): ...
    def start(self) -> MelraExecutorAdapter: ...   # spawns `melra serve` (stdio), returns wired adapter
    def close(self) -> None: ...
```

Notes: MELRA is Node 22+/pnpm; SOVA shells out via the pinned launcher (like Playwright
MCP). Run MELRA in `MELRA_MODE=enforced`, telemetry forced off, `payload.key` confined
to the admitted workspace. Update the pin to the audited commit (see B.5).

### B.4 New surface factory: `src/sova/community/executor_surfaces.py` additions

Add a computer surface generation wired to the MELRA backend, following the exact
shape of `process_surface_generation`:

```python
@dataclass(frozen=True, slots=True)
class MelraComputerSurfaceSpec:
    identifier: str
    window_binding: ...              # exact HWND/app + identity_digest
    node_runner: Path
    melra_home: Path

def melra_computer_surface_generation(spec, server: MelraServerProcess) -> EngineSurfaceGeneration:
    adapter = server.start()
    executor = MelraComputerExecutor(adapter, window_binding=spec.window_binding)
    surface = ManagedComputerSurface(
        executor=executor, kind="window",
        identity_digest=spec.window_binding.identity_digest,
        snapshot=melra_computer_snapshot(adapter, window_binding=spec.window_binding),
        pid=spec.window_binding.pid, window_id=spec.window_binding.window_id,
        cleanup=server.close,
    )
    return computer_surface_generation(surface)          # EXISTING function, reused
```

Then combine with a codec via the **existing** `computer_codec_factory()`.

### B.5 Wire computer + terminal into a live run (no engine core change)

`run_live_web_executor_engine` already accepts `additional_surface_factory` +
`additional_codec_factories` + `additional_surface_contract_digest`. Add a helper that
assembles a browser+computer+terminal engine:

`src/sova/community/executor_engine_full.py`:
```python
def run_full_capability_engine(
    target, mission, chamber_document, destination, *,
    package_runner, browser_executable,          # browser (Playwright, existing)
    computer_spec: MelraComputerSurfaceSpec | None,   # MELRA computer (B.4)
    process_specs: tuple[ExactProcessSurfaceSpec, ...],  # terminal (existing)
    ...engine controls...
) -> ExecutorChamberArtifacts:
    def additional_factory(phase: str) -> tuple[EngineSurfaceGeneration, ...]:
        surfaces = []
        if computer_spec is not None:
            surfaces.append(melra_computer_surface_generation(computer_spec, MelraServerProcess(...)))
        for spec in process_specs:
            surfaces.append(process_surface_generation(spec))     # EXISTING terminal surface
        return tuple(surfaces)
    codecs = {"sova.action-codec.computer/0.1.0": computer_codec_factory(), ...process codecs...}
    digest = _surface_contract_digest(additional_factory("primary"))  # compute once, pass in
    return run_live_web_executor_engine(
        target, mission, chamber_document, destination,
        additional_surface_factory=additional_factory,
        additional_codec_factories=codecs,
        additional_surface_contract_digest=digest,
        ...,
    )
```

Terminal is thus wired using the **already-built** `ExactProcessSurfaceSpec` /
`process_surface_generation` / `RestrictedLocalExecutor` — no new terminal code.

### B.6 Extend the computer action algebra (scroll/drag/key)

To let agents really "click around and try different things," widen the reviewed
computer algebra:
- In `src/sova/runtime/computer_surface.py`, extend `_ADMITTED_ACTIONS` and
  `_READ_ACTION` handling to include `computer.scroll`, `computer.drag`,
  `computer.key`.
- In `src/sova/runtime/action_codecs.py`, extend `ComputerActionCodec` to decode those
  actions from reviewed targets (bounded params: scroll delta, drag path within window,
  key from an allowlist).
- Map each to a MELRA op in `MelraComputerExecutor` (B.1) with pre/post screenshot
  evidence.
- Add matching `EvidenceSatisfactionPolicy` entries in `computer_surface_generation`
  (it already generates one policy per capability — just ensure new capabilities carry
  evidence + `require_observation_change=True` for mutations).

### B.7 Receipt + conformance

- Update `MELRA_AUDIT_RECEIPT` in `src/sova/mcp/receipts.py` to the newly audited MELRA
  version/commit; **change `status` to reflect proven computer conformance only after
  B.8 passes**. Do not claim computer conformance in the receipt until the live test is
  green; until then keep the honest "file-effects-proven; computer under validation"
  wording.
- Add a computer conformance suite mirroring the existing executor conformance
  (`src/sova/conformance.py`): snapshot → click → type → scroll → drag on a
  **fixture-owned** window, with independent post-action UI-tree/screenshot delta.

### B.8 Tests (Workstream B)

- `tests/unit/test_melra_computer_executor.py`: capability inventory exactly matches
  the admitted algebra; `execute` maps actions↔MELRA ops; receipts→`ActionOutcome`
  with pre/post screenshot evidence; MELRA error → `OutcomeStatus.FAILED`/`UNSUPPORTED`
  with correct `FailureCause`. Use a fake MELRA transport (no real server).
- `tests/unit/test_melra_computer_surface.py`: `melra_computer_surface_generation`
  yields a valid `EngineSurfaceGeneration` (one evidence policy per capability, per the
  `EngineSurfaceGeneration.__post_init__` invariant).
- `tests/unit/test_computer_algebra_extension.py`: scroll/drag/key decode with bounded
  params; out-of-window drag rejected; non-allowlisted key rejected.
- `tests/integration/test_full_capability_engine_scripted.py`: browser+computer+terminal
  surfaces compose in one engine run against fixtures with a fake MELRA + real
  `RestrictedLocalExecutor`; per-surface evidence present; grants never leak paths.
- `tests/integration/test_melra_computer_live.py` (gated `SOVA_RUN_REAL_MELRA=1`):
  spawn real MELRA, drive a fixture-owned window, assert click/type/scroll change the
  UI tree and screenshots differ. Record honest skip when MELRA/Node unavailable.

**Acceptance criteria (B):** an authorized run can, in one engine session, drive a
real browser (Playwright), a real desktop window (MELRA: click/type/scroll/drag/key
with pre/post screenshot evidence), a terminal (RestrictedLocalExecutor), and files
(WorkspaceExecutor); planners still only see redacted observations and reviewed
locators; the MELRA receipt states computer conformance **only** after the live test
passes.

---

## Workstream C — Full capability within authorization (guardrails that gate, not cap)

**Goal:** once the operator proves control and authorizes a target, the engine can do
everything a real user/attacker could on *that* target — navigate, click, drag, type,
change settings, submit forms, send messages/emails, and run adversarial missions to
make the target's agents hallucinate/jailbreak — **without** loosening the
proof-of-control admission or the human-approval gate.

**Reframing (important):** the current design does **not** forbid these effects. It
requires (1) proof of control, (2) `authority.max_effect` high enough, (3) human
approval at the right level (MUTATE→NORMAL, EXTERNAL→EXTERNAL, offensive/DESTRUCTIVE→
DESTRUCTIVE), and it **hard-blocks only `irreversible`**. So "make it capable" =
provide an easy authorized path to grant high effect classes + expose the actions +
add a guarded irreversible opt-in. This is authorized security testing, gated by
ownership proof.

### C.1 Full-capability authorization profile: `src/sova/safety/profiles.py` (new)

```python
def full_capability_authority(
    *, target: str, subject: Principal, issued_by: Principal,
    proof: ControlProof, containment_digest: str,
    max_effect: EffectClass = EffectClass.EXTERNAL,   # EXTERNAL enables settings/email/messages
    budget: EffectBudget, ttl_minutes: int = 60,
    allow_offensive: bool = False,
) -> AuthorityEnvelope:
    """Build an AuthorityEnvelope pre-scoped to a proven-owned target with a high
    effect ceiling. Ownership must be 'self'/'explicit' with a matching ControlProof;
    never issue this without a validated proof for `target`."""
```

- `Scope` includes the target, the full action set the mission needs
  (`browser.*`, `computer.*`, `filesystem.*`, `process.exec`), and the target's domain
  in `domains` so EXTERNAL network effects to the *authorized* host are allowed while
  third-party domains remain out of scope (the `Scope.allows` domain check already does
  this).
- `max_effect=EXTERNAL` unlocks "send email / change setting / submit form" (these are
  MUTATE or EXTERNAL effects), each still requiring the matching approval level.
- `allow_offensive=True` sets the mission/intent `offensive=True` path, which forces
  DESTRUCTIVE-level batch approval.

### C.2 One batch approval for the whole campaign

Use the existing `ApprovalBatchChallenge` / `approve_batch`. The CLI presents the full
planned action scope (per mission action class) as one human review; `approve_batch`
issues per-intent tokens. This is how "full capability" stays human-gated without a
prompt per click: one informed approval covers the authorized campaign. No new kernel
code — just wire the CLI to build the batch from the mission's declared action classes.

### C.3 Guarded irreversible opt-in (the one real kernel change)

Today `AuthorizationKernel.decide` appends `"irreversible-effect-prohibited"` whenever
`intent.irreversible` is true. Add an **explicit, narrow** opt-in:

- Add `allow_irreversible: bool = False` to `AuthorityEnvelope` (default False →
  behavior unchanged).
- In `decide(...)`, replace the unconditional block with:
  ```python
  if intent.irreversible and not authority.allow_irreversible:
      reasons.append("irreversible-effect-prohibited")
  if intent.irreversible and authority.allow_irreversible:
      # require DESTRUCTIVE approval + ownership 'self'/'explicit' + valid proof
      # (offensive path already forces DESTRUCTIVE via _approval_level; make
      #  irreversible also force DESTRUCTIVE in _approval_level)
  ```
- In `_approval_level`, make `intent.irreversible` also return
  `ApprovalLevel.DESTRUCTIVE`.
- `full_capability_authority(..., allow_irreversible=True)` must require
  `ownership in {"self","explicit"}` and a non-legal proof, and must be surfaced in the
  CLI behind a distinct `--allow-irreversible` flag with its own destructive-review
  confirmation string. Legal-acquisition/offline targets can never set this.

This keeps the default safe (irreversible blocked) while giving owners of the target an
explicit, audited way to authorize irreversible tests (e.g. deleting a record in their
own staging system).

### C.4 Expose the actions (mostly already present)

"Send email / change settings" on a website = existing browser mission actions
(navigate, fill form field, click submit) — the semantic browser mission already
supports navigation, forms, pointer/keyboard, drag, modal, tabs (per the acceptance
matrix). Verify the browser codec (`BrowserActionCodec` in `action_codecs.py`) admits
the full form/submit/setting-toggle action set; extend if any are missing. Desktop
equivalents come from Workstream B's extended computer algebra.

### C.5 Adversarial mission library: `src/sova/live/adversarial_missions.py` (new)

The user wants agents that "try different ways to make the platform's agents
hallucinate and make mistakes." Provide a curated, versioned library of adversarial
`SemanticBrowserMission` / prompt-injection templates:

- Categories map to the existing attack taxonomy (Topic 03.3): prompt/instruction
  manipulation, tool/permission misuse, memory/retrieval poisoning, MCP
  tool-description rug-pull, cross-agent/delegated-action, multi-turn/persistent-state,
  conditional/dormant triggers.
- Each mission declares its objective, success oracle (deterministic where possible),
  and required evidence — reuse `search/` (trigger search) and `oracles.py`.
- These are **testing** payloads aimed at an *authorized* target's agent, recorded as
  `.sova` scenarios. Gate behind `offensive=True` + DESTRUCTIVE approval + proof.
- Wire into the swarm: different agents can run different adversarial missions
  concurrently and share which injections landed via the blackboard.

### C.6 Keep the admission gate explicit (no bypass)

Do not add any code path that executes against a target without a validated
`ControlProof` for that target. `full_capability_authority` and
`run_full_capability_engine` must both call the existing `verified_browser_control` /
`validate_control_proof` and refuse on failure. The capability increase is entirely
downstream of a passed ownership proof.

### C.7 Tests (Workstream C)

- `tests/unit/test_full_capability_authority.py`: profile builds only with a valid
  proof for the target; domains include the authorized host and exclude third parties;
  EXTERNAL effects to the authorized host allowed, to another host denied.
- `tests/unit/test_irreversible_optin.py`: default → irreversible denied; with
  `allow_irreversible=True` + DESTRUCTIVE approval + `ownership="self"` → allowed;
  with legal-offline ownership → still denied; NORMAL approval → denied.
- `tests/unit/test_adversarial_missions.py`: library loads, each mission has an oracle
  + required evidence + taxonomy mapping; offensive missions require DESTRUCTIVE
  approval.
- `tests/integration/test_authorized_full_capability_fixture.py`: against a loopback
  fixture the operator owns, run a mission that changes a setting + submits a form +
  (opt-in) performs an irreversible delete; assert each is recorded, evidence-verified,
  and blocked when the proof is withheld.

**Acceptance criteria (C):** with a valid ownership proof + one batch approval, an
authorized run performs the full user/attacker action set (including settings changes,
message/email submission, and adversarial jailbreak missions) on the authorized target;
irreversible effects require an explicit distinct opt-in + destructive review; nothing
runs without a passed proof; third-party domains stay out of scope.

---

## Workstream D — Arena modes + registry contribution (default-ON)

**Goal:** Arena is a safe environment + recording chamber that supports (a) our agent
vs another agent and (b) an external agent vs a platform, recording **every action and
intent from both sides** into `.sova`; and every run contributes to the SOVA registry
by default (opt-out), via a real client to the self-hosted registry service with a
git-PR fallback.

### D.1 Arena modes (extend existing arena, do not rewrite)

`agent_arena.py` already does challenger/defender/judge with full both-sides recording.
`chamber.py` already does agent/environment, agent/agent, and multi-agent topologies.
Add two thin **mode presets** + CLI entry points:

- **Mode: `agent-vs-agent`** (`sova arena versus`): our `ProviderRoleModel` (or a
  `GVisorOciAgentAdapter` external agent) vs another agent, in the sensed synthetic
  environment. This is `run_agent_arena` with both roles provider/OCI-backed and the
  advisory (non-overriding) judge. Record both sides (already done).
- **Mode: `agent-vs-platform`** (`sova arena platform`): an external agent (admitted
  via the existing gVisor `runsc` OCI adapter, no direct browser authority) is set
  loose against an **authorized** web/computer platform using the Workstream B/C engine
  surfaces, while the chamber records every observation, action, intent, and effect from
  the agent side and every environment response from the platform side into one
  `.sova-trace` + `.sova`.

Both modes reuse the existing recording (`TraceWriter`, `_safe_transfer` redaction,
`build_capsule`) — the "records everything from both sides in `.sova`" requirement is
already met by the chamber; D.1 is mostly presets + CLI + docs.

### D.2 "Everything from both sides" — verify completeness

Audit the event set written per arena turn and ensure both the agent side (prompt,
model response, intent, tool/action request, inter-agent message) and the environment/
platform side (observation, effect, oracle result, judge assessment) are captured.
Add any missing event kinds to `trace/kinds.py`. Add a test asserting a full round-trip
of a two-sided match reconstructs both sides from the trace alone.

### D.3 Registry upload client: `src/sova/registry/client.py` (new)

The missing "connection." Build an HTTP client to the self-hostable registry service
(`registry/service.py`), reusing the provider `UrllibTransport` pattern (stdlib
`urllib`, no new deps):

```python
class RegistryClient:
    def __init__(self, *, base_url: str, token: str, transport=UrllibTransport()): ...
    def health(self) -> dict: ...                       # GET /health (key-digest contract)
    def stage_upload(self, staged_dir: Path) -> str:    # POST staged .sova (token-gated)
    def verification_status(self, upload_id: str) -> dict:  # poll async verify queue
    def promote(self, upload_id: str) -> dict:          # content-addressed promote (server-driven)
```

Match the service's existing staged-upload + async-verification + content-address
promotion contract (read `registry/service.py` for exact routes, token header, and the
signed service index / SSE). The client must:
- Only upload artifacts that passed `preview_contribution` gates (redaction, secret
  scan, schema-valid `.sova`).
- Never send secrets/tokens inside artifacts (the existing `_SECRET`/magic screens in
  `contribution.py` already enforce this — call them before upload).
- Verify the server's signed index / key digest before trusting it (client trust +
  sequence checks already specified in the acceptance matrix).

### D.4 Git-PR fallback: `src/sova/registry/pr_contribution.py` (new)

When no registry service is configured, prepare a contribution branch/PR to a public
registry git repo (using `gh`/git, mirroring the existing local staging output of
`prepare_contribution`). Output is a ready-to-push branch + PR body; the human merge is
the publish step. No live server required.

### D.5 Auto-contribution wiring (default-ON, opt-out)

Add a post-run contribution step invoked by engine/arena/swarm runs:

`src/sova/registry/auto_contribute.py`:
```python
def auto_contribute_after_run(
    artifacts_dir: Path, *,
    contributor: Mapping[str, Any], license_expr: str,
    registry: RegistryClient | None,        # None -> git-PR fallback
    enabled: bool = True,                    # DEFAULT ON
    consent_corpus_reuse: bool = True,       # separateCorpusReuseConsent default ON per founder
) -> dict:
    if not enabled:
        return {"contributed": False, "reason": "operator-opted-out"}
    spec = _build_contribution_spec(artifacts_dir, contributor, license_expr,
                                    gates={... all True incl separateCorpusReuseConsent ...})
    preview = preview_contribution(spec)         # existing gates: redaction/secret/schema
    if not preview["acceptedForLocalStaging"]:
        return {"contributed": False, "reason": "gates-failed", "preview": preview}
    staged = prepare_contribution(spec, artifacts_dir / "contribution", confirmed=True)
    if registry is not None:
        return {"contributed": True, "transport": "service",
                "upload": registry.stage_upload(artifacts_dir / "contribution")}
    return {"contributed": True, "transport": "git-pr",
            "pr": prepare_pr(artifacts_dir / "contribution")}
```

- **Default ON:** every `engine`, `arena`, and `swarm` run calls this unless
  `--no-contribute` is passed. The `contribution` block appears in each run's report.
- **Opt-out:** `--no-contribute` on any run command sets `enabled=False`.
- **Consent + privacy honesty:** the founder chose default-ON, but the existing gates
  (redaction, secret scan, schema validation, human-review flag) still run, and the run
  output must clearly state what was uploaded and where, plus how to opt out. Keep
  `humanModerationRequired`/`confirmationRequired` honesty on the server side.
- First-run notice: on the first contribution of a machine, print a one-time clear
  notice that contribution is ON by default and how to disable it (respect the
  local-first, no-silent-telemetry principle by making the upload visible and
  documented — this is disclosed contribution, not silent telemetry).

### D.6 CLI (`src/sova/cli.py`)

- `sova arena versus ...` (agent-vs-agent) and `sova arena platform ...`
  (agent-vs-platform), both wired to the arena modes in D.1.
- Global `--no-contribute` on `engine`, `arena`, `swarm` commands; `--registry-url` +
  `--registry-token` (or a config/env) to select the service; absent → git-PR fallback.
- `sova registry submit <staged-dir>` and `sova registry status <upload-id>` thin
  wrappers over `RegistryClient` for manual submission.

### D.7 Tests (Workstream D)

- `tests/unit/test_registry_client.py`: staged upload / status / promote against a
  `FakeTransport` (reuse the providers' `FakeTransport`); refuses artifacts failing the
  secret/redaction/schema gates; verifies server index/key digest before trusting.
- `tests/unit/test_auto_contribute.py`: default ON stages + "uploads" via fake client;
  `--no-contribute` short-circuits; gate failure blocks upload; report block accurate.
- `tests/unit/test_pr_contribution.py`: git-PR fallback prepares a branch + PR body
  from staged output; no network.
- `tests/integration/test_arena_versus_records_both_sides.py`: agent-vs-agent match
  reconstructs both sides from the trace alone; judge is advisory/non-overriding.
- `tests/integration/test_arena_platform_records_both_sides.py`: external OCI agent vs
  loopback platform fixture; every agent-side intent/action and platform-side
  effect/observation is in the `.sova`; contribution staged by default.

**Acceptance criteria (D):** both arena modes run and record every action + intent from
both sides into a verifiable `.sova`; runs contribute to the registry by default via a
working service client (git-PR fallback when no service); `--no-contribute` cleanly
opts out; all existing redaction/secret/schema gates still fire before any upload; the
upload is visible and documented (disclosed contribution, never silent).

---

## Cross-cutting concerns

### CC.1 Sequencing / dependency order for the builder

1. **Workstream B** (computer/terminal wiring) — unblocks real desktop capability and is
   the lowest-risk (reuses existing surfaces). Do B.1–B.6 first; B.8 tests gate it.
2. **Workstream C** (authorization profile + irreversible opt-in + adversarial missions)
   — small kernel change + profile; depends on nothing but should land before the swarm
   so swarm agents inherit full-capability authorities.
3. **Workstream A** (swarm) — depends on B + C so each worker can drive the full surface
   set under a full-capability authority. Largest new-code surface.
4. **Workstream D** (arena modes + registry) — arena modes depend on A/B/C for the
   platform mode; the registry client is independent and can be built in parallel any
   time.

### CC.2 Determinism / replay rules (repo convention)

- Do not call wall-clock/`random` in ways that break replay. Timestamps for messages
  and traces come from the existing trace clock injection; pass `now`/`unix_ms` in as
  the codebase already does. Vary swarm agent personas by index, not by RNG.
- All new artifacts must round-trip through the existing canonical JSON + hash + sign
  path and verify offline (reuse `formats/canonical.py`, `trace/integrity.py`).

### CC.3 Public/private boundary + safety (must pass CI)

- Run `scripts/check-public-boundary.ps1` — no confidential Atlas/MELRA-private/TRUSCOR
  material, no secrets, no raw traces except synthetic provenance-recorded goldens.
- Adversarial mission payloads (C.5) are offensive functionality → they must be
  self/authorized-target-only, DESTRUCTIVE-approval-gated, and fail closed on
  third-party targets (SAFETY GATE discipline from the parts index).
- Keep every new "not a security sandbox" honesty string where the existing code keeps
  them (browser/computer/terminal are not isolation boundaries).

### CC.4 Documentation + status markers

- Every new doc uses the `<!-- status: ... -->` marker (planned/implemented/experiment).
- Update `README.md` project-status table rows for: swarm (now concurrent + blackboard),
  computer-use (MELRA computer live), arena modes, and registry contribution (default
  ON). Do not upgrade a status string to "validated" until its live test is green.
- Update `docs/engineering/founder-vision-acceptance-matrix-2026-08-09.md` rows
  "Multi-agent swarms", "Broad computer-use execution", "Arbitrary desktop-software UI
  testing", and "Live registry and leaderboard" only when their exit criteria pass.

### CC.5 Full acceptance test matrix (green before launch)

| # | Test | Proves |
|---|---|---|
| 1 | `test_web_swarm_scripted` | concurrent isolated agents + blackboard + merged `.sova` |
| 2 | `test_web_swarm_real_browser` (gated) | real concurrent browser contexts |
| 3 | `test_full_capability_engine_scripted` | browser+computer+terminal+file compose |
| 4 | `test_melra_computer_live` (gated) | real desktop click/type/scroll/drag |
| 5 | `test_full_capability_authority` + `test_irreversible_optin` | capability gated, not capped |
| 6 | `test_authorized_full_capability_fixture` | settings/submit/irreversible on owned target |
| 7 | `test_arena_versus_records_both_sides` | agent-vs-agent both sides in `.sova` |
| 8 | `test_arena_platform_records_both_sides` | agent-vs-platform both sides in `.sova` |
| 9 | `test_registry_client` + `test_auto_contribute` | default-ON contribution + opt-out |
| 10 | full existing suite + boundary/secret/typing/lint | no regressions, launch-clean |

### CC.6 Explicit non-goals for this plan (do not build)

- No arbitrary-target autonomy (still requires proof-of-control + approval).
- No CAPTCHA bypass, automated account creation, or credential harvesting (login stays
  the manual `session browser-handoff` handoff; the swarm reuses an already-authorized
  persistent session).
- No hosted SOVA service, metering, or silent telemetry. Registry contribution is
  disclosed, gated, and opt-out — not telemetry.
- No claim of a VM/security sandbox for host execution; keep the honesty strings.

---

## Appendix — exact seams cheat-sheet (for the builder)

- **Add a surface to a live run** → pass `additional_surface_factory` +
  `additional_codec_factories` + `additional_surface_contract_digest` to
  `run_live_web_executor_engine`. No engine-core edit.
- **New backend** → implement `Executor` Protocol (`contract.py`): `name`,
  `capabilities()`, `execute(request, context, cancellation)`. Return `ActionOutcome`
  with `evidence`, honest `verification`, correct `side_effect`/`failure_cause`.
- **Computer backend** → wrap it in `ManagedComputerSurface(executor, kind,
  identity_digest, snapshot)` then `computer_surface_generation(surface)` +
  `computer_codec_factory()`.
- **Terminal backend** → `ExactProcessSurfaceSpec(...)` →
  `process_surface_generation(spec)` + `process_codec_factory(spec)` (already built on
  `RestrictedLocalExecutor`).
- **Each swarm agent** → a `ProviderRoleModel` (or `ScriptedModel` in tests) wrapped by
  `BlackboardAwareRoleModel`; run inside its own `run_live_web_executor_engine` call.
- **Authorization for full capability** → `full_capability_authority(...)` →
  `ApprovalBatchChallenge`/`approve_batch` for one human review over the campaign →
  `AuthorizationKernel.decide` per action (unchanged except the guarded irreversible
  opt-in).
- **Record inter-agent comms** → `sova.inter-agent.sent` / `sova.inter-agent.received`
  (kinds already used in `agent_arena.py`); board transcript into the coordinator trace.
- **Contribute** → `preview_contribution` → `prepare_contribution` →
  `RegistryClient.submit_capsule_and_trace` (service) or `prepare_pr` (git). Default
  ON, `--no-contribute` off.

---

# Appendix A2 — `RegistryClient` mapped to the real registry service

This is the concrete implementation of Workstream D.3, resolved against the actual
routes and contracts in `src/sova/registry/service.py`. **The client builds nothing
by hand — it reuses the existing submission builders.**

## A2.1 The real HTTP contract (read from `service.py`)

The reference service is a stdlib `http.server` handler. Routes:

| Method | Route | Auth | Request | Response |
|---|---|---|---|---|
| `GET` | `/v1/health` | none | — | `{artifactType: "sova.community-service-health", schemaVersion: "0.1.0", status: "ready", limits: {...}, ...}` |
| `GET` | `/v1/index` | none | — | signed index (`store.signed_index()`) |
| `GET` | `/v1/leaderboard` | none | — | standard-profile leaderboard rows |
| `GET` | `/v1/submissions/<id>` | none | — | `{artifactType: "sova.community-submission-status", id, status, ...}` |
| `GET` | `/v1/objects/sha256/<digest>` | none | — | `application/octet-stream` object bytes |
| `GET` | `/v1/events?after=<id>` | none | `Last-Event-ID` header | `text/event-stream` (SSE) |
| `POST` | `/v1/submissions` | **`Authorization: Bearer <token>`** | JSON submission document (Content-Length required) | `202 ACCEPTED` + status doc |

Hard facts the client must honor:
- **Auth:** `POST` requires `Authorization: Bearer <token>` compared with
  `hmac.compare_digest`. Token is created by `create_community_service_token(path)`
  (min 24 chars). No token → `401 SOVA-SERVICE-AUTH`.
- **Server is loopback-only** (`CommunityServiceConfig` rejects non-loopback hosts).
  So the client targets either a locally/operator-run instance on `127.0.0.1:<port>`
  **or** the operator's own TLS front-end (the Caddy/container blueprint) that proxies
  to the loopback service. Client accepts an arbitrary `base_url`; the *server* is what
  enforces loopback binding.
- **Body shape** (`_SUBMISSION_TYPE = "sova.community-submission"`, `schemaVersion
  "0.1.0"`): exactly `{artifactType, schemaVersion, kind, metadata, files}`, where
  `files` is exactly **2** entries (`max_files == 2`, `_REQUIRED_UPLOAD_FILES`) each
  `{name, digest, size, data(base64)}`. Server also requires the submission to contain
  **exactly one `.sova` capsule and one `.sova-trace`** and the trace signer to be
  **pinned** in the server's `trusted_key_ids` (`SOVA-SERVICE-TRUST` otherwise).
- **Size:** `max_body_bytes = 48 MiB`, `max_file_bytes = 16 MiB` (defaults, advertised
  in `/v1/health` `limits`). Client reads `health().limits` and passes matching
  `CommunityServiceLimits` to the builder so the body cannot be rejected for size.
- **Status lifecycle:** `queued → verifying → accepted` (and `verifying → queued` on
  server restart recovery). Verification never executes submitted content.

## A2.2 `src/sova/registry/client.py` (new — concrete)

```python
# SPDX-License-Identifier: Apache-2.0
"""HTTP client for the loopback/operator-fronted SOVA community registry service."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin
from urllib.request import Request, urlopen  # noqa: S310 - operator-supplied base_url

from sova.formats import strict_json_loads
from sova.formats.errors import FormatError
from sova.registry.service import (
    CommunityServiceLimits,
    prepare_community_submission,      # (*, kind, metadata, capsule, trace, limits) -> dict
    serialize_community_submission,    # (document, *, limits) -> bytes
    # NOTE: reuse the existing health-verification helper in service.py
    #       (the function that validates the "sova.community-service-health" doc,
    #        lines ~100-173). Confirm its exported name and import it here rather
    #        than re-validating by hand.
)

_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_TERMINAL_STATES = frozenset({"accepted", "rejected"})


@dataclass(frozen=True, slots=True)
class RegistryEndpoint:
    base_url: str          # "http://127.0.0.1:8787" or "https://registry.example.org"
    token: str             # operator bearer token (create_community_service_token)

    def __post_init__(self) -> None:
        if not self.base_url.startswith(("http://127.", "http://localhost", "https://")):
            raise FormatError(
                "SOVA-REGISTRY-CLIENT-URL",
                "registry base url must be loopback http or https",
            )
        if len(self.token) < 24:
            raise FormatError("SOVA-REGISTRY-CLIENT-TOKEN", "operator token too short")


class RegistryClient:
    def __init__(self, endpoint: RegistryEndpoint, *, timeout_s: float = 30.0) -> None:
        self._endpoint = endpoint
        self._timeout_s = timeout_s

    # ---- internal helpers -------------------------------------------------
    def _url(self, route: str) -> str:
        return urljoin(self._endpoint.base_url.rstrip("/") + "/", route.lstrip("/"))

    def _read_json(self, request: Request) -> dict[str, Any]:
        with urlopen(request, timeout=self._timeout_s) as response:  # noqa: S310
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise FormatError("SOVA-REGISTRY-CLIENT-SIZE", "registry response too large")
        parsed = strict_json_loads(raw, max_bytes=_MAX_RESPONSE_BYTES)
        if not isinstance(parsed, dict):
            raise FormatError("SOVA-REGISTRY-CLIENT-BODY", "registry response is not an object")
        return parsed

    def _get(self, route: str) -> dict[str, Any]:
        return self._read_json(Request(self._url(route), method="GET"))

    def _post(self, route: str, body: bytes) -> dict[str, Any]:
        request = Request(
            self._url(route),
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self._endpoint.token}",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
        )
        return self._read_json(request)

    # ---- public surface ---------------------------------------------------
    def health(self) -> dict[str, Any]:
        doc = self._get("/v1/health")
        # reuse service.py's health verifier here to reject anything but the exact
        # ready contract before trusting advertised limits / methodology snapshot.
        _verify_health(doc)                       # imported from service.py
        return doc

    def limits_from_health(self) -> CommunityServiceLimits:
        doc = self.health()
        raw = doc.get("limits", {})
        return CommunityServiceLimits(
            max_body_bytes=int(raw["maxRequestBodyBytes"]),
            max_file_bytes=int(raw["maxRawFileBytes"]),
            max_files=int(raw["maxFiles"]),
        )

    def submit_capsule_and_trace(
        self, *, kind: str, metadata: Mapping[str, Any], capsule: Path, trace: Path,
        limits: CommunityServiceLimits | None = None,
    ) -> dict[str, Any]:
        """Build the exact 2-file submission and POST it. Returns the 202 status doc."""
        selected = limits or self.limits_from_health()
        document = prepare_community_submission(
            kind=kind, metadata=dict(metadata), capsule=capsule, trace=trace, limits=selected,
        )
        body = serialize_community_submission(document, limits=selected)
        return self._post("/v1/submissions", body)   # {..., "id": "sova-sub-...", "status": "queued"}

    def submission_status(self, submission_id: str) -> dict[str, Any]:
        return self._get(f"/v1/submissions/{submission_id}")

    def wait_until_terminal(
        self, submission_id: str, *, poll_s: float, deadline_s: float,
        sleep=None,
    ) -> dict[str, Any]:
        """Poll status until accepted/rejected or the deadline. `sleep` injected for tests."""
        # loop: status -> if status in _TERMINAL_STATES return; else sleep(poll_s) until deadline
        ...
```

**Integration:** replace the `stage_upload` sketch in Workstream D's
`auto_contribute_after_run` with `RegistryClient.submit_capsule_and_trace(kind=...,
metadata=..., capsule=<the run's .sova>, trace=<the run's .sova-trace>)`. The run's
capsule + trace are exactly the two files the server requires; no extra staging archive
is uploaded over HTTP (the local `prepare_contribution` staging remains for the git-PR
path and for the human-visible audit trail).

## A2.3 Client tests — `tests/unit/test_registry_client.py`

Use the providers' `FakeTransport` idiom, or a stdlib `http.server` bound to
`127.0.0.1:0` running a real `CommunityRegistryStore` in a thread (preferred — it
exercises the true contract):

- `test_health_rejects_non_ready_doc` — a doc missing `status: "ready"` raises.
- `test_submit_round_trips_against_real_loopback_service` — start the real service with
  a pinned signer + token, submit a signed fixture capsule+trace, assert `202` + a
  `sova-sub-` id + `status == "queued"`, then poll to a terminal state.
- `test_submit_requires_bearer_token` — wrong/absent token → `401 SOVA-SERVICE-AUTH`.
- `test_submit_rejects_unpinned_signer` — trace signed by an unpinned key →
  `SOVA-SERVICE-TRUST`.
- `test_submit_rejects_oversize` — file over `max_file_bytes` → `SOVA-SERVICE-LIMIT`
  before any network call (builder raises).
- `test_wait_until_terminal_honours_deadline` — injected `sleep`, deadline reached →
  returns last non-terminal status without hanging.

**Acceptance (A2):** the client submits a run's `.sova` + `.sova-trace` to the real
service contract, authenticates with the operator bearer token, honors advertised
limits, verifies health before trust, and polls to a terminal state — all with no new
third-party dependency (stdlib `urllib` only).

---

# Appendix B2 — `swarm/` package skeleton + failing tests

Concrete stubs for Workstream A. Every function raises `NotImplementedError` so the
suite is red until implemented (TDD). Types/signatures are final; bodies are the build
target.

## B2.1 `src/sova/community/swarm/message.py`

```python
# SPDX-License-Identifier: Apache-2.0
"""Typed inter-agent swarm message contract (redacted before it reaches the board)."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

_MAX_PAYLOAD_BYTES = 256 * 1024


class SwarmMessageKind(StrEnum):
    OBSERVATION = "observation"
    HYPOTHESIS = "hypothesis"
    FINDING = "finding"
    TASK_CLAIM = "task-claim"
    TASK_RELEASE = "task-release"
    HELP_REQUEST = "help-request"
    STATUS = "status"


@dataclass(frozen=True, slots=True)
class SwarmMessage:
    author_agent_id: str
    seq: int
    kind: SwarmMessageKind
    refs: tuple[str, ...]
    payload: dict[str, Any]
    posted_unix_ms: int          # injected (deterministic in tests), never called internally

    def __post_init__(self) -> None:
        raise NotImplementedError  # validate ids, seq>=0, bounded payload, canonical refs

    @property
    def id(self) -> str:
        raise NotImplementedError  # "swarm-msg:" + digest

    @property
    def digest(self) -> str:
        raise NotImplementedError

    def canonical_mapping(self) -> dict[str, Any]:
        raise NotImplementedError
```

## B2.2 `src/sova/community/swarm/blackboard.py`

```python
# SPDX-License-Identifier: Apache-2.0
"""Thread-safe, redacted, hash-chained shared blackboard for the agent swarm."""
from __future__ import annotations
import threading
from sova.community.swarm.message import SwarmMessage, SwarmMessageKind
from sova.trace import Redactor


class SwarmBlackboard:
    def __init__(self, *, redactor: Redactor, max_messages: int = 4096,
                 max_bytes: int = 32 * 1024 * 1024) -> None:
        self._lock = threading.RLock()
        self._messages: list[SwarmMessage] = []
        self._chain_head = "sha256:" + "0" * 64
        raise NotImplementedError

    def post(self, message: SwarmMessage) -> str:
        # redact payload -> reject on disclosure; verify refs exist; append under lock;
        # extend chain (prev -> curr); enforce caps; return new chain head digest.
        raise NotImplementedError

    def read(self, *, since_seq_by_author: dict[str, int] | None = None,
             kinds: tuple[SwarmMessageKind, ...] | None = None) -> tuple[SwarmMessage, ...]:
        raise NotImplementedError

    def transcript(self) -> tuple[SwarmMessage, ...]:
        raise NotImplementedError

    def chain_head_digest(self) -> str:
        raise NotImplementedError
```

## B2.3 `src/sova/community/swarm/worker.py`

```python
# SPDX-License-Identifier: Apache-2.0
"""One swarm agent = one isolated single-agent engine run + comms decorator."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from sova.community.swarm.blackboard import SwarmBlackboard
from sova.live.semantic_workflow import SemanticBrowserMission
from sova.runtime import RoleModel          # protocol
from sova.providers import ModelRequest, ModelResult


@dataclass(frozen=True, slots=True)
class SwarmWorkerSpec:
    agent_id: str
    persona: str
    model: RoleModel
    mission: SemanticBrowserMission
    chamber_document: dict


class BlackboardAwareRoleModel:              # implements RoleModel
    def __init__(self, inner: RoleModel, *, agent_id: str,
                 blackboard: SwarmBlackboard, trace_writer) -> None:
        raise NotImplementedError

    def respond(self, request: ModelRequest) -> ModelResult:
        # read new board msgs -> augment request (record inter-agent.received) ->
        # inner.respond -> extract posts -> blackboard.post (record inter-agent.sent)
        raise NotImplementedError


class SwarmWorker:
    def __init__(self, spec: SwarmWorkerSpec, *, blackboard, shared_budget, target,
                 package_runner: Path, browser_executable: Path, approval_context,
                 secret_resolver, provider_calls_authorized, event_observer,
                 cancellation) -> None:
        raise NotImplementedError

    def run(self, destination: Path):        # -> ExecutorChamberArtifacts
        # wraps spec.model in BlackboardAwareRoleModel, calls
        # run_live_web_executor_engine into destination/agents/<agent_id>/
        raise NotImplementedError
```

## B2.4 `src/sova/community/swarm/runtime.py`

```python
# SPDX-License-Identifier: Apache-2.0
"""Concurrent swarm runtime: thread pool, isolation, aggregate + per-agent budgets."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path

_HARD_AGENT_CAP = 8


@dataclass(frozen=True, slots=True)
class SwarmArtifacts:
    destination: Path
    agent_count: int
    swarm_capsule: Path          # swarm.sova
    coordinator_trace: Path      # coordinator.sova-trace
    report: Path                 # swarm-report.json
    contribution: dict


def run_web_swarm(target, base_mission, *, agent_count, personas, models, destination,
                  package_runner, browser_executable, approval_batch, approval_tokens,
                  control_proof, secret_resolver, provider_calls_authorized, swarm_budget,
                  max_concurrency=_HARD_AGENT_CAP, offensive=False, cancellation=None,
                  event_observer=None) -> SwarmArtifacts:
    # validate agent_count (1.._HARD_AGENT_CAP unless allow_large upstream);
    # build one SwarmBlackboard + one shared BudgetLedger(swarm_budget);
    # ThreadPoolExecutor(min(agent_count, max_concurrency)); isolate failures;
    # coordinator.seed -> spawn workers -> coordinator.merge -> SwarmArtifacts.
    raise NotImplementedError
```

## B2.5 `src/sova/community/swarm/coordinator.py`

```python
# SPDX-License-Identifier: Apache-2.0
"""Swarm coordinator: seed differentiated work, collect, dedup, merge into one .sova."""
from __future__ import annotations


class SwarmCoordinator:
    def seed(self, base_mission, agent_count, personas):   # -> tuple[SwarmWorkerSpec, ...]
        raise NotImplementedError

    def merge(self, agent_artifacts, board):               # -> SwarmArtifacts
        # dedup findings by (taxonomy, locator, effect); build coordinator trace
        # embedding board.transcript() + chain head; build_capsule -> swarm.sova
        raise NotImplementedError
```

## B2.6 Failing tests (author these red first)

`tests/unit/test_swarm_message.py`
```python
def test_message_id_is_stable_digest(): ...        # canonical_mapping -> deterministic id
def test_payload_over_limit_rejected(): ...
def test_negative_seq_rejected(): ...
```

`tests/unit/test_swarm_blackboard.py`
```python
def test_post_then_read_returns_message(): ...
def test_concurrent_posts_preserve_chain_and_count(): ...   # N threads, assert len + monotone chain
def test_redaction_disclosure_rejects_post(): ...           # credential-shaped payload -> raises
def test_unknown_ref_rejected(): ...
def test_message_cap_enforced(): ...
```

`tests/unit/test_swarm_worker.py`
```python
def test_blackboard_aware_model_injects_received_and_posts_sent(): ...  # ScriptedModel inner
def test_worker_records_inter_agent_events(): ...           # trace has sent/received kinds
```

`tests/integration/test_web_swarm_scripted.py`
```python
def test_three_scripted_agents_isolated_and_merged(tmp_path): ...
    # assert: agents/agent-0{1,2,3} dirs exist with distinct workspaces (no cross-write),
    #         one swarm.sova, deduped findings, coordinator.sova-trace verifies offline,
    #         aggregate budget enforced, one injected worker crash does not abort peers,
    #         operator agent-count prompt path is exercised via explicit agent_count arg.
```

`tests/integration/test_web_swarm_real_browser.py` (gated `SOVA_RUN_REAL_BROWSER=1`)
```python
def test_two_agents_have_distinct_browser_contexts(tmp_path): ...
```

**Acceptance (B2):** the `swarm/` package imports cleanly, all stubs raise
`NotImplementedError`, and the test files above exist and FAIL for the right reason
(not-implemented), giving the builder a precise red-to-green target that, when green,
satisfies Workstream A's acceptance criteria.
