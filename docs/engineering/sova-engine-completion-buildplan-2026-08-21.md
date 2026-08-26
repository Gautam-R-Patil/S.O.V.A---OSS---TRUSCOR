<!-- status: planned -->

# SOVA Engine — Completion Build Plan (spoon-feeding handoff)

> **Tracking update (2026-08-26):** this historical engine buildplan is
> superseded for launch tracking by the
> [universal-security launch checklist](./universal-security-launch-checklist-2026-08-26.md).
> Preserve it as implementation history; do not treat its dates or final checklist
> as the current universal-security launch gate.

**Date:** 2026-08-21
**Purpose:** Finish the SOVA testing engine to the founder's vision. This document
resolves every hard/architectural question **now** (authored on Opus) so the
remaining work is mechanical and can be executed step-by-step (on Sonnet)
without further design decisions.

**How to use this doc:** Do the tasks **in order** (6 → 7 → 8 → 9 → 10). Each task
is self-contained: exact files, exact signatures, exact invariants, exact tests,
and the exact lint/typecheck/test gate to pass before moving on. Do not skip the
gate. Do not redesign — the design is settled below; if reality contradicts a
stated fact, stop and flag it rather than improvising.

Companion doc (background/rationale): `last-mile-launch-implementation-plan-2026-08-21.md`.

---

## 0. Status against the founder's vision

The vision: *swarms of agents that test any UI/URL/software for vulnerabilities
using browser automation, computer use, terminal use, file manipulation, stress
testing, and login — all under proven authorization — plus an Arena that records
every action/intent to `.sova` and contributes to the SOVA registry (default-on).*

| Capability | State | Remaining |
|---|---|---|
| Browser automation (Playwright surface) | **Done** | — |
| Terminal use (host process + gVisor OCI) | **Done** | — |
| File manipulation (workspace surface) | **Done** | — |
| Computer use (MELRA): click / type / inspect / **scroll / drag / key** | **Done** | — (Task 6 complete) |
| Swarm (parallel isolated agents + blackboard + merged `.sova`) | **Done** | — |
| Adversarial / jailbreak missions | **Done** | — |
| Full capability in one run (browser+computer+terminal+files) | **Done** | — (Task 7 complete) |
| Stress testing | **Done** | — (Task 8 complete) |
| Authorization kernel + irreversible opt-in + full-capability profile | **Done** | — |
| Arena (agent-vs-agent, agent-vs-platform) records to `.sova` | **Done** | — |
| Registry contribution (HTTP client + git-PR fallback, default-on) | **Done** | — (Task 10 confirmed) |

## STATUS: ALL TASKS COMPLETE (2026-08-21)

Tasks 6–10 are built and green. Final gate: **1680 unit tests passed, 3 skipped**
(environment-gated), ruff + ruff format + mypy all clean; 148 integration tests
collect cleanly with the three new live-conformance modules included.

**Bug found and fixed during Task 9** — Task 7's composed computer surface could
never have bound at runtime. `ManagedComputerSurface.bind()` requires
`TargetInstance.process_id`/`window_handle_digest` for a `window`-kind surface,
and requires `session.identity_digest` to equal the surface's own
`identity_digest` — but `run_live_web_executor_engine` never populated those
fields and derives the session identity internally. Fixed by (a) adding opt-in
`additional_target_process_id`/`_process_start_digest`/`_window_handle_digest`
passthrough to `run_live_web_executor_engine` (every existing caller leaves them
`None`, preserving the exact prior admission shape), and (b) removing
`identity_digest` from `MelraComputerBackendSpec` in favour of
`_session_identity_digest()`, which mirrors the engine's own formula so the
composed surface binds to the real session identity rather than an
operator-guessed one.

**One deliberate deviation from this plan:** `_MAX_TOTAL_INTERACTIONS` is **128**,
not the 200 sketched in §8.1. At 200 the ceiling equalled
`_MAX_AGENTS * _MAX_REPETITIONS` (8 × 25) exactly and was therefore unreachable —
not a real constraint. 128 makes it an independent bound, as intended.

**New CLI surface:** `sova engine full-web` and `sova engine stress-web` (handler
count 119 → 121), both with default-on registry contribution and `--no-contribute`.

Remaining before announcing: run the three env-gated live lanes on a machine with
the toolchain (§11 items 3–4) — the one thing that cannot be verified from here.

---

## 1. Global invariants (NEVER violate — these are the whole product)

1. **Proof-of-control gates everything.** No engine/swarm/stress run proceeds
   without `verified_browser_control` returning proven origins/host. Full
   capability changes *what* an authorized agent may do, never *whether*
   authorization is required. (User's words: "the only difference is you have
   given all the permissions and authorisations of the platform you're testing.")
2. **Planners never receive executor objects, process handles, workspaces,
   profile paths, or secret providers.** They receive redacted observations and
   declarative grants only. Every new surface obeys this.
3. **Fail-closed codecs.** Model JSON → bounded `ActionRequest` only through the
   existing codec discipline: exact field sets, `_reject_sensitive_material`,
   byte/element/count ceilings. New actions extend the finite algebra; they never
   accept free-form input.
4. **No DoS.** Stress testing is *bounded, authorized robustness probing*, never
   an unbounded flood. Hard code ceilings; refuse unauthorized/unproven targets.
5. **Registry contribution is disclosed, not silent telemetry**, default-on with
   an explicit opt-out. Git-PR fallback **never** auto-pushes or opens PRs.
6. **Least privilege per target.** A reviewed target only permits the action(s)
   its own capability admits — never the surface-wide ceiling.

## 2. The gate (run after EVERY task; all must be green)

Windows note: pytest basetemp must be **outside** the repo, or Windows denies
access. Use the flag below verbatim.

```bash
# from repo root: C:\Users\HP\Downloads\SOVA-OSS
ruff check src tests
ruff format --check src tests
mypy src
python -m pytest tests/unit --basetemp="C:/Users/HP/AppData/Local/Temp/sova-pytest-outside" -q
```

Baseline before Task 6: **1635 unit tests green, ruff+mypy clean.** Each task adds
tests and must keep the whole suite green with zero regressions. If a "failure"
lives under `pytest-of-HP`/basetemp, it is an artifact — re-run with the flag.

---

## TASK 6 — Finish the MELRA computer algebra (scroll / drag / key)

**Status going in:** `action_codecs.py` (codec dispatch for scroll/drag/key) and
`computer_surface.py` (`ManagedComputerSurface(..., mutations=...)`) are **already
done and green**. `melra_computer.py` is **partially** done: `_validated_mutations`,
`_melra_computer_capabilities(mutations)`, `MelraComputerExecutor(..., mutations=)`,
and `melra_computer_lazy_executor(..., mutations=)` already thread the ceiling.
**Only two gaps remain.**

### 6.1 Design decision (SETTLED — do not deviate)

**Per-element action assignment = element-capability ∩ operator-ceiling, fail-early.**

MELRA `computer.inspect` output is provisional (see module docstring). Extend the
assumed element shape with two **optional** boolean hints, default `False`:

```
{"id": str, "editable": bool, "scrollable"?: bool, "draggable"?: bool,
 "boundingBox": {"x": int, "y": int, "width": int, "height": int}}
```

Element-capability rule (before intersect):
- `computer.click` → every element (universal).
- `computer.type`  → `editable` elements.
- `computer.key`   → `editable` elements (a focused field/control is the canonical
  place to send Enter/Tab/Escape/arrows; text entry itself stays in `type`).
- `computer.scroll`→ `scrollable` elements.
- `computer.drag`  → `draggable` elements.

Then **intersect** each element's capability set with the operator ceiling
(`mutations`). If the intersection is empty, **drop the element entirely** (do not
emit a `ReviewedComputerTarget` with empty actions — the dataclass rejects that).

**Why this is correct & safe:** a target never advertises an action the executor
won't run (the ceiling also drives `MelraComputerExecutor._admitted` and the
advertised capabilities), so stale/over-broad actions fail at *decode*, not at
execution. Backward compatible: with the default ceiling `("computer.click",
"computer.type")`, the `scrollable`/`draggable` hints are intersected away and
output is byte-for-byte identical to today (existing 14 tests stay green).

**Consistency invariant (critical):** `melra_computer_surface_generation` must
thread **one** `mutations` value to all three consumers — the lazy executor
(advertised capabilities), the snapshot source (per-element assignment), and
`ManagedComputerSurface(mutations=...)` (admitted actions). Divergence is a bug.

### 6.2 Edits to `src/sova/runtime/melra_computer.py`

**(a)** Change `_parse_inspect_elements` to take the ceiling and apply the rule:

```python
def _element_actions(
    *, editable: bool, scrollable: bool, draggable: bool, ceiling: frozenset[str]
) -> tuple[str, ...]:
    capable = {"computer.click"}
    if editable:
        capable |= {"computer.type", "computer.key"}
    if scrollable:
        capable.add("computer.scroll")
    if draggable:
        capable.add("computer.drag")
    return tuple(sorted(capable & ceiling))


def _parse_inspect_elements(
    provider_output: Mapping[str, Any],
    mutations: tuple[str, ...] = _DEFAULT_MUTATIONS,
) -> tuple[ReviewedComputerTarget, ...]:
    ceiling = frozenset(_validated_mutations(mutations))
    ...
    for element in elements:
        ...
        editable = element.get("editable", False)
        scrollable = element.get("scrollable", False)
        draggable = element.get("draggable", False)
        if any(not isinstance(flag, bool) for flag in (editable, scrollable, draggable)):
            raise FormatError(
                "SOVA-MELRA-COMPUTER-INSPECT",
                "MELRA inspect element flags (editable/scrollable/draggable) must be booleans",
            )
        # ... existing id/box validation (unchanged) ...
        actions = _element_actions(
            editable=editable, scrollable=scrollable, draggable=draggable, ceiling=ceiling
        )
        if not actions:
            continue  # element admits nothing within the operator ceiling; drop it
        targets.append(ReviewedComputerTarget(reference, actions, {"x": center_x, "y": center_y}))
    return tuple(targets)
```

Keep every existing check (element-object shape, id/box bounds, duplicate-reference
rejection, `_MAX_INSPECT_ELEMENTS`). Only the `actions` derivation and the two new
optional-flag reads change. Note: the current strict shape check rejects unknown
keys? **No** — it reads specific keys and ignores extras, so adding optional reads
is safe. Confirm by reading the loop; if it enforces an exact key set, relax it to
allow `scrollable`/`draggable` (and only those two) as optional.

**(b)** Thread `mutations` through `MelraComputerSnapshotSource`:

```python
class MelraComputerSnapshotSource:
    def __init__(
        self, executor: LazyStdioExecutor, *, mutations: tuple[str, ...] = _DEFAULT_MUTATIONS
    ) -> None:
        self._executor = executor
        self._mutations = _validated_mutations(mutations)
        self._workspace: Path | None = None
    ...
    def __call__(self) -> ComputerSurfaceSnapshot:
        ...
        targets = _parse_inspect_elements(provider_output, self._mutations)
        ...
```

### 6.3 Edit to `src/sova/community/executor_surfaces.py`

Add a `mutations` parameter to `melra_computer_surface_generation` and thread it to
all three consumers:

```python
def melra_computer_surface_generation(  # noqa: PLR0913
    *,
    node_executable: Path,
    cli_entrypoint: Path,
    policy_factory: Callable[[Path], Path],
    identity_digest: str,
    pid: int,
    window_id: int,
    mutations: tuple[str, ...] = ("computer.click", "computer.type"),
) -> EngineSurfaceGeneration:
    lazy_executor = melra_computer_lazy_executor(
        node_executable=node_executable,
        cli_entrypoint=cli_entrypoint,
        policy_factory=policy_factory,
        mutations=mutations,
    )
    snapshot_source = MelraComputerSnapshotSource(lazy_executor, mutations=mutations)
    surface = ManagedComputerSurface(
        executor=lazy_executor,
        kind="window",
        identity_digest=identity_digest,
        snapshot=snapshot_source,
        pid=pid,
        window_id=window_id,
        cleanup=lazy_executor.close,
        mutations=mutations,
    )
    ...
```

(Import the literal default from `melra_computer` if you prefer a single source of
truth: `from sova.runtime.melra_computer import _DEFAULT_MUTATIONS` — but a public
module shouldn't import a private name; re-declare the tuple locally, they must
stay equal. Simpler: hard-code `("computer.click", "computer.type")` as above.)

### 6.4 Tests — extend `tests/unit/test_melra_computer.py`

Add (do not remove the 14 existing; they must stay green unchanged):

- `test_default_ceiling_ignores_scroll_drag_hints` — element with
  `scrollable=True, draggable=True` under default ceiling → target actions are
  exactly `("computer.click",)` (or `+type` if editable). Proves backward compat.
- `test_scroll_hint_admits_scroll_when_in_ceiling` — ceiling includes
  `computer.scroll`; a `scrollable` element gets `computer.scroll`; a
  non-scrollable one does not.
- `test_drag_hint_admits_drag_when_in_ceiling` — two `draggable` elements each get
  `computer.drag` under a drag-containing ceiling.
- `test_key_follows_editable` — `computer.key` appears iff element is `editable`
  and `computer.key` is in the ceiling.
- `test_element_dropped_when_intersection_empty` — ceiling `("computer.scroll",)`,
  a non-scrollable non-editable element → dropped (not in output), no empty-action
  crash.
- `test_non_boolean_flag_rejected` — `scrollable: "yes"` → `FormatError`
  `SOVA-MELRA-COMPUTER-INSPECT`.
- `test_snapshot_source_threads_ceiling` — build `MelraComputerSnapshotSource(exec,
  mutations=("computer.click","computer.scroll"))` with a fake transport returning a
  scrollable element; assert the emitted target carries `computer.scroll`.
- `test_surface_generation_threads_ceiling` (in `tests/unit/test_executor_surfaces.py`)
  — `melra_computer_surface_generation(..., mutations=(...,))` produces a surface
  whose advertised capabilities equal the ceiling + `computer.inspect`.

**Gate:** run §2. Expect **1635 + ~8 = ~1643** green.

---

## TASK 7 — Full-capability engine run (browser + computer + terminal + files)

**Goal:** one authorized run in which the swarm/agents can drive the browser AND a
MELRA computer window AND one host-process (terminal) template AND the workspace —
all behind the same proof-of-control, all recorded to one `.sova`.

**Architecture (CONFIRMED in code — no redesign):**
- `run_live_web_executor_engine` already builds browser + workspace built-ins and
  accepts `additional_surface_factory: (phase) -> tuple[EngineSurfaceGeneration]`,
  `additional_codec_factories: Mapping[codec_id, CodecFactory]`, and
  `additional_surface_contract_digest: str`.
- The engine routes each grant to its codec by `grant.codec_id`
  (`ExecutorEngineRuntime.codec_resolver`). Distinct codec_ids coexist:
  `sova.action-codec.browser/0.1.0`, `.../workspace/...`, `.../computer/...`,
  `.../process/...`.
- **Hard constraint:** exactly **one** host-process template per run. All process
  templates share codec_id `sova.action-codec.process/0.1.0`; the registry is a
  dict keyed by codec_id, so two templates collide. Terminal = one reviewed
  `ExactProcessSurfaceSpec`. (gVisor OCI is a separate codec_id and could be added
  later the same way; out of scope for v1 full-capability.)
- Per-phase freshness: the factory MUST build fresh surface generations each call
  (`_record_surface_generation` rejects aliased executors). `melra_computer_surface_generation`
  and `process_surface_generation` both build fresh objects each call — good.
- The precomputed `additional_surface_contract_digest` must equal what the factory
  produces each phase. All inputs (identity_digest, pid, window_id, mutations,
  process spec) are fixed, so the digest is stable. Compute it once from a
  throwaway build and `close()` that build.

### 7.1 New file: `src/sova/community/executor_engine_full.py`

```python
# SPDX-License-Identifier: Apache-2.0
"""Full-capability authorized run: browser + workspace + MELRA computer + one
reviewed host-process (terminal) surface, composed over the live web engine."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sova.community.executor_surfaces import (
    ExactProcessSurfaceSpec,
    computer_codec_factory,
    melra_computer_surface_generation,
    process_codec_factory,
    process_surface_generation,
)
from sova.community.live_executor_engine import run_live_web_executor_engine
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from pathlib import Path
    from sova.community.executor_chamber import ApprovalPrompt, ExecutorChamberArtifacts
    from sova.community.executor_engine import CodecFactory, EngineSurfaceGeneration
    from sova.live.semantic_workflow import SemanticBrowserMission
    from sova.runtime import RoleModel
    from sova.safety import ControlProof
    from sova.targets import TargetManifest

_COMPUTER_CODEC_ID = "sova.action-codec.computer/0.1.0"
_PROCESS_CODEC_ID = "sova.action-codec.process/0.1.0"


@dataclass(frozen=True, slots=True)
class MelraComputerBackendSpec:
    """Everything needed to launch one reviewed MELRA computer window."""
    node_executable: Path
    cli_entrypoint: Path
    policy_factory: Callable[[Path], Path]
    identity_digest: str
    pid: int
    window_id: int
    mutations: tuple[str, ...] = ("computer.click", "computer.type")


def _build_additional(
    computer: MelraComputerBackendSpec | None,
    process_template: ExactProcessSurfaceSpec | None,
) -> tuple[EngineSurfaceGeneration, ...]:
    surfaces: list[EngineSurfaceGeneration] = []
    if computer is not None:
        surfaces.append(
            melra_computer_surface_generation(
                node_executable=computer.node_executable,
                cli_entrypoint=computer.cli_entrypoint,
                policy_factory=computer.policy_factory,
                identity_digest=computer.identity_digest,
                pid=computer.pid,
                window_id=computer.window_id,
                mutations=computer.mutations,
            )
        )
    if process_template is not None:
        surfaces.append(process_surface_generation(process_template))
    return tuple(surfaces)


def run_full_capability_web_engine(  # noqa: PLR0913
    target: TargetManifest,
    mission: SemanticBrowserMission,
    chamber_document: dict[str, Any],
    destination: Path,
    *,
    package_runner: Path,
    browser_executable: Path,
    approval_prompt: ApprovalPrompt,
    secret_resolver: Callable[[str], str | None],
    provider_calls_authorized: bool,
    target_observation_disclosure_authorized: bool,
    control_proof: ControlProof | None = None,
    external_models: Mapping[str, RoleModel] | None = None,
    computer: MelraComputerBackendSpec | None = None,
    process_template: ExactProcessSurfaceSpec | None = None,
    offensive: bool = False,
    headless: bool = True,
    package_cache: Path | None = None,
    browser_cache: Path | None = None,
    workspace_parent: Path | None = None,
    workspace_seed: Path | None = None,
    event_observer: Callable[[str, dict[str, Any]], None] | None = None,
) -> ExecutorChamberArtifacts:
    if computer is None and process_template is None:
        raise FormatError(
            "SOVA-EXECUTOR-ENGINE-FULL",
            "full-capability run requires at least one of a computer or process surface; "
            "use run_live_web_executor_engine for browser+workspace only",
        )

    codec_factories: dict[str, CodecFactory] = {}
    if computer is not None:
        codec_factories[_COMPUTER_CODEC_ID] = computer_codec_factory(sensor_name="computer")
    if process_template is not None:
        codec_factories[_PROCESS_CODEC_ID] = process_codec_factory(process_template)

    # Precompute the contract digest from a throwaway build; then close it.
    representative = _build_additional(computer, process_template)
    try:
        contract_digest = sha256_digest(
            canonical_json_bytes(
                [s.contract_mapping() for s in sorted(representative, key=lambda i: i.sensor_name)]
            )
        )
    finally:
        for surface in reversed(representative):
            surface.close()

    def additional_surface_factory(_phase: str) -> tuple[EngineSurfaceGeneration, ...]:
        return _build_additional(computer, process_template)

    return run_live_web_executor_engine(
        target,
        mission,
        chamber_document,
        destination,
        package_runner=package_runner,
        browser_executable=browser_executable,
        approval_prompt=approval_prompt,
        secret_resolver=secret_resolver,
        provider_calls_authorized=provider_calls_authorized,
        target_observation_disclosure_authorized=target_observation_disclosure_authorized,
        control_proof=control_proof,
        external_models=external_models,
        offensive=offensive,
        headless=headless,
        package_cache=package_cache,
        browser_cache=browser_cache,
        workspace_parent=workspace_parent,
        workspace_seed=workspace_seed,
        additional_surface_factory=additional_surface_factory,
        additional_codec_factories=codec_factories,
        additional_surface_contract_digest=contract_digest,
        event_observer=event_observer,
    )


__all__ = ["MelraComputerBackendSpec", "run_full_capability_web_engine"]
```

**Watch-outs (verify against the live engine while building):**
- `_build_additional` must return the surfaces in a **stable order** — the digest
  sorts by `sensor_name`, so order in the tuple doesn't affect the digest, but the
  engine's `_record_surface_generation` requires unique sensor_names/backend_ids.
  `process_{id}` and `computer` differ — fine.
- `computer_codec_factory` and `process_codec_factory` already exist in
  `executor_surfaces.py`; do not re-implement.
- Closing the throwaway MELRA build calls `lazy_executor.close()` on a
  never-launched executor — confirm that is a no-op (it should be). If it raises on
  an un-launched process, guard the digest build so a benign close doesn't fail the
  run.

### 7.2 Operator chamber document

The engine validates that every `grant.codec_id` in the supplied chamber document
is a subset of the runtime's codecs (built-in browser/workspace + the additional
computer/process). The **operator authors** the document; the helper does not
synthesize it. Provide a documented example fixture (not code) showing grants for
all four codec_ids and a case whose participant `allowedGrants` reference them.
Put it at `docs/engineering/examples/full-capability-chamber.json` for reference
only (tests build their own minimal documents).

### 7.3 Tests — new `tests/unit/test_executor_engine_full.py`

Use the same fake/scripted-model + fake-transport harness the existing engine
tests use (mirror `test_executor_engine.py` / `test_melra_computer.py` fixtures;
do NOT launch a real browser here — that's Task 9).

- `test_requires_at_least_one_extra_surface` — both `computer` and
  `process_template` None → `FormatError SOVA-EXECUTOR-ENGINE-FULL`.
- `test_contract_digest_is_stable_across_rebuilds` — build additional twice via the
  internal factory; assert equal contract digests (guards the reproduction-phase
  substitution check).
- `test_codec_registry_has_expected_ids` — with both surfaces, the assembled
  `codec_factories` keys == `{_COMPUTER_CODEC_ID, _PROCESS_CODEC_ID}`.
- `test_process_only_and_computer_only` — each single-surface configuration
  assembles a one-entry codec registry and one additional surface.
- `test_end_to_end_scripted` — a scripted planner proposes one workspace write and
  one computer click against a fake MELRA transport + fake browser surface; assert
  the run produces a capsule and the trace records both effects. (If wiring a fake
  browser is too heavy, split: assert the helper forwards the exact
  `additional_*` arguments into `run_live_web_executor_engine` via monkeypatch, and
  cover real execution in Task 9's gated test.)

**Gate:** run §2.

---

## TASK 8 — Stress testing (bounded, authorized robustness profile)

**Design decision (SETTLED):** Stress testing = a **bounded, authorization-gated
swarm robustness profile** that fans the adversarial-tactic library (and optional
operator payloads) across N concurrent agents, with **bounded per-agent
repetition**, aggregating a robustness report into the swarm `.sova`. It reuses
`run_web_swarm` + `sova.live.adversarial_missions` + the offensive-mission path.
It is **not** a raw network flood (that would be DoS — forbidden by §1.4).

Rationale: in agent-security terms, "stress testing the target's agent" means
sustained, varied, adversarial input to find where it breaks / hallucinates —
exactly what the adversarial missions + swarm already do. "Stress" adds *volume
and variety under hard ceilings*, not raw request flooding.

### 8.1 New file: `src/sova/community/swarm/stress.py`

```python
# SPDX-License-Identifier: Apache-2.0
"""Bounded authorized robustness ("stress") profile over the concurrent swarm."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sova.community.swarm.runtime import SwarmArtifacts, run_web_swarm
from sova.formats.errors import FormatError
from sova.live.adversarial_missions import adversarial_tactic_ids, build_adversarial_mission

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path
    from sova.community.executor_chamber import ApprovalPrompt
    from sova.safety import ControlProof
    from sova.targets import TargetManifest

# Hard ceilings — never configurable above these (anti-DoS, §1.4).
_MAX_AGENTS = 8
_MAX_REPETITIONS = 25          # bounded mission repeats per agent
_MAX_TOTAL_INTERACTIONS = 200  # agents * repetitions ceiling


@dataclass(frozen=True, slots=True)
class StressReport:
    destination: Path
    swarm: SwarmArtifacts
    tactic_ids: tuple[str, ...]
    agent_count: int
    repetitions: int
```

`run_stress_profile(...)` signature and behavior:

```python
def run_stress_profile(  # noqa: PLR0913
    target: TargetManifest,
    base_chamber_document: dict[str, Any],
    destination: Path,
    *,
    entry_url: str,
    package_runner: Path,
    browser_executable: Path,
    approval_prompt: ApprovalPrompt,
    secret_resolver: Callable[[str], str | None],
    provider_calls_authorized: bool,
    target_observation_disclosure_authorized: bool,
    agent_count: int,
    repetitions: int = 1,
    tactic_ids: tuple[str, ...] | None = None,   # default: full library
    extra_payloads: tuple[str, ...] = (),
    control_proof: ControlProof | None = None,
    headless: bool = True,
    package_cache: Path | None = None,
    browser_cache: Path | None = None,
    event_observer: Callable[[str, dict[str, Any]], None] | None = None,
) -> StressReport:
    ...
```

Behavior + invariants:
1. Validate ceilings: `1 <= agent_count <= _MAX_AGENTS`,
   `1 <= repetitions <= _MAX_REPETITIONS`,
   `agent_count * repetitions <= _MAX_TOTAL_INTERACTIONS`. Else
   `FormatError SOVA-SWARM-STRESS-BOUNDS`.
2. `selected = tactic_ids or adversarial_tactic_ids()`. Validate each is a known
   tactic (reuse `adversarial_tactic`; unknown → its existing `FormatError`).
3. Build **one offensive** `SemanticBrowserMission` for the profile. For v1, the
   mission carried into the swarm is a single adversarial mission built from the
   first selected tactic with **all** selected tactics' payloads (+ `extra_payloads`)
   folded into `extra_payloads`, so each agent exercises the full battery.
   (`build_adversarial_mission(tactic_ids[0], entry_url=entry_url,
   extra_payloads=<union of the rest>)`. Dedup payloads — the builder rejects
   duplicates.) `offensive` is forced `True`; this forces DESTRUCTIVE approval at
   the engine (correct — it's active adversarial testing under proof-of-control).
4. **Repetition:** encode `repetitions` into each agent's objective via
   `personas`/focus so an agent re-runs its battery `repetitions` times within its
   single engine session. v1 simplest honest mapping: pass `agent_count` to
   `run_web_swarm` and set the coordinator focus/persona text to instruct
   `repetitions` passes; the true per-session loop lives in the mission objective,
   not new executor code. (Do NOT add a raw resend loop at the network layer.)
5. Delegate to `run_web_swarm(target, mission, base_chamber_document, destination,
   agent_count=agent_count, offensive=True, ...)`. The swarm already produces
   `swarm.sova` + coordinator trace + merged findings.
6. Return `StressReport` referencing the `SwarmArtifacts` and the tactic set.

**Scope honesty:** v1 stress = concurrency × adversarial variety × bounded
repetition, all recorded. It deliberately does NOT add a new network load
generator. If true HTTP load testing is wanted later, it must be a separate,
explicitly-gated surface with per-second rate ceilings and owner attestation — out
of scope here and flagged as such.

### 8.2 Tests — new `tests/unit/test_swarm_stress.py`

- `test_bounds_reject_too_many_agents` / `_too_many_repetitions` /
  `_too_many_total_interactions` → `SOVA-SWARM-STRESS-BOUNDS`.
- `test_unknown_tactic_rejected`.
- `test_default_uses_full_tactic_library` — `tactic_ids=None` selects
  `adversarial_tactic_ids()`.
- `test_mission_is_offensive_and_folds_all_payloads` — built mission
  `.offensive is True` and its `seed_inputs` contain a payload from each selected
  tactic.
- `test_delegates_to_swarm` — monkeypatch `run_web_swarm`; assert it is called once
  with `offensive=True`, the computed `agent_count`, and the built mission; assert
  the returned `StressReport` wraps the swarm artifacts.
- `test_duplicate_payloads_deduped` — overlapping tactic payloads don't raise.

**Gate:** run §2.

---

## TASK 9 — Real end-to-end integration tests (env-gated, opt-in)

These exercise the actual browser/MELRA processes and are **skipped by default**;
they run only when the operator sets the env var (they need Node, Playwright, and a
MELRA build present). Put them under `tests/integration/`.

Guard pattern (top of each test/module):
```python
import os, pytest
pytestmark = pytest.mark.skipif(
    os.environ.get("SOVA_RUN_REAL_BROWSER") != "1",
    reason="set SOVA_RUN_REAL_BROWSER=1 to run the real-browser swarm test",
)
```

### 9.1 `tests/integration/test_real_browser_swarm.py` (gate `SOVA_RUN_REAL_BROWSER=1`)
- Start a **local** loopback HTTP fixture app (the repo already has a
  chat/echo fixture pattern — reuse it; if none, a `http.server` thread serving a
  tiny page with a form). Prove control over `127.0.0.1` via the existing
  loopback/control-proof path.
- Run `run_web_swarm(..., agent_count=3, headless=True)` with a scripted-or-real
  model against the fixture.
- Assert: `swarm.sova` and `coordinator.sova-trace` exist; report `agentCount==3`;
  each agent dir has its own capsule/trace; wall-clock < serialized lower bound
  (proves real concurrency, as the existing timing test does).

### 9.2 `tests/integration/test_real_melra_computer.py` (gate `SOVA_RUN_REAL_MELRA=1`)
- Requires a MELRA build path via env (`SOVA_MELRA_NODE`, `SOVA_MELRA_CLI`,
  `SOVA_MELRA_POLICY`). If any missing → skip with a clear reason.
- Launch `melra_computer_lazy_executor(..., mutations=("computer.click",
  "computer.type","computer.scroll"))`, run one `computer.inspect`, assert a
  redacted snapshot with ≥1 reviewed target and that a `scrollable` target (if the
  fixture window has one) carries `computer.scroll`.
- Verifies the **provisional inspect contract** against a live MELRA — the module
  docstring flags this as the one unverified assumption; update the docstring if
  the live shape differs (and adjust `_parse_inspect_elements` + its unit tests).

### 9.3 `tests/integration/test_real_full_capability.py` (gate both vars)
- Compose `run_full_capability_web_engine` against the loopback fixture + real
  MELRA + one reviewed host-process template (e.g. an absolute path to a benign
  echo binary). Assert one capsule records browser + computer + process + workspace
  effects.

**Note:** These do not run in the default CI gate (§2). Run them manually before
launch on a machine with the toolchain. Record the outcome in the launch checklist.

**Gate:** run §2 (the new integration tests are skipped, so the count is unchanged;
confirm they COLLECT without import errors: `pytest tests/integration --co -q`).

---

## TASK 10 — CLI surface + registry-default-on confirmation

### 10.1 Wire new commands in `src/sova/cli.py`
Follow the existing `_engine_run_web` / `_engine_swarm_web` handler patterns
(already present) and their `_add_contribution_arguments` wiring:

- `sova engine full-web` → `run_full_capability_web_engine`. Add flags for the
  computer backend (`--melra-node`, `--melra-cli`, `--melra-policy`,
  `--melra-identity`, `--melra-pid`, `--melra-window-id`, `--melra-mutations`
  comma-list) and one `--process-template` spec (identifier + absolute executable +
  argv prefix + `--trusted-host-process` ack). At least one of computer/process
  required (mirror the helper's guard). Reuse `_contribute_run_evidence`.
- `sova swarm stress` → `run_stress_profile`. Flags: `--agents`, `--repetitions`,
  `--tactics` (comma-list, default all), `--entry-url`, plus the shared browser/
  auth/contribution flags. Reuse `_prompt_agent_count` for the interactive
  "how many agents?" behavior the founder asked for.

Keep every new command behind the same authorization/offensive/disclosure flags as
the existing engine commands. Update `tests/unit/test_cli_surface_audit.py` to
include the two new subcommands (the audit test enumerates the CLI surface).

### 10.2 Confirm registry default-on (should already be true)
- `auto_contribute_after_run(..., enabled=True)` is the default; the CLI opt-out is
  `--no-contribute`. Verify both engine commands AND the two new commands call the
  contribution path by default. Add a CLI test asserting that without
  `--no-contribute`, the contribution function is invoked (monkeypatch it), and
  with `--no-contribute` it is not.

**Gate:** run §2, plus `sova --help` and each new `--help` renders without error.

---

## 11. Final launch checklist (run before announcing)

1. §2 gate green: ruff, ruff format, mypy, full unit suite (expect ~1660+ tests).
2. `pytest tests/integration --co -q` collects with no import errors.
3. On a toolchain machine: `SOVA_RUN_REAL_BROWSER=1` swarm test passes;
   `SOVA_RUN_REAL_MELRA=1` computer test passes; full-capability test passes.
4. MELRA inspect contract confirmed against a live build (Task 9.2); module
   docstring updated to drop "provisional" if verified.
5. `sova engine full-web --help`, `sova swarm stress --help` render.
6. Registry: a real run against a live `CommunityHTTPService` accepts the capsule;
   git-PR fallback produces a local branch/patch WITHOUT pushing.
7. Update `docs/engineering/last-mile-launch-implementation-plan-2026-08-21.md`
   status table and this doc's §0 to "Done".
8. Update memory index (`MEMORY.md`) note: engine completed to vision on 2026-08-21.

---

## 12. Build order & handoff summary (for the Sonnet session)

Do strictly in order; gate after each:

1. **Task 6** — finish MELRA algebra (2 files edited, ~8 tests). Lowest risk;
   unblocks nothing else but completes computer-use.
2. **Task 7** — `executor_engine_full.py` (1 new file, ~5 tests). Composition only.
3. **Task 8** — `swarm/stress.py` (1 new file, ~6 tests). Reuses swarm+adversarial.
4. **Task 9** — 3 gated integration tests. No default-CI impact.
5. **Task 10** — CLI wiring + registry-default-on tests.

Every design question is answered above. If code contradicts a stated fact
(e.g. a signature differs), **stop and report** rather than guessing — but the
signatures here were read from the current tree and are accurate as of
2026-08-21. Keep the six global invariants (§1) inviolate; they are the product.
