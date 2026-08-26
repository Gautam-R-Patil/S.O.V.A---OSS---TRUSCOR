# SPDX-License-Identifier: Apache-2.0
"""Desktop computer-use surface backed by the MELRA MCP adapter.

SOVA uses MELRA for desktop computer-use only: browser stays on the pinned
Playwright MCP surface (`sova.runtime.browser_surface`) and terminal stays on
`RestrictedLocalExecutor`.  `MelraExecutorAdapter` (`sova.mcp.adapter`) already
implements the full MELRA plan/approve/execute contract across browser,
computer, and terminal actions.  This module narrows that contract to exactly
the reviewed window-kind computer algebra `ManagedComputerSurface` admits
(`computer.inspect`, `computer.click`, `computer.type`), launches it lazily
through the same `LazyStdioExecutor` primitive the browser surface uses (fresh
process per session, live-capability-substitution detection, deterministic
cleanup), and builds a redacted, coordinate-based snapshot for planner review.

The exact shape of MELRA's `computer.inspect` provider output is pinned here
provisionally (`_parse_inspect_elements`) pending verification against a live
MELRA instance; `tests/unit/test_melra_computer.py` documents and exercises
the assumed contract with a fake MCP transport.  MELRA does not synthesize or
validate its own policy content -- `policy_factory` is the caller's
responsibility, matching MELRA's own policy documentation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sova.executors import (
    ActionOutcome,
    ActionRequest,
    CancellationToken,
    Capability,
    OutcomeStatus,
    SideEffect,
)
from sova.formats.errors import FormatError
from sova.mcp import MELRA_AUDIT_RECEIPT, MelraDirectories, MelraExecutorAdapter, melra_stdio_spec
from sova.runtime.action_codecs import ReviewedComputerTarget
from sova.runtime.computer_surface import ComputerSurfaceSnapshot
from sova.runtime.managed_surfaces import LazyStdioExecutor

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from pathlib import Path

    from sova.executors import ExecutionContext
    from sova.mcp import MCPClient, StdioServerSpec

_MAX_INSPECT_ELEMENTS = 256
_MAX_COORDINATE = 1_000_000
#: Reviewed mutation names MELRA is allowed to expose through this surface.
_ADMITTED_MUTATIONS = frozenset(
    {"computer.click", "computer.type", "computer.scroll", "computer.drag", "computer.key"}
)
#: Historical default; keeps every existing caller (click + type only) unchanged.
_DEFAULT_MUTATIONS: tuple[str, ...] = ("computer.click", "computer.type")


def _melra_computer_capabilities(mutations: tuple[str, ...]) -> tuple[Capability, ...]:
    """Build the narrowed contract for `computer.inspect` plus `mutations`.

    `LazyStdioExecutor` compares this declared set against the live adapter's
    advertised capabilities at first launch and refuses to proceed on drift, so
    each Capability here must match `MelraExecutorAdapter`'s advertised shape
    exactly (version, side effect, idempotency, evidence).
    """
    version = MELRA_AUDIT_RECEIPT.version
    evidence = ("melra-receipt",)
    capabilities = [
        Capability(
            name="computer.inspect",
            version=version,
            side_effect=SideEffect.READ,
            idempotent=True,
            evidence=evidence,
        )
    ]
    capabilities.extend(
        Capability(
            name=mutation,
            version=version,
            side_effect=SideEffect.MUTATE,
            idempotent=False,
            evidence=evidence,
        )
        for mutation in mutations
    )
    return tuple(sorted(capabilities, key=lambda item: item.identifier))


def _validated_mutations(mutations: tuple[str, ...]) -> tuple[str, ...]:
    if (
        not isinstance(mutations, tuple)
        or not mutations
        or len(set(mutations)) != len(mutations)
        or any(item not in _ADMITTED_MUTATIONS for item in mutations)
    ):
        raise FormatError(
            "SOVA-MELRA-COMPUTER-CONFIG",
            "MELRA computer mutation set must be a unique non-empty subset of the "
            "reviewed algebra (click, type, scroll, drag, key)",
        )
    return mutations


class MelraComputerExecutor:
    """Narrow one MELRA MCP adapter to the reviewed window-kind computer algebra.

    `delegate` may advertise browser and terminal capabilities too; only
    `computer.inspect` plus the declared `mutations` are exposed or dispatched.
    """

    def __init__(
        self,
        delegate: MelraExecutorAdapter,
        *,
        mutations: tuple[str, ...] = _DEFAULT_MUTATIONS,
    ) -> None:
        self._mutations = _validated_mutations(mutations)
        available = {capability.name: capability for capability in delegate.capabilities()}
        expected = _melra_computer_capabilities(self._mutations)
        matched = tuple(
            available[capability.name] for capability in expected if capability.name in available
        )
        if matched != expected:
            raise FormatError(
                "SOVA-MELRA-COMPUTER-CAPABILITY",
                "MELRA adapter does not advertise the exact reviewed computer algebra",
                details={
                    "expected": sorted(item.identifier for item in expected),
                    "available": sorted(available),
                },
            )
        self._delegate = delegate
        self._capabilities = tuple(sorted(matched, key=lambda item: item.identifier))
        self._admitted = frozenset(item.name for item in self._capabilities)

    @property
    def name(self) -> str:
        return f"sova-melra-computer:{self._delegate.name}"

    def capabilities(self) -> tuple[Capability, ...]:
        return self._capabilities

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        if request.action not in self._admitted:
            raise FormatError(
                "SOVA-MELRA-COMPUTER-ACTION",
                "computer executor received an action outside the reviewed algebra",
            )
        return self._delegate.execute(request, context, cancellation)

    def close(self) -> None:
        close = getattr(self._delegate, "close", None)
        if callable(close):
            close()


def melra_computer_lazy_executor(
    *,
    node_executable: Path,
    cli_entrypoint: Path,
    policy_factory: Callable[[Path], Path],
    name: str = "sova-melra-computer",
    mutations: tuple[str, ...] = _DEFAULT_MUTATIONS,
) -> LazyStdioExecutor:
    """Build a lazily-launched, capability-narrowed MELRA computer executor.

    `policy_factory` receives the admitted disposable workspace and must
    materialize (or already contain) an existing MELRA policy file inside it,
    returning its absolute path.  SOVA does not author MELRA policy content;
    MELRA's own authorization/effect semantics remain the operator's
    responsibility to configure.  `mutations` selects the reviewed algebra
    (default click + type); admitting scroll/drag/key widens what the planner
    may propose against the bound window.
    """
    if not callable(policy_factory):
        raise FormatError(
            "SOVA-MELRA-COMPUTER-CONFIG",
            "MELRA computer executor requires a callable policy factory",
        )
    admitted_mutations = _validated_mutations(mutations)

    def spec_factory(workspace: Path) -> StdioServerSpec:
        directories = MelraDirectories(
            state=workspace / ".melra-state",
            policy=policy_factory(workspace),
        )
        return melra_stdio_spec(
            node_executable=node_executable,
            cli_entrypoint=cli_entrypoint,
            workspace=workspace,
            directories=directories,
        )

    def adapter_factory(client: MCPClient) -> MelraComputerExecutor:
        return MelraComputerExecutor(MelraExecutorAdapter(client), mutations=admitted_mutations)

    return LazyStdioExecutor(
        name=name,
        capabilities=_melra_computer_capabilities(admitted_mutations),
        spec_factory=spec_factory,
        adapter_factory=adapter_factory,
    )


def _bounded_int(value: Any, *, role: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_COORDINATE:
        raise FormatError(
            "SOVA-MELRA-COMPUTER-INSPECT",
            f"MELRA inspect element {role} is not a bounded non-negative integer",
        )
    return value


def _element_actions(
    *,
    editable: bool,
    scrollable: bool,
    draggable: bool,
    ceiling: frozenset[str],
) -> tuple[str, ...]:
    """Intersect one element's advertised capability with the operator ceiling.

    A target only ever carries an action both the element supports *and* the
    operator admitted for this session; anything else fails at decode, never
    at execution (see `ComputerActionCodec._target`).
    """
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
    """Convert MELRA's assumed `computer.inspect` output into reviewed targets.

    Assumed provisional shape (see module docstring):
    ``{"elements": [{"id": str, "editable": bool, "scrollable"?: bool,
    "draggable"?: bool, "boundingBox": {"x": int, "y": int, "width": int,
    "height": int}}, ...]}``. ``scrollable``/``draggable`` default to
    ``False`` when absent. Any element that does not match this shape is
    rejected rather than silently dropped or coerced; an element whose
    capability does not intersect ``mutations`` is dropped (not rejected).
    """
    ceiling = frozenset(_validated_mutations(mutations))
    elements = provider_output.get("elements")
    if not isinstance(elements, list):
        raise FormatError(
            "SOVA-MELRA-COMPUTER-INSPECT",
            "MELRA inspect output did not contain an element list",
        )
    if len(elements) > _MAX_INSPECT_ELEMENTS:
        raise FormatError(
            "SOVA-MELRA-COMPUTER-INSPECT-LIMIT",
            "MELRA inspect output exceeds the reviewed element limit",
        )
    targets: list[ReviewedComputerTarget] = []
    seen_references: set[str] = set()
    for element in elements:
        if not isinstance(element, dict):
            raise FormatError(
                "SOVA-MELRA-COMPUTER-INSPECT",
                "MELRA inspect element is not an object",
            )
        element_id = element.get("id")
        box = element.get("boundingBox")
        editable = element.get("editable", False)
        scrollable = element.get("scrollable", False)
        draggable = element.get("draggable", False)
        if (
            not isinstance(element_id, str)
            or not element_id
            or not isinstance(box, dict)
            or not isinstance(editable, bool)
            or not isinstance(scrollable, bool)
            or not isinstance(draggable, bool)
        ):
            raise FormatError(
                "SOVA-MELRA-COMPUTER-INSPECT",
                "MELRA inspect element is missing its id, bounding box, or a boolean flag",
            )
        reference = f"melra-{element_id}"[:256]
        if reference in seen_references:
            raise FormatError(
                "SOVA-MELRA-COMPUTER-INSPECT",
                "MELRA inspect output contains a duplicate element identity",
            )
        seen_references.add(reference)
        x = _bounded_int(box.get("x"), role="x")
        y = _bounded_int(box.get("y"), role="y")
        width = _bounded_int(box.get("width"), role="width")
        height = _bounded_int(box.get("height"), role="height")
        center_x = min(_MAX_COORDINATE, x + width // 2)
        center_y = min(_MAX_COORDINATE, y + height // 2)
        actions = _element_actions(
            editable=editable,
            scrollable=scrollable,
            draggable=draggable,
            ceiling=ceiling,
        )
        if not actions:
            continue
        targets.append(ReviewedComputerTarget(reference, actions, {"x": center_x, "y": center_y}))
    return tuple(targets)


class MelraComputerSnapshotSource:
    """Zero-arg `ComputerSnapshotCallback` that binds its workspace after construction.

    `ManagedComputerSurface` requires a snapshot callback at construction time,
    but the disposable workspace it must observe is only known once the engine
    binds the surface to a fresh session.  Callers must invoke `bind_workspace`
    from the same `EngineSurfaceGeneration.bind` closure that binds the
    underlying `ManagedComputerSurface` (see
    `sova.community.executor_surfaces.melra_computer_surface_generation`).
    """

    def __init__(
        self,
        executor: LazyStdioExecutor,
        *,
        mutations: tuple[str, ...] = _DEFAULT_MUTATIONS,
    ) -> None:
        self._executor = executor
        self._mutations = _validated_mutations(mutations)
        self._workspace: Path | None = None

    def bind_workspace(self, workspace: Path) -> None:
        if self._workspace is not None and self._workspace != workspace:
            raise FormatError(
                "SOVA-MELRA-COMPUTER-SNAPSHOT-AFFINITY",
                "MELRA computer snapshot source cannot move to another workspace generation",
            )
        self._workspace = workspace

    def __call__(self) -> ComputerSurfaceSnapshot:
        workspace = self._workspace
        if workspace is None:
            raise FormatError(
                "SOVA-MELRA-COMPUTER-SNAPSHOT-AFFINITY",
                "MELRA computer snapshot source is not workspace-bound",
            )
        outcome = self._executor.trusted_observe(
            workspace=workspace,
            action="computer.inspect",
            inputs={},
        )
        if outcome.status != OutcomeStatus.SUCCEEDED:
            raise FormatError(
                "SOVA-MELRA-COMPUTER-INSPECT",
                "MELRA computer inspect did not succeed",
                details={"status": outcome.status.value},
            )
        provider_output = outcome.output.get("providerOutput")
        if not isinstance(provider_output, dict):
            raise FormatError(
                "SOVA-MELRA-COMPUTER-INSPECT",
                "MELRA computer inspect returned no provider output",
            )
        targets = _parse_inspect_elements(provider_output, self._mutations)
        projection = {
            "melra": {
                "elementCount": len(targets),
                "taskId": outcome.output.get("taskId"),
            }
        }
        return ComputerSurfaceSnapshot(projection, targets)


__all__ = [
    "MelraComputerExecutor",
    "MelraComputerSnapshotSource",
    "melra_computer_lazy_executor",
]
