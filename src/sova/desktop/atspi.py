# SPDX-License-Identifier: Apache-2.0
"""Application-bound Linux AT-SPI accessibility executor."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from typing import TYPE_CHECKING, Any, Protocol

from sova.executors import (
    ActionOutcome,
    ActionRequest,
    CancellationToken,
    Capability,
    EvidenceReference,
    ExecutionContext,
    FailureCause,
    OutcomeStatus,
    SideEffect,
)
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from types import ModuleType

_MAX_NODES = 10_000
_MAX_DEPTH = 64
_MAX_TEXT_BYTES = 64 * 1024
_MAX_APPLICATION_BYTES = 512


class AtSpiBackend(Protocol):
    def snapshot(self, application: str) -> dict[str, Any]: ...

    def activate(self, application: str, role: str, name: str) -> None: ...

    def set_text(self, application: str, role: str, name: str, text: str) -> None: ...


@dataclass(frozen=True, slots=True)
class _AccessibleNode:
    role: str
    name: str
    states: tuple[str, ...]
    children: tuple[_AccessibleNode, ...]

    def to_mapping(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "name": self.name,
            "states": list(self.states),
            "children": [child.to_mapping() for child in self.children],
        }


class PyAtSpiBackend:
    """AT-SPI implementation using the system pyatspi bindings and D-Bus service."""

    def __init__(self, module: ModuleType | None = None) -> None:
        try:
            self._module = module or import_module("pyatspi")
        except ImportError as error:
            raise FormatError(
                "SOVA-ATSPI-UNAVAILABLE",
                "system pyatspi bindings are unavailable",
            ) from error

    def _application(self, name: str) -> Any:
        desktop = self._module.Registry.getDesktop(0)
        matches = [child for child in desktop if getattr(child, "name", None) == name]
        if len(matches) != 1:
            raise FormatError(
                "SOVA-ATSPI-APPLICATION",
                "exactly one admitted application must be present",
            )
        return matches[0]

    def _node(self, accessible: Any, *, depth: int, count: list[int]) -> _AccessibleNode:
        if depth > _MAX_DEPTH or count[0] >= _MAX_NODES:
            raise FormatError("SOVA-ATSPI-LIMIT", "AT-SPI tree exceeds configured bounds")
        count[0] += 1
        role = str(accessible.getRoleName())
        name = str(getattr(accessible, "name", ""))
        states: tuple[str, ...] = ()
        try:
            raw_states = accessible.getState().getStates()
            states = tuple(sorted(str(item) for item in raw_states))
        except (AttributeError, RuntimeError):
            states = ("state-unavailable",)
        children = tuple(self._node(child, depth=depth + 1, count=count) for child in accessible)
        return _AccessibleNode(role, name, states, children)

    def snapshot(self, application: str) -> dict[str, Any]:
        return self._node(self._application(application), depth=0, count=[0]).to_mapping()

    def _find(self, application: str, role: str, name: str) -> Any:
        pending = [self._application(application)]
        matches: list[Any] = []
        visited = 0
        while pending:
            accessible = pending.pop()
            visited += 1
            if visited > _MAX_NODES:
                raise FormatError("SOVA-ATSPI-LIMIT", "AT-SPI search exceeds configured bounds")
            accessible_role = str(accessible.getRoleName())
            accessible_name = str(getattr(accessible, "name", ""))
            if accessible_role == role and accessible_name == name:
                matches.append(accessible)
            pending.extend(accessible)
        if len(matches) != 1:
            raise FormatError("SOVA-ATSPI-LOCATOR", "accessibility locator is absent or ambiguous")
        return matches[0]

    def activate(self, application: str, role: str, name: str) -> None:
        action = self._find(application, role, name).queryAction()
        for index in range(action.nActions):
            if action.getName(index).casefold() in {"click", "press", "activate"}:
                if action.doAction(index) is not True:
                    raise FormatError("SOVA-ATSPI-ACTION", "AT-SPI action was refused")
                return
        raise FormatError("SOVA-ATSPI-ACTION", "element exposes no admitted activation action")

    def set_text(self, application: str, role: str, name: str, text: str) -> None:
        editable = self._find(application, role, name).queryEditableText()
        if editable.setTextContents(text) is not True:
            raise FormatError("SOVA-ATSPI-ACTION", "AT-SPI text mutation was refused")


def _locator(inputs: dict[str, Any]) -> tuple[str, str]:
    if set(inputs) - {"role", "name", "text"}:
        raise FormatError("SOVA-ATSPI-INPUT", "AT-SPI action contains unsupported fields")
    role = inputs.get("role")
    name = inputs.get("name")
    if not isinstance(role, str) or not role or not isinstance(name, str) or not name:
        raise FormatError("SOVA-ATSPI-LOCATOR", "AT-SPI action requires exact role and name")
    return role, name


def _text(inputs: dict[str, Any]) -> str:
    text = inputs.get("text")
    if not isinstance(text, str) or len(text.encode()) > _MAX_TEXT_BYTES:
        raise FormatError(
            "SOVA-ATSPI-TEXT",
            "AT-SPI text is absent or exceeds 64 KiB",
        )
    return text


class AtSpiDesktopExecutor:
    """Run exact accessibility actions against one named Linux application."""

    name = "sova-linux-atspi"

    def __init__(self, application: str, *, backend: AtSpiBackend | None = None) -> None:
        if not application or len(application.encode()) > _MAX_APPLICATION_BYTES:
            raise FormatError("SOVA-ATSPI-APPLICATION", "application name is invalid")
        self._application = application
        self._backend = backend or PyAtSpiBackend()

    def capabilities(self) -> tuple[Capability, ...]:
        return (
            Capability(
                name="computer.snapshot",
                version="0.1",
                side_effect=SideEffect.READ,
                idempotent=True,
                evidence=("atspi-tree",),
            ),
            Capability(
                name="computer.click",
                version="0.1",
                side_effect=SideEffect.MUTATE,
                idempotent=False,
                evidence=("atspi-tree-before", "atspi-tree-after"),
            ),
            Capability(
                name="computer.type",
                version="0.1",
                side_effect=SideEffect.MUTATE,
                idempotent=False,
                evidence=("atspi-tree-before", "atspi-tree-after"),
            ),
        )

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        del context
        effect = {
            "computer.snapshot": SideEffect.READ,
            "computer.click": SideEffect.MUTATE,
            "computer.type": SideEffect.MUTATE,
        }.get(request.action)
        if effect is None:
            return ActionOutcome(request.id, OutcomeStatus.UNSUPPORTED, SideEffect.READ, {})
        if cancellation.cancelled:
            return ActionOutcome(request.id, OutcomeStatus.CANCELLED, effect, {})
        try:
            before = canonical_json_bytes(self._backend.snapshot(self._application))
            if request.action != "computer.snapshot":
                role, name = _locator(request.inputs)
                if request.action == "computer.click":
                    self._backend.activate(self._application, role, name)
                else:
                    text = _text(request.inputs)
                    self._backend.set_text(self._application, role, name, text)
            after = canonical_json_bytes(self._backend.snapshot(self._application))
            before_digest = sha256_digest(before)
            after_digest = sha256_digest(after)
            return ActionOutcome(
                request_id=request.id,
                status=OutcomeStatus.SUCCEEDED,
                side_effect=effect,
                output={
                    "platform": "linux",
                    "applicationBound": True,
                    "beforeDigest": before_digest,
                    "afterDigest": after_digest,
                    "postObservationCaptured": True,
                },
                evidence=(
                    EvidenceReference(
                        "atspi-tree-before", "application/json", before_digest, len(before)
                    ),
                    EvidenceReference(
                        "atspi-tree-after", "application/json", after_digest, len(after)
                    ),
                ),
                verification="atspi-dbus-post-action-accessibility-snapshot",
                retryable=False,
                error_code=None,
                limitations=(
                    "AT-SPI and the application accessibility tree are observation sources.",
                    "The host desktop and D-Bus session are not a security sandbox.",
                    "No coordinate-only fallback, shell, or unrestricted process control "
                    "is enabled.",
                ),
                failure_cause=FailureCause.NONE,
            )
        except FormatError as error:
            return ActionOutcome(
                request.id,
                OutcomeStatus.FAILED,
                effect,
                {},
                error_code=error.issue.code,
                limitations=("AT-SPI provider error details are omitted from evidence.",),
                failure_cause=FailureCause.EXECUTOR,
            )


__all__ = ["AtSpiBackend", "AtSpiDesktopExecutor", "PyAtSpiBackend"]
