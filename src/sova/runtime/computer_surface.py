# SPDX-License-Identifier: Apache-2.0
"""Session-bound computer executor and redacted reviewed-target observation surface.

This module deliberately does not discover ambient desktops.  A trusted adapter
host supplies one exact application/window executor plus a snapshot callback.
The callback's target list is converted into immutable reviewed locators before
planner output can select it.
"""

from __future__ import annotations

import copy
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from sova.executors import ActionOutcome, ActionRequest, CancellationToken
from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError
from sova.runtime.action_codecs import (
    ComputerActionCodec,
    ComputerIdentityBinding,
    ReviewedComputerTarget,
)
from sova.trace import Redactor

if TYPE_CHECKING:
    from pathlib import Path

    from sova.executors import Capability, ExecutionContext, Executor
    from sova.runtime.target_environment import SessionEnvelope, TargetInstance

_MAX_PROJECTION_BYTES = 256 * 1024
_MAX_TARGETS = 2_000
_READ_ACTION = {"application": "computer.snapshot", "window": "computer.inspect"}
#: The full reviewed computer mutation algebra a backend may advertise.
_ADMITTED_MUTATIONS = frozenset(
    {"computer.click", "computer.type", "computer.scroll", "computer.drag", "computer.key"}
)
_ADMITTED_ACTIONS = frozenset({"computer.snapshot", "computer.inspect", *_ADMITTED_MUTATIONS})
#: A backend that declares no explicit mutation set gets the historical default;
#: this keeps every existing caller (click + type only) byte-for-byte unchanged.
_DEFAULT_MUTATIONS = ("computer.click", "computer.type")


@dataclass(frozen=True, slots=True)
class ComputerSurfaceSnapshot:
    """Trusted adapter snapshot before redaction and planner exposure."""

    projection: Mapping[str, Any]
    reviewed_targets: tuple[ReviewedComputerTarget, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.projection, Mapping):
            raise FormatError(
                "SOVA-COMPUTER-SURFACE-OBSERVATION",
                "computer snapshot projection must be an object",
            )
        if (
            not isinstance(self.reviewed_targets, tuple)
            or len(self.reviewed_targets) > _MAX_TARGETS
            or any(type(target) is not ReviewedComputerTarget for target in self.reviewed_targets)
            or len({target.reference for target in self.reviewed_targets})
            != len(self.reviewed_targets)
        ):
            raise FormatError(
                "SOVA-COMPUTER-SURFACE-TARGET",
                "computer snapshot reviewed targets are malformed or duplicated",
            )


ComputerSnapshotCallback = Callable[[], ComputerSurfaceSnapshot]
ComputerCleanup = Callable[[], None]


def _canonical_capabilities(executor: Executor) -> tuple[Capability, ...]:
    capabilities = executor.capabilities()
    if not isinstance(capabilities, tuple) or not capabilities:
        raise FormatError(
            "SOVA-COMPUTER-SURFACE-CAPABILITY",
            "computer executor has no immutable capability inventory",
        )
    ordered = tuple(sorted(capabilities, key=lambda item: item.identifier))
    identifiers = [item.identifier for item in ordered]
    if len(identifiers) != len(set(identifiers)) or any(
        item.name not in _ADMITTED_ACTIONS for item in ordered
    ):
        raise FormatError(
            "SOVA-COMPUTER-SURFACE-CAPABILITY",
            "computer executor capability inventory is duplicated or outside the reviewed algebra",
        )
    return ordered


class _BoundComputerExecutor:
    def __init__(self, surface: ManagedComputerSurface) -> None:
        self.__surface = surface

    @property
    def name(self) -> str:
        return self.__surface.name

    def capabilities(self) -> tuple[Capability, ...]:
        return self.__surface.capabilities()

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        return self.__surface._dispatch(request, context, cancellation)


class ManagedComputerSurface:
    """Bind one exact application/window executor to one SOVA session generation."""

    def __init__(  # noqa: PLR0913
        self,
        *,
        executor: Executor,
        kind: Literal["application", "window"],
        identity_digest: str,
        snapshot: ComputerSnapshotCallback,
        pid: int | None = None,
        window_id: int | None = None,
        cleanup: ComputerCleanup | None = None,
        redactor: Redactor | None = None,
        mutations: tuple[str, ...] = _DEFAULT_MUTATIONS,
    ) -> None:
        if not isinstance(kind, str) or kind not in _READ_ACTION or not callable(snapshot):
            raise FormatError(
                "SOVA-COMPUTER-SURFACE-CONFIG",
                "computer surface requires an application/window kind and snapshot callback",
            )
        if (
            not isinstance(mutations, tuple)
            or not mutations
            or len(set(mutations)) != len(mutations)
            or any(item not in _ADMITTED_MUTATIONS for item in mutations)
        ):
            raise FormatError(
                "SOVA-COMPUTER-SURFACE-CAPABILITY",
                "computer surface mutation set must be a unique non-empty subset of the "
                "reviewed algebra (click, type, scroll, drag, key)",
            )
        # Validate the identity shape before a target/session exists.  The
        # placeholder digest is replaced with the exact session digest at bind.
        ComputerIdentityBinding(kind, "sha256:" + "0" * 64, identity_digest, pid, window_id)
        capabilities = _canonical_capabilities(executor)
        actions = {item.name for item in capabilities}
        # The backend must advertise EXACTLY the one observation action plus the
        # declared mutation set -- no more, no less.  This preserves the
        # no-silent-substitution guarantee while allowing an operator to admit a
        # wider reviewed algebra than click/type.
        required = {_READ_ACTION[kind], *mutations}
        if actions != required:
            raise FormatError(
                "SOVA-COMPUTER-SURFACE-CAPABILITY",
                "computer surface requires exactly its one observation action plus its "
                "declared reviewed mutation set",
                details={
                    "missing": sorted(required - actions),
                    "extra": sorted(actions - required),
                },
            )
        name = executor.name
        if not isinstance(name, str) or not name:
            raise FormatError(
                "SOVA-COMPUTER-SURFACE-EXECUTOR",
                "computer executor name is invalid",
            )
        if cleanup is not None and not callable(cleanup):
            raise FormatError(
                "SOVA-COMPUTER-SURFACE-CLEANUP",
                "computer cleanup callback is invalid",
            )
        self.__delegate = executor
        self.__capabilities = capabilities
        self.__capability_digest = sha256_digest(
            canonical_json_bytes([item.identifier for item in capabilities])
        )
        self.__name = f"sova-managed-computer:{name}"
        self.__kind = kind
        self.__identity_digest = identity_digest
        self.__pid = pid
        self.__window_id = window_id
        self.__snapshot = snapshot
        self.__cleanup = cleanup
        self.__redactor = redactor or Redactor(context_id=f"computer:{identity_digest}")
        self.__workspace: Path | None = None
        self.__workspace_identity: tuple[int, int] | None = None
        self.__session_digest: str | None = None
        self.__executor: Executor = _BoundComputerExecutor(self)
        self.__closed = False
        self.__cleanup_complete = False
        self.__lock = threading.RLock()

    @property
    def name(self) -> str:
        return self.__name

    @property
    def executor(self) -> Executor:
        return self.__executor

    @property
    def identity_digest(self) -> str:
        return self.__identity_digest

    @property
    def closed(self) -> bool:
        with self.__lock:
            return self.__closed

    @property
    def cleanup_complete(self) -> bool:
        with self.__lock:
            return self.__cleanup_complete

    def capabilities(self) -> tuple[Capability, ...]:
        return self.__capabilities

    @staticmethod
    def _is_link_or_junction(path: Path) -> bool:
        return path.is_symlink() or getattr(path, "is_junction", lambda: False)()

    def bind(self, session: SessionEnvelope, target: TargetInstance, workspace: Path) -> None:
        with self.__lock:
            if self.__closed or self.__workspace is not None:
                raise FormatError(
                    "SOVA-COMPUTER-SURFACE-AFFINITY",
                    "computer surface is closed or already bound",
                )
            session.assert_target(target)
            if session.identity_digest != self.__identity_digest:
                raise FormatError(
                    "SOVA-COMPUTER-SURFACE-IDENTITY",
                    "computer identity differs from the admitted session identity",
                )
            if self.__kind == "window" and (
                target.process_id != self.__pid or target.window_handle_digest is None
            ):
                raise FormatError(
                    "SOVA-COMPUTER-SURFACE-IDENTITY",
                    "computer window differs from the admitted target process/window generation",
                )
            if self._is_link_or_junction(workspace):
                raise FormatError(
                    "SOVA-COMPUTER-SURFACE-WORKSPACE",
                    "computer surface workspace cannot be a link or junction",
                )
            try:
                resolved = workspace.resolve(strict=True)
                workspace_stat = resolved.stat()
            except (OSError, RuntimeError) as error:
                raise FormatError(
                    "SOVA-COMPUTER-SURFACE-WORKSPACE",
                    "computer surface workspace is unavailable",
                ) from error
            if not resolved.is_dir():
                raise FormatError(
                    "SOVA-COMPUTER-SURFACE-WORKSPACE",
                    "computer surface requires a real disposable workspace",
                )
            self.__workspace = resolved
            self.__workspace_identity = (workspace_stat.st_dev, workspace_stat.st_ino)
            self.__session_digest = session.digest

    def _binding(self) -> ComputerIdentityBinding:
        session_digest = self.__session_digest
        if session_digest is None:
            raise FormatError(
                "SOVA-COMPUTER-SURFACE-AFFINITY",
                "computer surface is not session-bound",
            )
        return ComputerIdentityBinding(
            self.__kind,
            session_digest,
            self.__identity_digest,
            self.__pid,
            self.__window_id,
        )

    def _assert_inventory(self) -> None:
        actual = _canonical_capabilities(self.__delegate)
        actual_digest = sha256_digest(canonical_json_bytes([item.identifier for item in actual]))
        if actual != self.__capabilities or actual_digest != self.__capability_digest:
            raise FormatError(
                "SOVA-COMPUTER-SURFACE-CAPABILITY-SUBSTITUTION",
                "computer executor capability generation changed after admission",
            )

    def _bound_workspace(self) -> tuple[Path, str]:
        workspace = self.__workspace
        identity = self.__workspace_identity
        session_digest = self.__session_digest
        if self.__closed or workspace is None or identity is None or session_digest is None:
            raise FormatError(
                "SOVA-COMPUTER-SURFACE-AFFINITY",
                "computer surface is closed or unbound",
            )
        if self._is_link_or_junction(workspace):
            raise FormatError(
                "SOVA-COMPUTER-SURFACE-WORKSPACE",
                "computer surface workspace identity is no longer valid",
            )
        try:
            resolved = workspace.resolve(strict=True)
            workspace_stat = workspace.stat()
        except (OSError, RuntimeError) as error:
            raise FormatError(
                "SOVA-COMPUTER-SURFACE-WORKSPACE",
                "computer surface workspace identity is no longer valid",
            ) from error
        if (
            resolved != workspace
            or not workspace.is_dir()
            or (workspace_stat.st_dev, workspace_stat.st_ino) != identity
        ):
            raise FormatError(
                "SOVA-COMPUTER-SURFACE-WORKSPACE",
                "computer surface workspace identity is no longer valid",
            )
        return workspace, session_digest

    def _dispatch(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        with self.__lock:
            workspace, session_digest = self._bound_workspace()
            try:
                context_workspace = context.workspace.resolve(strict=True)
            except (OSError, RuntimeError) as error:
                raise FormatError(
                    "SOVA-COMPUTER-SURFACE-WORKSPACE",
                    "computer execution workspace is unavailable",
                ) from error
            if (
                context_workspace != workspace
                or context.environment.get("sessionDigest") != session_digest
                or context.authorization.get("decision") != "allowed"
            ):
                raise FormatError(
                    "SOVA-COMPUTER-SURFACE-AFFINITY",
                    "computer execution escaped its allowed session/workspace grant",
                )
            capability = next(
                (item for item in self.__capabilities if item.name == request.action),
                None,
            )
            if capability is None:
                raise FormatError(
                    "SOVA-COMPUTER-SURFACE-CAPABILITY",
                    "computer action is outside the reviewed capability generation",
                )
            self._assert_inventory()
            outcome = self.__delegate.execute(copy.deepcopy(request), context, cancellation)
            self._assert_inventory()
            if (
                type(outcome) is not ActionOutcome
                or outcome.request_id != request.id
                or outcome.side_effect != capability.side_effect
            ):
                raise FormatError(
                    "SOVA-COMPUTER-SURFACE-OUTCOME-SUBSTITUTION",
                    "computer executor changed request or side-effect identity",
                )
            return outcome

    def observe(self) -> Mapping[str, Any]:
        """Return a detached, redacted projection and exact selectable target set."""
        with self.__lock:
            self._bound_workspace()
            self._assert_inventory()
            try:
                snapshot = self.__snapshot()
            except Exception as error:
                raise FormatError(
                    "SOVA-COMPUTER-SURFACE-OBSERVATION",
                    "trusted computer observation failed without exposing target details",
                ) from error
            if type(snapshot) is not ComputerSurfaceSnapshot:
                raise FormatError(
                    "SOVA-COMPUTER-SURFACE-OBSERVATION",
                    "trusted computer observation returned another contract type",
                )
            ComputerActionCodec(
                self._binding(),
                "sha256:" + "0" * 64,
                snapshot.reviewed_targets,
            )
            projection, records = self.__redactor.redact(dict(snapshot.projection))
            targets = [
                {
                    "reference": target.reference,
                    "actions": list(target.actions),
                    "locator": target.canonical_locator(),
                }
                for target in snapshot.reviewed_targets
            ]
            document = {
                "binding": self._binding().to_mapping(),
                "ui": projection,
                "reviewedTargets": targets,
                "redactionCount": len(records),
            }
            encoded = canonical_json_bytes(document)
            if len(encoded) > _MAX_PROJECTION_BYTES:
                raise FormatError(
                    "SOVA-COMPUTER-SURFACE-LIMIT",
                    "redacted computer observation exceeds 256 KiB",
                )
            detached = strict_json_loads(encoded, max_bytes=_MAX_PROJECTION_BYTES)
            if not isinstance(detached, dict):  # pragma: no cover - source is an object
                raise TypeError
            return detached

    def close(self) -> None:
        with self.__lock:
            if self.__closed:
                if not self.__cleanup_complete:
                    raise FormatError(
                        "SOVA-COMPUTER-SURFACE-CLEANUP",
                        "computer surface is closed but cleanup was not verified",
                    )
                return
            self.__closed = True
            failures = 0
            callbacks: list[ComputerCleanup] = []
            close = getattr(self.__delegate, "close", None)
            if callable(close):
                callbacks.append(close)
            if self.__cleanup is not None and self.__cleanup not in callbacks:
                callbacks.append(self.__cleanup)
            for callback in callbacks:
                try:
                    callback()
                except Exception:  # noqa: BLE001 - target details remain private
                    failures += 1
            self.__cleanup_complete = failures == 0
            if failures:
                raise FormatError(
                    "SOVA-COMPUTER-SURFACE-CLEANUP",
                    "computer surface cleanup could not be verified",
                )


__all__ = [
    "ComputerCleanup",
    "ComputerSnapshotCallback",
    "ComputerSurfaceSnapshot",
    "ManagedComputerSurface",
]
