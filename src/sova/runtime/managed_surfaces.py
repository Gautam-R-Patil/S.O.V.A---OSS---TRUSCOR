# SPDX-License-Identifier: Apache-2.0
"""Managed executor surfaces and independent observation policies for SOVA.

The lazy stdio wrapper starts a pinned MCP backend only after the chamber owns
its disposable workspace.  It advertises a reviewed static capability contract
up front, then fails closed unless the live backend exposes that exact contract.
Planner models never receive this wrapper, its client, process id, or workspace.
"""

from __future__ import annotations

import copy
import re
import threading
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Self

from sova.executors import (
    ActionOutcome,
    ActionRequest,
    CancellationToken,
    Capability,
    ExecutionContext,
    Executor,
    OutcomeStatus,
    SideEffect,
)
from sova.formats import canonical_json_bytes, strict_json_loads
from sova.formats.errors import FormatError
from sova.live.startup import start_stdio_client
from sova.mcp.protocol import MCPClient, StdioMCPClient, StdioServerSpec

if TYPE_CHECKING:
    from collections.abc import Sequence

    from sova.community.executor_chamber import ChamberObservation, ChamberVerification
    from sova.runtime.unified_execution import CapabilityBinding

_MAX_OBSERVATION_BYTES = 256 * 1024
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")

ServerSpecFactory = Callable[[Path], StdioServerSpec]
ExecutorAdapterFactory = Callable[[MCPClient], Executor]
ObservationSensor = Callable[[], Mapping[str, Any]]


def _capability_mapping(capability: Capability) -> dict[str, Any]:
    return {
        "name": capability.name,
        "version": capability.version,
        "sideEffect": capability.side_effect.value,
        "idempotent": capability.idempotent,
        "evidence": list(capability.evidence),
    }


def _canonical_capabilities(values: Sequence[Capability]) -> tuple[Capability, ...]:
    if not values or any(type(item) is not Capability for item in values):
        raise FormatError(
            "SOVA-MANAGED-SURFACE-CAPABILITY",
            "managed surface requires an exact non-empty Capability inventory",
        )
    ordered = tuple(sorted(values, key=lambda item: item.identifier))
    if len({item.identifier for item in ordered}) != len(ordered):
        raise FormatError(
            "SOVA-MANAGED-SURFACE-CAPABILITY",
            "managed surface capability identifier is duplicated",
        )
    if len({item.name for item in ordered}) != len(ordered):
        raise FormatError(
            "SOVA-MANAGED-SURFACE-CAPABILITY",
            "managed surface cannot dispatch multiple versions of one action",
        )
    canonical_json_bytes([_capability_mapping(item) for item in ordered])
    return ordered


def _assert_live_capabilities(
    actual: tuple[Capability, ...],
    expected: tuple[Capability, ...],
) -> None:
    if actual != expected:
        raise FormatError(
            "SOVA-MANAGED-SURFACE-CAPABILITY-SUBSTITUTION",
            "live backend capability inventory differs from its reviewed contract",
        )


class LazyStdioExecutor:
    """Launch one pinned stdio backend on first trusted observe/execute call."""

    def __init__(
        self,
        *,
        name: str,
        capabilities: tuple[Capability, ...],
        spec_factory: ServerSpecFactory,
        adapter_factory: ExecutorAdapterFactory,
    ) -> None:
        if not name or not callable(spec_factory) or not callable(adapter_factory):
            raise FormatError(
                "SOVA-MANAGED-SURFACE",
                "managed surface name and factories are required",
            )
        self._name = name
        self._capabilities = _canonical_capabilities(capabilities)
        self._spec_factory = spec_factory
        self._adapter_factory = adapter_factory
        self._workspace: Path | None = None
        self._session_digest: str | None = None
        self._client: MCPClient | None = None
        self._adapter: Executor | None = None
        self._lock = threading.RLock()
        self._closed = False
        self._cleanup_complete = False

    @property
    def name(self) -> str:
        return self._name

    @property
    def started(self) -> bool:
        with self._lock:
            return self._adapter is not None

    @property
    def process_id(self) -> int | None:
        with self._lock:
            client = self._client
            value = None if client is None else getattr(client, "process_id", None)
            return value if isinstance(value, int) and value > 0 else None

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    @property
    def cleanup_complete(self) -> bool:
        with self._lock:
            return self._cleanup_complete

    def capabilities(self) -> tuple[Capability, ...]:
        return self._capabilities

    def _ensure_started(  # noqa: PLR0912 - startup validates every owned trust boundary
        self,
        workspace: Path,
        *,
        session_digest: str | None = None,
    ) -> Executor:
        with self._lock:
            if self._closed:
                raise FormatError(
                    "SOVA-MANAGED-SURFACE-CLOSED",
                    "managed surface is already closed",
                )
            if workspace.is_symlink():
                raise FormatError(
                    "SOVA-MANAGED-SURFACE-WORKSPACE",
                    "managed surface workspace cannot be a symbolic link",
                )
            try:
                resolved = workspace.resolve(strict=True)
            except OSError as error:
                raise FormatError(
                    "SOVA-MANAGED-SURFACE-WORKSPACE",
                    "managed surface workspace does not resolve to an existing directory",
                ) from error
            if not resolved.is_dir():
                raise FormatError(
                    "SOVA-MANAGED-SURFACE-WORKSPACE",
                    "managed surface requires one real existing workspace",
                )
            if self._workspace is not None and self._workspace != resolved:
                raise FormatError(
                    "SOVA-MANAGED-SURFACE-AFFINITY",
                    "managed surface cannot move to another workspace generation",
                )
            if session_digest is not None:
                if _DIGEST.fullmatch(session_digest) is None:
                    raise FormatError(
                        "SOVA-MANAGED-SURFACE-SESSION",
                        "managed surface requires an exact canonical session digest",
                    )
                if self._session_digest is not None and self._session_digest != session_digest:
                    raise FormatError(
                        "SOVA-MANAGED-SURFACE-AFFINITY",
                        "managed surface cannot move to another session generation",
                    )
            if self._adapter is not None:
                self._assert_adapter_capabilities(self._adapter)
                if self._session_digest is None:
                    self._session_digest = session_digest
                return self._adapter
            spec = self._spec_factory(resolved)
            try:
                spec_workspace = spec.cwd.resolve(strict=True)
            except OSError as error:
                raise FormatError(
                    "SOVA-MANAGED-SURFACE-WORKSPACE",
                    "managed stdio specification has an inaccessible working directory",
                ) from error
            if spec.cwd.is_symlink() or spec_workspace != resolved:
                raise FormatError(
                    "SOVA-MANAGED-SURFACE-AFFINITY",
                    "managed stdio specification escaped its bound workspace",
                )
            client: MCPClient | None = None
            adapter: Executor | None = None
            try:
                client = start_stdio_client(spec, StdioMCPClient)
                adapter = self._adapter_factory(client)
                actual = _canonical_capabilities(adapter.capabilities())
                _assert_live_capabilities(actual, self._capabilities)
            except Exception:
                if adapter is not None:
                    close = getattr(adapter, "close", None)
                    if callable(close):
                        with suppress(Exception):
                            close()
                if client is not None:
                    with suppress(Exception):
                        client.close()
                raise
            self._workspace = resolved
            self._session_digest = session_digest
            self._client = client
            self._adapter = adapter
            return adapter

    def _assert_adapter_capabilities(self, adapter: Executor) -> None:
        actual = _canonical_capabilities(adapter.capabilities())
        _assert_live_capabilities(actual, self._capabilities)

    def _assert_outcome(
        self,
        request: ActionRequest,
        outcome: ActionOutcome,
        capability: Capability,
    ) -> None:
        if type(outcome) is not ActionOutcome or (
            outcome.request_id != request.id or outcome.side_effect != capability.side_effect
        ):
            raise FormatError(
                "SOVA-MANAGED-SURFACE-OUTCOME-SUBSTITUTION",
                "managed backend outcome changed request or side-effect identity",
            )

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        session_digest = context.environment.get("sessionDigest")
        if not isinstance(session_digest, str):
            raise FormatError(
                "SOVA-MANAGED-SURFACE-SESSION",
                "managed executor dispatch requires a bound session digest",
            )
        capability = next(
            (item for item in self._capabilities if item.name == request.action),
            None,
        )
        if capability is None:
            raise FormatError(
                "SOVA-MANAGED-SURFACE-CAPABILITY",
                "request action is outside the reviewed capability inventory",
            )
        with self._lock:
            adapter = self._ensure_started(
                context.workspace,
                session_digest=session_digest,
            )
            outcome = adapter.execute(copy.deepcopy(request), context, cancellation)
            self._assert_adapter_capabilities(adapter)
            self._assert_outcome(request, outcome, capability)
            return outcome

    def trusted_observe(
        self,
        *,
        workspace: Path,
        action: str,
        inputs: Mapping[str, Any],
        timeout_seconds: float = 20.0,
    ) -> ActionOutcome:
        """Invoke one declared read capability from trusted coordinator space."""
        capability = next((item for item in self._capabilities if item.name == action), None)
        if capability is None or capability.side_effect != SideEffect.READ:
            raise FormatError(
                "SOVA-MANAGED-SURFACE-OBSERVATION",
                "trusted observation requires a declared read-only capability",
            )
        with self._lock:
            adapter = self._ensure_started(workspace)
            bound_workspace = self._workspace
            if bound_workspace is None:  # pragma: no cover - startup establishes this
                raise TypeError
            request = ActionRequest(
                f"trusted-observation:{action.replace('.', '-')}",
                action,
                strict_json_loads(canonical_json_bytes(dict(inputs))),
                timeout_seconds,
            )
            context = ExecutionContext(
                bound_workspace,
                {
                    "decision": "allowed",
                    "scopeDigest": "sha256:" + "0" * 64,
                    "decidedBy": "sova.managed-surface-observer/0.1",
                },
            )
            outcome = adapter.execute(request, context, CancellationToken())
            self._assert_adapter_capabilities(adapter)
            self._assert_outcome(request, outcome, capability)
            if outcome.status != OutcomeStatus.SUCCEEDED:
                raise FormatError(
                    "SOVA-MANAGED-SURFACE-OBSERVATION",
                    "trusted surface observation did not succeed",
                )
            return outcome

    def coordinator_client(
        self,
        *,
        workspace: Path,
        session_digest: str,
    ) -> MCPClient:
        """Return the live client only to the trusted surface coordinator.

        Planner models and action codecs never receive this object.  This
        narrow escape hatch exists for backend lifecycle operations such as
        starting/stopping evidence recording that are intentionally absent
        from the model-visible capability inventory.
        """
        with self._lock:
            self._ensure_started(workspace, session_digest=session_digest)
            if self._client is None:  # pragma: no cover - startup establishes it
                raise TypeError
            return self._client

    def close(self) -> None:
        with self._lock:
            if self._closed:
                if not self._cleanup_complete:
                    raise FormatError(
                        "SOVA-MANAGED-SURFACE-CLEANUP",
                        "managed surface is closed but cleanup was not verified",
                    )
                return
            self._closed = True
            adapter = self._adapter
            client = self._client
            self._adapter = None
            self._client = None
            failures = 0
            if adapter is not None:
                close = getattr(adapter, "close", None)
                if callable(close):
                    try:
                        close()
                    except Exception:  # noqa: BLE001 - cleanup details remain private
                        failures += 1
            if client is not None:
                try:
                    client.close()
                except Exception:  # noqa: BLE001 - cleanup details remain private
                    failures += 1
            self._cleanup_complete = failures == 0
            if failures:
                raise FormatError(
                    "SOVA-MANAGED-SURFACE-CLEANUP",
                    "managed surface cleanup could not be verified",
                )

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class CompositeObservationSource:
    """Capture a deterministic detached projection from multiple trusted sensors."""

    def __init__(self, sensors: Mapping[str, ObservationSensor]) -> None:
        if not sensors or any(
            not isinstance(key, str) or not key or not callable(value)
            for key, value in sensors.items()
        ):
            raise FormatError(
                "SOVA-MANAGED-OBSERVATION",
                "composite observation requires named trusted sensors",
            )
        self._sensors = MappingProxyType(dict(sorted(sensors.items())))

    def __call__(self) -> Mapping[str, Any]:
        projection: dict[str, Any] = {}
        for name, sensor in self._sensors.items():
            try:
                value = sensor()
            except Exception as error:
                raise FormatError(
                    "SOVA-MANAGED-OBSERVATION",
                    "trusted observation sensor failed without exposing target details",
                ) from error
            if not isinstance(value, Mapping):
                raise FormatError(
                    "SOVA-MANAGED-OBSERVATION",
                    "trusted observation sensor returned a non-object value",
                )
            projection[name] = dict(value)
        encoded = canonical_json_bytes(projection)
        if len(encoded) > _MAX_OBSERVATION_BYTES:
            raise FormatError(
                "SOVA-MANAGED-OBSERVATION-LIMIT",
                "composite observation exceeds 256 KiB",
            )
        detached = strict_json_loads(encoded, max_bytes=_MAX_OBSERVATION_BYTES)
        if not isinstance(detached, dict):  # pragma: no cover - projection is a dict
            raise TypeError
        return detached


@dataclass(frozen=True, slots=True)
class EvidenceSatisfactionPolicy:
    """Independent conditions for satisfying one capability evidence contract."""

    capability: str
    satisfied_evidence: tuple[str, ...]
    required_projection_paths: tuple[tuple[str, ...], ...] = ()
    required_output_keys: tuple[str, ...] = ()
    require_observation_change: bool = False
    independence: str = "agent-independent"

    def __post_init__(self) -> None:
        if (
            not isinstance(self.capability, str)
            or not self.capability
            or not self.satisfied_evidence
            or any(not isinstance(label, str) or not label for label in self.satisfied_evidence)
            or len(set(self.satisfied_evidence)) != len(self.satisfied_evidence)
            or not isinstance(self.require_observation_change, bool)
            or self.independence not in {"agent-independent", "cross-executor"}
        ):
            raise FormatError(
                "SOVA-EVIDENCE-POLICY",
                "evidence satisfaction policy is invalid",
            )
        if any(
            not isinstance(path, tuple)
            or not path
            or any(not isinstance(item, str) or not item for item in path)
            for path in self.required_projection_paths
        ) or len(set(self.required_projection_paths)) != len(self.required_projection_paths):
            raise FormatError(
                "SOVA-EVIDENCE-POLICY",
                "evidence projection path is invalid",
            )
        if any(not isinstance(key, str) or not key for key in self.required_output_keys) or len(
            set(self.required_output_keys)
        ) != len(self.required_output_keys):
            raise FormatError(
                "SOVA-EVIDENCE-POLICY",
                "evidence output-key contract is invalid",
            )
        satisfied = tuple(sorted(self.satisfied_evidence))
        projection_paths = tuple(sorted(self.required_projection_paths))
        output_keys = tuple(sorted(self.required_output_keys))
        object.__setattr__(self, "satisfied_evidence", satisfied)
        object.__setattr__(self, "required_projection_paths", projection_paths)
        object.__setattr__(self, "required_output_keys", output_keys)


def _path_present(value: Mapping[str, Any], path: tuple[str, ...]) -> bool:
    current: object = value
    for segment in path:
        if not isinstance(current, Mapping) or segment not in current:
            return False
        current = current[segment]
    return current is not None


class PolicyEvidenceVerifier:
    """Verify adapter outcomes through explicit output and fresh-state obligations."""

    def __init__(
        self,
        policies: tuple[EvidenceSatisfactionPolicy, ...],
        *,
        backend_ids: tuple[str, ...] | None = None,
    ) -> None:
        capability_unique = len({item.capability for item in policies}) == len(policies)
        backend_bound = (
            isinstance(backend_ids, tuple)
            and len(backend_ids) == len(policies)
            and all(isinstance(item, str) and item for item in backend_ids)
            and len(set(zip(backend_ids, (item.capability for item in policies), strict=True)))
            == len(policies)
        )
        if (
            not policies
            or (backend_ids is None and not capability_unique)
            or (backend_ids is not None and not backend_bound)
        ):
            raise FormatError(
                "SOVA-EVIDENCE-POLICY",
                "evidence policies must be non-empty and capability or backend-capability unique",
            )
        self._policies = MappingProxyType({item.capability: item for item in policies})
        self._bound_policies = MappingProxyType(
            {}
            if backend_ids is None
            else {
                (backend_id, policy.capability): policy
                for backend_id, policy in zip(backend_ids, policies, strict=True)
            }
        )

    def __call__(
        self,
        request: ActionRequest,
        outcome: ActionOutcome,
        binding: CapabilityBinding,
        before: ChamberObservation,
        after: ChamberObservation,
    ) -> ChamberVerification:
        from sova.community.executor_chamber import ChamberVerification  # noqa: PLC0415

        del request
        policy = self._bound_policies.get(
            (binding.backend_id, binding.capability_identifier)
        ) or self._policies.get(binding.capability_identifier)
        if policy is None:
            raise FormatError(
                "SOVA-EVIDENCE-POLICY",
                "capability has no independent evidence policy",
            )
        labels_match = tuple(sorted(policy.satisfied_evidence)) == binding.expected_evidence
        projections_present = all(
            _path_present(after.projection, path) for path in policy.required_projection_paths
        )
        outputs_present = all(key in outcome.output for key in policy.required_output_keys)
        observation_condition = (
            not policy.require_observation_change
            or before.version.content_digest != after.version.content_digest
        )
        verified = bool(
            outcome.status == OutcomeStatus.SUCCEEDED
            and labels_match
            and projections_present
            and outputs_present
            and observation_condition
        )
        limitations: list[str] = []
        if not labels_match:
            limitations.append("Evidence policy does not exactly match the capability contract.")
        if not projections_present:
            limitations.append("Required fresh projection fields were absent.")
        if not outputs_present:
            limitations.append("Required normalized outcome fields were absent.")
        if not observation_condition:
            limitations.append("Required fresh observation change was not established.")
        return ChamberVerification(
            verified=verified,
            independence=policy.independence,
            method="sova-explicit-output-and-fresh-observation-policy/0.1",
            evidence_digests=(after.version.content_digest,),
            satisfied_evidence=policy.satisfied_evidence if verified else (),
            limitations=tuple(limitations),
        )


__all__ = [
    "CompositeObservationSource",
    "EvidenceSatisfactionPolicy",
    "ExecutorAdapterFactory",
    "LazyStdioExecutor",
    "ObservationSensor",
    "PolicyEvidenceVerifier",
    "ServerSpecFactory",
]
