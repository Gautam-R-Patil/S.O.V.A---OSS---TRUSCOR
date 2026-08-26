# SPDX-License-Identifier: Apache-2.0
"""Concrete trusted environment for one session-bound Executor Chamber.

The environment owns one immutable target/session generation, one exact
capability-to-executor registry, and one disposable workspace.  Planner code
must never receive this object: the trusted chamber coordinator consumes its
structural protocol and exposes only redacted projections and declarative
grants to planners.
"""

from __future__ import annotations

import copy
import re
import shutil
import tempfile
import threading
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Protocol, Self

from sova.executors import (
    ActionOutcome,
    ActionRequest,
    CancellationToken,
    Capability,
    EvidenceReference,
    ExecutionContext,
    Executor,
    OutcomeStatus,
    SecretProvider,
    SideEffect,
)
from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError
from sova.runtime.unified_execution import CapabilityBinding, ObservationVersion
from sova.trace import Redactor

_WORKSPACE_CLEANUP_ATTEMPTS = 100
_WORKSPACE_CLEANUP_RETRY_SECONDS = 0.01

if TYPE_CHECKING:
    from sova.community.executor_chamber import ChamberObservation, ChamberVerification
    from sova.runtime.target_environment import SessionEnvelope, TargetInstance


def _remove_workspace_with_retries(
    workspace: Path,
    *,
    attempts: int = _WORKSPACE_CLEANUP_ATTEMPTS,
    retry_seconds: float = _WORKSPACE_CLEANUP_RETRY_SECONDS,
) -> bool:
    """Remove one already-affinity-checked workspace after transient handle release."""
    for attempt in range(attempts):
        if not workspace.exists():
            return True
        try:
            shutil.rmtree(workspace)
        except OSError:
            if attempt + 1 == attempts:
                return False
            time.sleep(retry_seconds)
        else:
            return not workspace.exists()
    return False


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_OBSERVATION_BYTES = 256 * 1024
_MAX_VERIFICATION_TEXT_BYTES = 16 * 1024
_MAX_EVIDENCE_SIZE = (1 << 63) - 1


class RedactedObservationCallback(Protocol):
    """Capture target state; the environment redacts and detaches its result."""

    def __call__(self) -> Mapping[str, Any]: ...


class IndependentVerifierCallback(Protocol):
    """Independently assess one outcome against fresh before/after state."""

    def __call__(
        self,
        request: ActionRequest,
        outcome: ActionOutcome,
        binding: CapabilityBinding,
        before: ChamberObservation,
        after: ChamberObservation,
    ) -> ChamberVerification: ...


class EvidenceReader(Protocol):
    """Resolve evidence bytes in trusted coordinator space, never planner space."""

    def __call__(self, reference: EvidenceReference) -> bytes: ...


class EnvironmentCleanup(Protocol):
    """Close the owned target and any non-workspace resources."""

    def __call__(self) -> None: ...


def _format_error(code: str, message: str) -> FormatError:
    return FormatError(code, message)


def _require_digest(value: object, role: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise _format_error(
            "SOVA-BOUND-ENVIRONMENT-DIGEST",
            f"{role} must be a canonical lowercase SHA-256 digest",
        )
    return value


def _capability_document(capability: Capability) -> dict[str, Any]:
    return {
        "name": capability.name,
        "version": capability.version,
        "sideEffect": capability.side_effect.value,
        "idempotent": capability.idempotent,
        "evidence": list(capability.evidence),
    }


def _validate_capability(capability: object) -> Capability:
    if type(capability) is not Capability:
        raise _format_error(
            "SOVA-BOUND-ENVIRONMENT-CAPABILITY",
            "executor capability inventory must contain exact Capability values",
        )
    if (
        not capability.name
        or not capability.version
        or not isinstance(capability.side_effect, SideEffect)
        or not isinstance(capability.idempotent, bool)
        or not isinstance(capability.evidence, tuple)
        or any(not isinstance(role, str) or not role for role in capability.evidence)
        or len(set(capability.evidence)) != len(capability.evidence)
    ):
        raise _format_error(
            "SOVA-BOUND-ENVIRONMENT-CAPABILITY",
            "executor advertised a malformed capability contract",
        )
    canonical_json_bytes(_capability_document(capability))
    return capability


def _executor_inventory(executor: Executor) -> tuple[str, tuple[Capability, ...], str]:
    try:
        name = executor.name
        supplied = executor.capabilities()
    except Exception as error:
        raise _format_error(
            "SOVA-BOUND-ENVIRONMENT-BACKEND",
            "executor inventory could not be read through the trusted boundary",
        ) from error
    if not isinstance(name, str) or not name or not isinstance(supplied, tuple):
        raise _format_error(
            "SOVA-BOUND-ENVIRONMENT-BACKEND",
            "executor name or capability inventory is malformed",
        )
    capabilities = tuple(
        sorted(
            (_validate_capability(item) for item in supplied),
            key=lambda capability: capability.identifier,
        )
    )
    identifiers = tuple(item.identifier for item in capabilities)
    if len(set(identifiers)) != len(identifiers):
        raise _format_error(
            "SOVA-BOUND-ENVIRONMENT-CAPABILITY",
            "executor capability inventory contains a duplicate identifier",
        )
    document = {
        "executorName": name,
        "capabilities": [_capability_document(item) for item in capabilities],
    }
    return name, capabilities, sha256_digest(canonical_json_bytes(document))


def _detached_mapping(value: Mapping[str, Any], *, max_bytes: int) -> dict[str, Any]:
    raw = canonical_json_bytes(dict(value))
    if len(raw) > max_bytes:
        raise _format_error(
            "SOVA-BOUND-ENVIRONMENT-OBSERVATION",
            "redacted observation exceeds the configured size boundary",
        )
    detached = strict_json_loads(raw, max_bytes=max_bytes)
    if not isinstance(detached, dict):  # pragma: no cover - source is a mapping
        raise TypeError
    return detached


def _outcome_document(outcome: ActionOutcome) -> dict[str, Any]:
    return {
        "requestId": outcome.request_id,
        "status": outcome.status.value,
        "sideEffect": outcome.side_effect.value,
        "output": outcome.output,
        "evidence": [
            {
                "role": item.role,
                "mediaType": item.media_type,
                "digest": item.digest,
                "size": item.size,
            }
            for item in outcome.evidence
        ],
        "verification": outcome.verification,
        "retryable": outcome.retryable,
        "errorCode": outcome.error_code,
        "limitations": list(outcome.limitations),
        "failureCause": outcome.failure_cause.value,
    }


def _validate_evidence_references(
    references: tuple[EvidenceReference, ...],
) -> tuple[EvidenceReference, ...]:
    if not isinstance(references, tuple):
        raise _format_error(
            "SOVA-BOUND-ENVIRONMENT-EVIDENCE",
            "executor evidence references must use an immutable tuple",
        )
    identities: set[tuple[str, str]] = set()
    for reference in references:
        if type(reference) is not EvidenceReference:
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-EVIDENCE",
                "executor returned a malformed evidence reference",
            )
        if (
            not isinstance(reference.role, str)
            or not reference.role
            or not isinstance(reference.media_type, str)
            or not reference.media_type
            or isinstance(reference.size, bool)
            or not isinstance(reference.size, int)
            or not 0 <= reference.size <= _MAX_EVIDENCE_SIZE
        ):
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-EVIDENCE",
                "executor returned invalid evidence role, media type, or size metadata",
            )
        _require_digest(reference.digest, "evidence digest")
        identity = (reference.role, reference.digest)
        if identity in identities:
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-EVIDENCE",
                "executor returned a duplicate evidence role and digest",
            )
        identities.add(identity)
    return references


@dataclass(frozen=True, slots=True)
class _BackendRecord:
    backend_id: str
    executor: Executor
    name: str
    capabilities: tuple[Capability, ...]
    inventory_digest: str
    bindings: tuple[CapabilityBinding, ...]


class _OpaqueSecretProvider:
    """Action-scoped façade that never exposes the configured provider object."""

    __slots__ = ("_environment", "_provider")

    def __init__(
        self,
        environment: BoundExecutorChamberEnvironment,
        provider: SecretProvider,
    ) -> None:
        self._environment = environment
        self._provider = provider

    def resolve(self, reference: str) -> str:
        with self._environment._secret_resolution():
            if not isinstance(reference, str) or not reference:
                raise _format_error(
                    "SOVA-BOUND-ENVIRONMENT-SECRET",
                    "secret resolution requires a non-empty opaque reference",
                )
            try:
                value = self._provider.resolve(reference)
            except Exception as error:
                raise _format_error(
                    "SOVA-BOUND-ENVIRONMENT-SECRET",
                    "the opaque secret provider failed without exposing reference or value",
                ) from error
            if not isinstance(value, str):
                raise _format_error(
                    "SOVA-BOUND-ENVIRONMENT-SECRET",
                    "the opaque secret provider returned a non-string value",
                )
            return value


class _GuardedExecutor:
    """Executor façade that revalidates generation and dispatch context."""

    __slots__ = ("_environment", "_record")

    def __init__(
        self,
        environment: BoundExecutorChamberEnvironment,
        record: _BackendRecord,
    ) -> None:
        self._environment = environment
        self._record = record

    @property
    def name(self) -> str:
        with self._environment._coordinator_operation():
            self._environment._assert_backend_record(self._record)
            return self._record.name

    def capabilities(self) -> tuple[Capability, ...]:
        with self._environment._coordinator_operation():
            self._environment._assert_backend_record(self._record)
            return self._record.capabilities

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        with self._environment._coordinator_operation():
            self._environment._assert_backend_record(self._record)
            binding = self._environment._binding_for_request(self._record, request)
            self._environment._assert_execution_context(context, binding)
            canonical_json_bytes(request.inputs)
            with self._environment._executor_secret_lease():
                try:
                    outcome = self._record.executor.execute(request, context, cancellation)
                except FormatError:
                    raise
                except Exception as error:
                    raise _format_error(
                        "SOVA-BOUND-ENVIRONMENT-EXECUTOR",
                        "executor failed without exposing adapter or target details",
                    ) from error
            self._environment._assert_backend_record(self._record)
            self._environment._assert_outcome(request, binding, outcome)
            return outcome


class BoundExecutorChamberEnvironment:
    """Trusted, thread-affine owner of one exact chamber environment.

    The class structurally satisfies ``ExecutorChamberEnvironment``.  Its
    chamber types are imported for static checking only, keeping this runtime
    safety primitive independent of the community orchestration module.
    """

    __slots__ = (
        "_bindings",
        "_cleanup",
        "_cleanup_complete",
        "_closed",
        "_coordinator_thread",
        "_evidence_reader",
        "_executors",
        "_lock",
        "_observation_callback",
        "_records",
        "_secret_active_depth",
        "_secret_facade",
        "_session",
        "_session_digest",
        "_target",
        "_target_digest",
        "_verifier_callback",
        "_workspace",
        "_workspace_parent",
    )

    def __init__(  # noqa: PLR0913 - every injected item is a distinct trust boundary
        self,
        *,
        target: TargetInstance,
        session: SessionEnvelope,
        bindings: Mapping[str, CapabilityBinding],
        executors: Mapping[str, Executor],
        observe: RedactedObservationCallback,
        verify: IndependentVerifierCallback,
        workspace_parent: Path | None = None,
        precreated_workspace: Path | None = None,
        evidence_reader: EvidenceReader | None = None,
        secret_provider: SecretProvider | None = None,
        cleanup: EnvironmentCleanup | None = None,
    ) -> None:
        if not callable(observe) or not callable(verify):
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-CALLBACK",
                "observation and independent verifier callbacks are required",
            )
        session.assert_target(target)
        admitted_bindings = self._admit_bindings(bindings, session, target)
        records = self._admit_executors(executors, admitted_bindings, session)
        parent = self._workspace_root(workspace_parent)
        if precreated_workspace is None:
            try:
                workspace = Path(tempfile.mkdtemp(prefix="sova-chamber-", dir=parent)).resolve()
            except OSError as error:
                raise _format_error(
                    "SOVA-BOUND-ENVIRONMENT-WORKSPACE",
                    "disposable workspace could not be created",
                ) from error
        else:
            try:
                workspace = precreated_workspace.resolve(strict=True)
            except OSError as error:
                raise _format_error(
                    "SOVA-BOUND-ENVIRONMENT-WORKSPACE",
                    "precreated disposable workspace is unavailable",
                ) from error
            if precreated_workspace.is_symlink() or not workspace.is_dir():
                raise _format_error(
                    "SOVA-BOUND-ENVIRONMENT-WORKSPACE",
                    "precreated disposable workspace must be one real directory",
                )
        if workspace == parent or parent not in workspace.parents or workspace.is_symlink():
            shutil.rmtree(workspace, ignore_errors=True)
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-WORKSPACE",
                "disposable workspace escaped its admitted parent",
            )

        self._target = target
        self._session = session
        self._target_digest = target.digest
        self._session_digest = session.digest
        self._bindings: Mapping[str, CapabilityBinding] = MappingProxyType(admitted_bindings)
        self._records: Mapping[str, _BackendRecord] = MappingProxyType(records)
        self._workspace_parent = parent
        self._workspace = workspace
        self._observation_callback = observe
        self._verifier_callback = verify
        self._evidence_reader = evidence_reader
        self._cleanup = cleanup
        self._coordinator_thread = threading.get_ident()
        self._lock = threading.RLock()
        self._closed = False
        self._cleanup_complete = False
        self._secret_active_depth = 0
        self._secret_facade = (
            None if secret_provider is None else _OpaqueSecretProvider(self, secret_provider)
        )
        guarded: dict[str, Executor] = {
            backend_id: _GuardedExecutor(self, record) for backend_id, record in records.items()
        }
        self._executors: Mapping[str, Executor] = MappingProxyType(guarded)

    @staticmethod
    def _workspace_root(workspace_parent: Path | None) -> Path:
        candidate = (
            Path(tempfile.gettempdir()) if workspace_parent is None else Path(workspace_parent)
        )
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as error:
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-WORKSPACE",
                "workspace parent does not resolve to an existing directory",
            ) from error
        if not resolved.is_dir():
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-WORKSPACE",
                "workspace parent must be an existing directory",
            )
        return resolved

    @staticmethod
    def _admit_bindings(
        bindings: Mapping[str, CapabilityBinding],
        session: SessionEnvelope,
        target: TargetInstance,
    ) -> dict[str, CapabilityBinding]:
        if not isinstance(bindings, Mapping) or not bindings:
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-BINDING",
                "trusted environment requires at least one capability binding",
            )
        admitted: dict[str, CapabilityBinding] = {}
        for key, binding in bindings.items():
            if not isinstance(key, str) or type(binding) is not CapabilityBinding:
                raise _format_error(
                    "SOVA-BOUND-ENVIRONMENT-BINDING",
                    "binding registry contains a malformed entry",
                )
            if key != binding.binding_id or key in admitted:
                raise _format_error(
                    "SOVA-BOUND-ENVIRONMENT-BINDING",
                    "binding registry key does not exactly match its immutable binding id",
                )
            binding.assert_session_generation(session, target)
            admitted[key] = binding
        return dict(sorted(admitted.items()))

    @classmethod
    def _admit_executors(
        cls,
        executors: Mapping[str, Executor],
        bindings: Mapping[str, CapabilityBinding],
        session: SessionEnvelope,
    ) -> dict[str, _BackendRecord]:
        expected_backends = {binding.backend_id for binding in bindings.values()}
        if not isinstance(executors, Mapping) or set(executors) != expected_backends:
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-BACKEND",
                "executor registry must exactly match admitted backend ids",
            )
        identities: set[int] = set()
        records: dict[str, _BackendRecord] = {}
        for backend_id in sorted(expected_backends):
            executor = executors[backend_id]
            identity = id(executor)
            if identity in identities:
                raise _format_error(
                    "SOVA-BOUND-ENVIRONMENT-BACKEND",
                    "one raw executor instance cannot represent multiple backend generations",
                )
            identities.add(identity)
            name, capabilities, inventory_digest = _executor_inventory(executor)
            backend = session.backend(backend_id)
            actual = {
                capability.identifier: sha256_digest(
                    canonical_json_bytes(_capability_document(capability))
                )
                for capability in capabilities
            }
            expected = {
                capability.identifier: capability.contract_digest
                for capability in backend.capabilities
            }
            if actual != expected:
                raise _format_error(
                    "SOVA-BOUND-ENVIRONMENT-CAPABILITY-SUBSTITUTION",
                    "executor inventory differs from the admitted backend generation",
                )
            backend_bindings = tuple(
                sorted(
                    (binding for binding in bindings.values() if binding.backend_id == backend_id),
                    key=lambda binding: binding.binding_id,
                )
            )
            actions = tuple(binding.capability_name for binding in backend_bindings)
            if len(set(actions)) != len(actions):
                raise _format_error(
                    "SOVA-BOUND-ENVIRONMENT-CAPABILITY",
                    "one backend cannot dispatch multiple bound versions of the same action",
                )
            for binding in backend_bindings:
                capability = next(
                    (
                        item
                        for item in capabilities
                        if item.identifier == binding.capability_identifier
                    ),
                    None,
                )
                if capability is None or (
                    capability.side_effect != binding.side_effect
                    or capability.idempotent != binding.idempotent
                    or tuple(sorted(capability.evidence)) != binding.expected_evidence
                    or actual[capability.identifier] != binding.capability_contract_digest
                ):
                    raise _format_error(
                        "SOVA-BOUND-ENVIRONMENT-CAPABILITY-SUBSTITUTION",
                        "executor capability differs from its exact binding contract",
                    )
            records[backend_id] = _BackendRecord(
                backend_id,
                executor,
                name,
                capabilities,
                inventory_digest,
                backend_bindings,
            )
        return records

    @property
    def target(self) -> TargetInstance:
        with self._coordinator_operation():
            return self._target

    @property
    def session(self) -> SessionEnvelope:
        with self._coordinator_operation():
            return self._session

    @property
    def bindings(self) -> Mapping[str, CapabilityBinding]:
        with self._coordinator_operation():
            self._assert_integrity()
            return self._bindings

    @property
    def executors(self) -> Mapping[str, Executor]:
        with self._coordinator_operation():
            self._assert_integrity()
            return self._executors

    @property
    def workspace(self) -> Path:
        with self._coordinator_operation():
            self._assert_workspace()
            return self._workspace

    @property
    def secret_provider(self) -> SecretProvider | None:
        with self._coordinator_operation():
            return self._secret_facade

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    @property
    def cleanup_complete(self) -> bool:
        with self._lock:
            return self._cleanup_complete

    @contextmanager
    def _coordinator_operation(self) -> Iterator[None]:
        with self._lock:
            if self._closed:
                raise _format_error(
                    "SOVA-BOUND-ENVIRONMENT-CLOSED",
                    "trusted environment is closed",
                )
            if threading.get_ident() != self._coordinator_thread:
                raise _format_error(
                    "SOVA-BOUND-ENVIRONMENT-COORDINATOR",
                    "trusted environment can only be used by its creating coordinator thread",
                )
            yield

    def _assert_integrity(self) -> None:
        self._session.assert_target(self._target)
        if (
            self._target.digest != self._target_digest
            or self._session.digest != self._session_digest
        ):
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-SESSION-SUBSTITUTION",
                "target or session generation changed after environment admission",
            )
        for binding in self._bindings.values():
            binding.assert_session_generation(self._session, self._target)
        for record in self._records.values():
            self._assert_backend_record(record)

    def _assert_backend_record(self, record: _BackendRecord) -> None:
        name, capabilities, inventory_digest = _executor_inventory(record.executor)
        if (
            name != record.name
            or capabilities != record.capabilities
            or inventory_digest != record.inventory_digest
        ):
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-CAPABILITY-SUBSTITUTION",
                "executor inventory changed after environment admission",
            )
        backend = self._session.backend(record.backend_id)
        for binding in record.bindings:
            binding.assert_session_generation(self._session, self._target)
            if binding.backend_generation_digest != backend.digest:
                raise _format_error(
                    "SOVA-BOUND-ENVIRONMENT-BACKEND-SUBSTITUTION",
                    "executor binding no longer matches the admitted backend generation",
                )

    def _assert_workspace(self) -> None:
        try:
            resolved = self._workspace.resolve(strict=True)
        except OSError as error:
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-WORKSPACE",
                "disposable workspace disappeared or became inaccessible",
            ) from error
        if (
            resolved != self._workspace
            or self._workspace == self._workspace_parent
            or self._workspace_parent not in self._workspace.parents
            or self._workspace.is_symlink()
            or not self._workspace.is_dir()
        ):
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-WORKSPACE",
                "disposable workspace identity or boundary changed",
            )

    def _binding_for_request(
        self,
        record: _BackendRecord,
        request: ActionRequest,
    ) -> CapabilityBinding:
        if type(request) is not ActionRequest or request.retry_attempt != 0:
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-REQUEST",
                "executor dispatch requires one exact non-retry ActionRequest",
            )
        matches = tuple(
            binding for binding in record.bindings if binding.capability_name == request.action
        )
        if len(matches) != 1:
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-REQUEST-SUBSTITUTION",
                "request action does not resolve to one exact backend binding",
            )
        return matches[0]

    def _assert_execution_context(
        self,
        context: ExecutionContext,
        binding: CapabilityBinding,
    ) -> None:
        if type(context) is not ExecutionContext:
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-CONTEXT",
                "executor dispatch requires an exact ExecutionContext",
            )
        self._assert_workspace()
        expected_environment = {
            "targetInstanceDigest": self._target_digest,
            "sessionDigest": self._session_digest,
            "bindingDigest": binding.digest,
        }
        if (
            context.workspace.resolve() != self._workspace
            or context.environment != expected_environment
        ):
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-CONTEXT-SUBSTITUTION",
                "execution context changed workspace, session, target, or binding affinity",
            )
        if context.secret_provider is not self._secret_facade:
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-SECRET-SUBSTITUTION",
                "execution context changed the opaque secret provider",
            )
        grant = context.authorization.get("executionGrant")
        if not isinstance(grant, Mapping):
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-GRANT",
                "execution context lacks an exact execution grant",
            )
        expected = {
            "bindingDigest": binding.digest,
            "sessionDigest": self._session_digest,
            "targetInstanceDigest": self._target_digest,
            "environmentDigest": self._target.environment_digest,
            "backendGenerationDigest": binding.backend_generation_digest,
            "capabilityContractDigest": binding.capability_contract_digest,
        }
        if any(grant.get(key) != value for key, value in expected.items()):
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-GRANT-SUBSTITUTION",
                "execution grant changed an admitted trust dimension",
            )
        decision = grant.get("authorizationDecision")
        if not isinstance(decision, Mapping) or (
            decision.get("decision") != "allowed"
            or decision.get("proposalDigest") != grant.get("proposalDigest")
            or decision.get("bindingDigest") != binding.digest
            or decision.get("sessionDigest") != self._session_digest
        ):
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-GRANT",
                "execution grant does not contain an exact allowed decision",
            )
        decision_bytes = canonical_json_bytes(dict(decision))
        if (
            sha256_digest(decision_bytes) != grant.get("authorizationDecisionDigest")
            or context.authorization.get("proposalDigest") != grant.get("proposalDigest")
            or context.authorization.get("bindingDigest") != binding.digest
            or context.authorization.get("sessionDigest") != self._session_digest
        ):
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-GRANT-SUBSTITUTION",
                "authorization envelope does not match its execution grant",
            )
        issued = grant.get("issuedMonotonicNs")
        expires = grant.get("expiresMonotonicNs")
        now = time.monotonic_ns()
        if (
            isinstance(issued, bool)
            or not isinstance(issued, int)
            or isinstance(expires, bool)
            or not isinstance(expires, int)
            or now < issued
            or now >= expires
        ):
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-GRANT-EXPIRED",
                "execution grant is outside its monotonic validity window",
            )

    def _assert_outcome(
        self,
        request: ActionRequest,
        binding: CapabilityBinding,
        outcome: object,
    ) -> None:
        if type(outcome) is not ActionOutcome:
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-OUTCOME",
                "executor returned a malformed outcome",
            )
        if (
            outcome.request_id != request.id
            or outcome.side_effect != binding.side_effect
            or not isinstance(outcome.status, OutcomeStatus)
        ):
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-OUTCOME-SUBSTITUTION",
                "executor outcome changed request, effect, or status identity",
            )
        _validate_evidence_references(outcome.evidence)
        canonical_json_bytes(_outcome_document(outcome))

    @contextmanager
    def _executor_secret_lease(self) -> Iterator[None]:
        self._secret_active_depth += 1
        try:
            yield
        finally:
            self._secret_active_depth -= 1

    @contextmanager
    def _secret_resolution(self) -> Iterator[None]:
        with self._coordinator_operation():
            if self._secret_active_depth < 1:
                raise _format_error(
                    "SOVA-BOUND-ENVIRONMENT-SECRET",
                    "opaque secrets may only be resolved during bound executor dispatch",
                )
            yield

    def observe(self) -> Mapping[str, Any]:
        with self._coordinator_operation():
            self._assert_integrity()
            self._assert_workspace()
            try:
                captured = self._observation_callback()
            except Exception as error:
                raise _format_error(
                    "SOVA-BOUND-ENVIRONMENT-OBSERVATION",
                    "trusted observation callback failed without exposing target details",
                ) from error
            if not isinstance(captured, Mapping):
                raise _format_error(
                    "SOVA-BOUND-ENVIRONMENT-OBSERVATION",
                    "trusted observation callback must return an object",
                )
            redacted, _records = Redactor(
                context_id=f"sova-bound-environment:{self._session.session_id}"
            ).redact(dict(captured))
            if not isinstance(redacted, dict):  # pragma: no cover - source is a mapping
                raise TypeError
            result = _detached_mapping(redacted, max_bytes=_MAX_OBSERVATION_BYTES)
            self._assert_integrity()
            return result

    @staticmethod
    def _assert_observation(
        observation: ChamberObservation,
        session: SessionEnvelope,
        target: TargetInstance,
    ) -> None:
        version = observation.version
        projection = observation.projection
        if type(version) is not ObservationVersion or not isinstance(projection, dict):
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-OBSERVATION",
                "verifier received a malformed chamber observation",
            )
        if (
            version.session_digest != session.digest
            or version.target_instance_digest != target.digest
            or version.content_digest != sha256_digest(canonical_json_bytes(projection))
        ):
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-OBSERVATION-SUBSTITUTION",
                "verifier observation changed session, target, or content identity",
            )

    def _read_evidence(self, reference: EvidenceReference) -> None:
        if self._evidence_reader is None:
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-EVIDENCE-UNRESOLVED",
                "verified outcome evidence requires an independent byte reader",
            )
        try:
            data = self._evidence_reader(reference)
        except Exception as error:
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-EVIDENCE-UNRESOLVED",
                "independent evidence bytes could not be resolved",
            ) from error
        if not isinstance(data, bytes) or (
            len(data) != reference.size or sha256_digest(data) != reference.digest
        ):
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-EVIDENCE-DIGEST",
                "independent evidence bytes do not match reference size and digest",
            )

    def _assert_verification(
        self,
        verification: ChamberVerification,
        binding: CapabilityBinding,
        outcome: ActionOutcome,
        before: ChamberObservation,
        after: ChamberObservation,
    ) -> None:
        if (
            not isinstance(verification.verified, bool)
            or verification.independence not in {"agent-independent", "cross-executor"}
            or not isinstance(verification.method, str)
            or not verification.method
            or len(verification.method.encode("utf-8")) > _MAX_VERIFICATION_TEXT_BYTES
            or not isinstance(verification.evidence_digests, tuple)
            or not isinstance(verification.satisfied_evidence, tuple)
            or not isinstance(verification.limitations, tuple)
            or any(
                not isinstance(item, str)
                or len(item.encode("utf-8")) > _MAX_VERIFICATION_TEXT_BYTES
                for item in verification.limitations
            )
        ):
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-VERIFIER",
                "independent verifier returned an invalid or provider-only assessment",
            )
        digests = verification.evidence_digests
        for digest in digests:
            _require_digest(digest, "verification evidence digest")
        if tuple(sorted(set(digests))) != digests:
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-VERIFIER",
                "verification evidence digests must be unique and canonical",
            )
        satisfied = verification.satisfied_evidence
        if (
            any(not isinstance(item, str) or not item for item in satisfied)
            or tuple(sorted(set(satisfied))) != satisfied
            or not set(satisfied).issubset(binding.expected_evidence)
        ):
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-EVIDENCE-ROLE",
                "verifier satisfied-evidence labels are duplicated or outside the binding",
            )
        public_document = {
            "verified": verification.verified,
            "independence": verification.independence,
            "method": verification.method,
            "evidenceDigests": list(digests),
            "satisfiedEvidence": list(satisfied),
            "limitations": list(verification.limitations),
        }
        redacted, records = Redactor(
            context_id=f"sova-bound-verification:{self._session.session_id}"
        ).redact(public_document)
        if records or canonical_json_bytes(redacted) != canonical_json_bytes(public_document):
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-VERIFIER-SENSITIVE",
                "verifier result contains secret-shaped public material",
            )
        if not verification.verified:
            return
        if outcome.status == OutcomeStatus.SUCCEEDED and satisfied != binding.expected_evidence:
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-EVIDENCE-ROLE",
                "verified successful outcome did not satisfy every bound evidence label",
            )
        known_digests = {
            before.version.content_digest,
            after.version.content_digest,
            *(reference.digest for reference in outcome.evidence),
        }
        if not digests or not set(digests).issubset(known_digests):
            raise _format_error(
                "SOVA-BOUND-ENVIRONMENT-EVIDENCE-DIGEST",
                "verifier cited absent or unbound evidence digests",
            )
        cited_outcome_digests = set(digests) & {reference.digest for reference in outcome.evidence}
        for reference in outcome.evidence:
            if reference.digest in cited_outcome_digests:
                self._read_evidence(reference)

    def verify(
        self,
        request: ActionRequest,
        outcome: ActionOutcome,
        binding: CapabilityBinding,
        before: ChamberObservation,
        after: ChamberObservation,
    ) -> ChamberVerification:
        with self._coordinator_operation():
            self._assert_integrity()
            admitted = self._bindings.get(binding.binding_id)
            if admitted is None or admitted.digest != binding.digest:
                raise _format_error(
                    "SOVA-BOUND-ENVIRONMENT-BINDING-SUBSTITUTION",
                    "verifier received a capability outside the immutable registry",
                )
            binding.assert_session_generation(self._session, self._target)
            if (
                type(request) is not ActionRequest
                or type(outcome) is not ActionOutcome
                or request.action != binding.capability_name
            ):
                raise _format_error(
                    "SOVA-BOUND-ENVIRONMENT-VERIFIER",
                    "verifier request or outcome does not match the admitted capability",
                )
            self._assert_outcome(request, binding, outcome)
            self._assert_observation(before, self._session, self._target)
            self._assert_observation(after, self._session, self._target)
            if after.version.sequence != before.version.sequence + 1:
                raise _format_error(
                    "SOVA-BOUND-ENVIRONMENT-OBSERVATION-STALE",
                    "independent verification requires the next fresh observation version",
                )
            request_before = canonical_json_bytes(request.inputs)
            outcome_before = canonical_json_bytes(_outcome_document(outcome))
            before_projection = canonical_json_bytes(before.projection)
            after_projection = canonical_json_bytes(after.projection)
            verifier_request = copy.deepcopy(request)
            verifier_outcome = copy.deepcopy(outcome)
            verifier_before = copy.deepcopy(before)
            verifier_after = copy.deepcopy(after)
            try:
                verification = self._verifier_callback(
                    verifier_request,
                    verifier_outcome,
                    binding,
                    verifier_before,
                    verifier_after,
                )
            except FormatError:
                raise
            except Exception as error:
                raise _format_error(
                    "SOVA-BOUND-ENVIRONMENT-VERIFIER",
                    "independent verifier failed without exposing target details",
                ) from error
            if (
                request_before != canonical_json_bytes(verifier_request.inputs)
                or outcome_before != canonical_json_bytes(_outcome_document(verifier_outcome))
                or before_projection != canonical_json_bytes(verifier_before.projection)
                or after_projection != canonical_json_bytes(verifier_after.projection)
            ):
                raise _format_error(
                    "SOVA-BOUND-ENVIRONMENT-VERIFIER-MUTATION",
                    "verifier mutated trusted request, outcome, or observation inputs",
                )
            self._assert_verification(verification, binding, outcome, before, after)
            self._assert_integrity()
            return verification

    def close(self) -> None:
        with self._lock:
            if self._closed:
                if not self._cleanup_complete:
                    raise _format_error(
                        "SOVA-BOUND-ENVIRONMENT-CLEANUP-INCOMPLETE",
                        "trusted environment is closed but cleanup did not complete",
                    )
                return
            self._closed = True
            self._secret_active_depth = 0
            failures = 0
            if self._cleanup is not None:
                try:
                    self._cleanup()
                except Exception:  # noqa: BLE001 - cleanup details must not escape
                    failures += 1
            safe_workspace = bool(
                self._workspace != self._workspace_parent
                and self._workspace_parent in self._workspace.parents
            )
            if not safe_workspace or not _remove_workspace_with_retries(self._workspace):
                failures += 1
            if self._workspace.exists():
                failures += 1
            self._cleanup_complete = failures == 0
            if failures:
                raise _format_error(
                    "SOVA-BOUND-ENVIRONMENT-CLEANUP-INCOMPLETE",
                    "trusted environment closed fail-safe but one or more cleanup steps failed",
                )

    def __enter__(self) -> Self:
        with self._coordinator_operation():
            return self

    def __exit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> None:
        del exc_type, exc_value, traceback
        self.close()


__all__ = [
    "BoundExecutorChamberEnvironment",
    "EnvironmentCleanup",
    "EvidenceReader",
    "IndependentVerifierCallback",
    "RedactedObservationCallback",
]
