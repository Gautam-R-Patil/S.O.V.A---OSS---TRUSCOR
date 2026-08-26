# SPDX-License-Identifier: Apache-2.0
"""Session-affine action admission for a trusted multi-surface coordinator.

Models remain proposal-only.  This module binds a complete canonical proposal
to an immutable target/session/backend generation and supplies deterministic
resource scheduling.  It intentionally does not launch executors or wire the
CLI so the coordinator remains an explicit trust boundary.
"""

from __future__ import annotations

import re
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from sova.executors import EvidenceReference, SideEffect
from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    from sova.runtime.target_environment import SessionEnvelope, TargetInstance

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_MAX_ARGUMENT_BYTES = 1024 * 1024
_MAX_MEDIA_TYPE_CHARS = 255


def _require_digest(value: str, role: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise FormatError(
            "SOVA-UNIFIED-DIGEST",
            f"{role} must be a canonical lowercase SHA-256 digest",
        )


def _require_identifier(value: str, role: str) -> None:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise FormatError("SOVA-UNIFIED-IDENTIFIER", f"{role} is invalid")


def _canonical_identifiers(values: tuple[str, ...], role: str) -> tuple[str, ...]:
    for value in values:
        _require_identifier(value, role)
    normalized = tuple(sorted(set(values)))
    if len(normalized) != len(values):
        raise FormatError("SOVA-UNIFIED-DUPLICATE", f"{role} contains a duplicate")
    return normalized


class CompletionState(StrEnum):
    """What is independently known about a prior execution attempt."""

    NOT_STARTED = "not-started"
    CONFIRMED_FAILED = "confirmed-failed"
    AMBIGUOUS = "ambiguous"
    SUCCEEDED = "succeeded"


@dataclass(frozen=True, slots=True)
class ObservationVersion:
    """Monotone target observation bound to one immutable session generation."""

    session_digest: str
    target_instance_digest: str
    sequence: int
    content_digest: str

    def __post_init__(self) -> None:
        for value, role in (
            (self.session_digest, "observation session digest"),
            (self.target_instance_digest, "observation target-instance digest"),
            (self.content_digest, "observation content digest"),
        ):
            _require_digest(value, role)
        if (
            isinstance(self.sequence, bool)
            or not isinstance(self.sequence, int)
            or self.sequence < 0
        ):
            raise FormatError(
                "SOVA-UNIFIED-OBSERVATION-SEQUENCE",
                "observation sequence must be a non-negative integer",
            )

    @classmethod
    def capture(
        cls,
        session: SessionEnvelope,
        target: TargetInstance,
        sequence: int,
        content: Mapping[str, Any],
    ) -> ObservationVersion:
        """Digest one canonical observation after checking target/session affinity."""
        session.assert_target(target)
        return cls(
            session.digest,
            target.digest,
            sequence,
            sha256_digest(canonical_json_bytes(dict(content))),
        )

    def advance(self, content: Mapping[str, Any]) -> ObservationVersion:
        """Return the next observation; the old version remains immutable and stale."""
        return ObservationVersion(
            self.session_digest,
            self.target_instance_digest,
            self.sequence + 1,
            sha256_digest(canonical_json_bytes(dict(content))),
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "sessionDigest": self.session_digest,
            "targetInstanceDigest": self.target_instance_digest,
            "sequence": self.sequence,
            "contentDigest": self.content_digest,
        }

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))


@dataclass(frozen=True, slots=True)
class BoundActionProposal:
    """A complete model proposal with no ambient or wildcard authority."""

    proposal_id: str
    participant_id: str
    turn: int
    session_digest: str
    target_instance_digest: str
    environment_digest: str
    observation_version_digest: str
    observation_sequence: int
    action: str
    capability_version: str
    canonical_arguments: bytes
    arguments_digest: str
    expected_effect: SideEffect
    required_evidence: tuple[str, ...]
    affinity_resources: tuple[str, ...]
    effect_resources: tuple[str, ...]

    def __post_init__(self) -> None:
        for value, role in (
            (self.proposal_id, "proposal id"),
            (self.participant_id, "participant id"),
            (self.action, "proposal action"),
            (self.capability_version, "capability version"),
        ):
            _require_identifier(value, role)
        for value, role in (
            (self.session_digest, "proposal session digest"),
            (self.target_instance_digest, "proposal target-instance digest"),
            (self.environment_digest, "proposal environment digest"),
            (self.observation_version_digest, "proposal observation-version digest"),
            (self.arguments_digest, "proposal arguments digest"),
        ):
            _require_digest(value, role)
        if isinstance(self.turn, bool) or not isinstance(self.turn, int) or self.turn < 0:
            raise FormatError(
                "SOVA-UNIFIED-PROPOSAL-TURN",
                "proposal turn must be a non-negative integer",
            )
        if (
            isinstance(self.observation_sequence, bool)
            or not isinstance(self.observation_sequence, int)
            or self.observation_sequence < 0
        ):
            raise FormatError(
                "SOVA-UNIFIED-OBSERVATION-SEQUENCE",
                "proposal observation sequence must be non-negative",
            )
        if not self.canonical_arguments or len(self.canonical_arguments) > _MAX_ARGUMENT_BYTES:
            raise FormatError(
                "SOVA-UNIFIED-ARGUMENTS",
                "canonical action arguments must contain 1 byte to 1 MiB",
            )
        arguments = strict_json_loads(
            self.canonical_arguments,
            max_bytes=_MAX_ARGUMENT_BYTES,
        )
        if not isinstance(arguments, dict):
            raise FormatError(
                "SOVA-UNIFIED-ARGUMENTS",
                "canonical action arguments must be a JSON object",
            )
        if canonical_json_bytes(arguments) != self.canonical_arguments:
            raise FormatError(
                "SOVA-UNIFIED-ARGUMENTS-CANONICAL",
                "action arguments are not canonical SOVA JSON",
            )
        if sha256_digest(self.canonical_arguments) != self.arguments_digest:
            raise FormatError(
                "SOVA-UNIFIED-ARGUMENTS-DIGEST",
                "action arguments do not match their bound digest",
            )
        evidence = _canonical_identifiers(self.required_evidence, "required evidence role")
        if not evidence:
            raise FormatError(
                "SOVA-UNIFIED-EVIDENCE",
                "every action proposal requires evidence",
            )
        affinity = _canonical_identifiers(self.affinity_resources, "affinity resource")
        if not affinity:
            raise FormatError(
                "SOVA-UNIFIED-AFFINITY",
                "every action proposal requires session affinity",
            )
        effects = _canonical_identifiers(self.effect_resources, "effect resource")
        if self.expected_effect != SideEffect.READ and not effects:
            raise FormatError(
                "SOVA-UNIFIED-EFFECT-RESOURCE",
                "mutating proposals require an explicit effect resource",
            )
        if not isinstance(self.expected_effect, SideEffect):
            raise FormatError(
                "SOVA-UNIFIED-SIDE-EFFECT",
                "proposal side effect must use the executor side-effect contract",
            )
        object.__setattr__(self, "required_evidence", evidence)
        object.__setattr__(self, "affinity_resources", affinity)
        object.__setattr__(self, "effect_resources", effects)

    @classmethod
    def create(  # noqa: PLR0913 - every security binding is deliberately explicit
        cls,
        *,
        proposal_id: str,
        participant_id: str,
        turn: int,
        session: SessionEnvelope,
        target: TargetInstance,
        observation: ObservationVersion,
        action: str,
        capability_version: str,
        arguments: Mapping[str, Any],
        expected_effect: SideEffect,
        required_evidence: tuple[str, ...],
        affinity_resources: tuple[str, ...],
        effect_resources: tuple[str, ...] = (),
    ) -> BoundActionProposal:
        session.assert_target(target)
        if (
            observation.session_digest != session.digest
            or observation.target_instance_digest != target.digest
        ):
            raise FormatError(
                "SOVA-UNIFIED-OBSERVATION-AFFINITY",
                "observation is attached to another target or session generation",
            )
        encoded = canonical_json_bytes(dict(arguments))
        return cls(
            proposal_id,
            participant_id,
            turn,
            session.digest,
            target.digest,
            target.environment_digest,
            observation.digest,
            observation.sequence,
            action,
            capability_version,
            encoded,
            sha256_digest(encoded),
            expected_effect,
            required_evidence,
            affinity_resources,
            effect_resources,
        )

    @property
    def capability_identifier(self) -> str:
        return f"{self.action}/{self.capability_version}"

    @property
    def arguments(self) -> dict[str, Any]:
        value = strict_json_loads(self.canonical_arguments, max_bytes=_MAX_ARGUMENT_BYTES)
        if not isinstance(value, dict):  # pragma: no cover - constructor proves this
            raise TypeError
        return value

    def to_mapping(self) -> dict[str, Any]:
        return {
            "proposalId": self.proposal_id,
            "participantId": self.participant_id,
            "turn": self.turn,
            "sessionDigest": self.session_digest,
            "targetInstanceDigest": self.target_instance_digest,
            "environmentDigest": self.environment_digest,
            "observationVersionDigest": self.observation_version_digest,
            "observationSequence": self.observation_sequence,
            "capability": self.capability_identifier,
            "arguments": self.arguments,
            "argumentsDigest": self.arguments_digest,
            "expectedEffect": self.expected_effect.value,
            "requiredEvidence": list(self.required_evidence),
            "affinityResources": list(self.affinity_resources),
            "effectResources": list(self.effect_resources),
        }

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))


@dataclass(frozen=True, slots=True)
class CapabilityBinding:
    """Immutable metadata binding; ``backend_id`` is the trusted executor lookup key."""

    binding_id: str
    backend_id: str
    backend_generation: int
    backend_generation_digest: str
    capability_name: str
    capability_version: str
    capability_generation: int
    capability_contract_digest: str
    session_digest: str
    target_instance_digest: str
    environment_digest: str
    side_effect: SideEffect
    idempotent: bool
    expected_evidence: tuple[str, ...]
    verifier_id: str
    affinity_resources: tuple[str, ...]
    effect_resources: tuple[str, ...]

    def __post_init__(self) -> None:
        for value, role in (
            (self.binding_id, "capability binding id"),
            (self.backend_id, "capability backend id"),
            (self.capability_name, "capability name"),
            (self.capability_version, "capability version"),
            (self.verifier_id, "effect verifier id"),
        ):
            _require_identifier(value, role)
        if (
            isinstance(self.backend_generation, bool)
            or not isinstance(self.backend_generation, int)
            or self.backend_generation < 1
        ):
            raise FormatError(
                "SOVA-UNIFIED-BACKEND-GENERATION",
                "binding backend generation must be positive",
            )
        if (
            isinstance(self.capability_generation, bool)
            or not isinstance(self.capability_generation, int)
            or self.capability_generation < 1
        ):
            raise FormatError(
                "SOVA-UNIFIED-CAPABILITY-GENERATION",
                "binding capability generation must be positive",
            )
        for value, role in (
            (self.backend_generation_digest, "binding backend-generation digest"),
            (self.capability_contract_digest, "binding capability-contract digest"),
            (self.session_digest, "binding session digest"),
            (self.target_instance_digest, "binding target-instance digest"),
            (self.environment_digest, "binding environment digest"),
        ):
            _require_digest(value, role)
        evidence = _canonical_identifiers(self.expected_evidence, "expected evidence role")
        if not evidence:
            raise FormatError(
                "SOVA-UNIFIED-EVIDENCE",
                "capability binding requires evidence obligations",
            )
        affinity = _canonical_identifiers(self.affinity_resources, "affinity resource")
        if not affinity:
            raise FormatError(
                "SOVA-UNIFIED-AFFINITY",
                "capability binding requires session affinity",
            )
        effects = _canonical_identifiers(self.effect_resources, "effect resource")
        if self.side_effect != SideEffect.READ and not effects:
            raise FormatError(
                "SOVA-UNIFIED-EFFECT-RESOURCE",
                "mutating capability bindings require an effect resource",
            )
        if not isinstance(self.side_effect, SideEffect) or not isinstance(self.idempotent, bool):
            raise FormatError(
                "SOVA-UNIFIED-CAPABILITY-CONTRACT",
                "binding side effect and idempotence must use exact contract types",
            )
        object.__setattr__(self, "expected_evidence", evidence)
        object.__setattr__(self, "affinity_resources", affinity)
        object.__setattr__(self, "effect_resources", effects)

    @property
    def capability_identifier(self) -> str:
        return f"{self.capability_name}/{self.capability_version}"

    def assert_session_generation(
        self,
        session: SessionEnvelope,
        target: TargetInstance,
    ) -> None:
        session.assert_target(target)
        if session.digest != self.session_digest:
            raise FormatError(
                "SOVA-UNIFIED-SESSION-AFFINITY",
                "capability binding belongs to another session generation",
            )
        if target.digest != self.target_instance_digest:
            raise FormatError(
                "SOVA-UNIFIED-TARGET-AFFINITY",
                "capability binding belongs to another target generation",
            )
        if target.environment_digest != self.environment_digest:
            raise FormatError(
                "SOVA-UNIFIED-ENVIRONMENT-AFFINITY",
                "capability binding belongs to another environment",
            )
        backend = session.backend(self.backend_id)
        if (
            backend.generation != self.backend_generation
            or backend.digest != self.backend_generation_digest
        ):
            raise FormatError(
                "SOVA-UNIFIED-BACKEND-SUBSTITUTION",
                "backend generation does not match the capability binding",
            )
        capability = backend.capability(self.capability_identifier)
        if (
            capability.generation != self.capability_generation
            or capability.contract_digest != self.capability_contract_digest
        ):
            raise FormatError(
                "SOVA-UNIFIED-CAPABILITY-SUBSTITUTION",
                "capability generation does not match the binding",
            )
        session.assert_affinity(self.affinity_resources)

    def assert_admits(
        self,
        proposal: BoundActionProposal,
        session: SessionEnvelope,
        target: TargetInstance,
    ) -> None:
        self.assert_session_generation(session, target)
        mismatches: list[str] = []
        if proposal.session_digest != self.session_digest:
            mismatches.append("session")
        if proposal.target_instance_digest != self.target_instance_digest:
            mismatches.append("target")
        if proposal.environment_digest != self.environment_digest:
            mismatches.append("environment")
        if proposal.capability_identifier != self.capability_identifier:
            mismatches.append("capability")
        if proposal.expected_effect != self.side_effect:
            mismatches.append("effect")
        if proposal.required_evidence != self.expected_evidence:
            mismatches.append("evidence")
        if proposal.affinity_resources != self.affinity_resources:
            mismatches.append("affinity-resources")
        if proposal.effect_resources != self.effect_resources:
            mismatches.append("effect-resources")
        if mismatches:
            raise FormatError(
                "SOVA-UNIFIED-BINDING-MISMATCH",
                "action proposal does not match its exact capability binding",
                details={"dimensions": mismatches},
            )

    def scheduler_resources(self) -> tuple[str, ...]:
        return tuple(sorted({*self.affinity_resources, *self.effect_resources}))

    def retry_allowed(self, completion: CompletionState) -> bool:
        """Allow only unambiguous idempotent retries with conservative mutation rules."""
        if not isinstance(completion, CompletionState):
            raise FormatError(
                "SOVA-UNIFIED-COMPLETION-STATE",
                "retry decision requires a typed completion state",
            )
        if completion in {CompletionState.AMBIGUOUS, CompletionState.SUCCEEDED}:
            return False
        if not self.idempotent:
            return False
        if self.side_effect != SideEffect.READ:
            return completion == CompletionState.NOT_STARTED
        return completion in {CompletionState.NOT_STARTED, CompletionState.CONFIRMED_FAILED}

    def fallback_allowed_to(
        self,
        other: CapabilityBinding,
        *,
        completion: CompletionState,
        session: SessionEnvelope,
        target: TargetInstance,
    ) -> bool:
        """Return whether a fallback remains in the same exact state domain."""
        try:
            self.assert_session_generation(session, target)
            other.assert_session_generation(session, target)
        except FormatError:
            return False
        return bool(
            self.retry_allowed(completion)
            and other.idempotent
            and self.capability_identifier == other.capability_identifier
            and self.side_effect == other.side_effect
            and self.session_digest == other.session_digest
            and self.target_instance_digest == other.target_instance_digest
            and self.environment_digest == other.environment_digest
            and self.affinity_resources == other.affinity_resources
            and self.effect_resources == other.effect_resources
            and self.expected_evidence == other.expected_evidence
            and self.verifier_id == other.verifier_id
        )

    def assert_fallback_allowed(
        self,
        other: CapabilityBinding,
        *,
        completion: CompletionState,
        session: SessionEnvelope,
        target: TargetInstance,
    ) -> None:
        if not self.fallback_allowed_to(
            other,
            completion=completion,
            session=session,
            target=target,
        ):
            raise FormatError(
                "SOVA-UNIFIED-FALLBACK-DENIED",
                "fallback would cross affinity or violate retry safety",
            )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "bindingId": self.binding_id,
            "backendId": self.backend_id,
            "backendGeneration": self.backend_generation,
            "backendGenerationDigest": self.backend_generation_digest,
            "capability": self.capability_identifier,
            "capabilityGeneration": self.capability_generation,
            "capabilityContractDigest": self.capability_contract_digest,
            "sessionDigest": self.session_digest,
            "targetInstanceDigest": self.target_instance_digest,
            "environmentDigest": self.environment_digest,
            "sideEffect": self.side_effect.value,
            "idempotent": self.idempotent,
            "expectedEvidence": list(self.expected_evidence),
            "verifierId": self.verifier_id,
            "affinityResources": list(self.affinity_resources),
            "effectResources": list(self.effect_resources),
        }

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))


@dataclass(frozen=True, slots=True)
class ExecutionGrant:
    """One expiring execution grant bound to an allowed canonical proposal."""

    grant_id: str
    proposal_digest: str
    binding_digest: str
    session_digest: str
    target_instance_digest: str
    environment_digest: str
    observation_version_digest: str
    backend_generation_digest: str
    capability_contract_digest: str
    canonical_authorization_decision: bytes
    authorization_decision_digest: str
    issued_monotonic_ns: int
    expires_monotonic_ns: int

    def __post_init__(self) -> None:
        _require_identifier(self.grant_id, "execution grant id")
        for value, role in (
            (self.proposal_digest, "grant proposal digest"),
            (self.binding_digest, "grant capability-binding digest"),
            (self.session_digest, "grant session digest"),
            (self.target_instance_digest, "grant target-instance digest"),
            (self.environment_digest, "grant environment digest"),
            (self.observation_version_digest, "grant observation-version digest"),
            (self.backend_generation_digest, "grant backend-generation digest"),
            (self.capability_contract_digest, "grant capability-contract digest"),
            (self.authorization_decision_digest, "grant authorization-decision digest"),
        ):
            _require_digest(value, role)
        if (
            isinstance(self.issued_monotonic_ns, bool)
            or not isinstance(self.issued_monotonic_ns, int)
            or isinstance(self.expires_monotonic_ns, bool)
            or not isinstance(self.expires_monotonic_ns, int)
            or self.issued_monotonic_ns < 0
            or self.expires_monotonic_ns <= self.issued_monotonic_ns
        ):
            raise FormatError(
                "SOVA-UNIFIED-GRANT-WINDOW",
                "execution grant requires a positive monotonic validity window",
            )
        if (
            not self.canonical_authorization_decision
            or len(self.canonical_authorization_decision) > _MAX_ARGUMENT_BYTES
        ):
            raise FormatError(
                "SOVA-UNIFIED-AUTHORIZATION-BINDING",
                "canonical authorization decision must contain 1 byte to 1 MiB",
            )
        decision = strict_json_loads(
            self.canonical_authorization_decision,
            max_bytes=_MAX_ARGUMENT_BYTES,
        )
        if not isinstance(decision, dict):
            raise FormatError(
                "SOVA-UNIFIED-AUTHORIZATION-BINDING",
                "canonical authorization decision must be a JSON object",
            )
        if canonical_json_bytes(decision) != self.canonical_authorization_decision:
            raise FormatError(
                "SOVA-UNIFIED-AUTHORIZATION-CANONICAL",
                "authorization decision is not canonical SOVA JSON",
            )
        if sha256_digest(self.canonical_authorization_decision) != (
            self.authorization_decision_digest
        ):
            raise FormatError(
                "SOVA-UNIFIED-AUTHORIZATION-DIGEST",
                "authorization decision does not match its bound digest",
            )
        expected_decision = {
            "proposalDigest": self.proposal_digest,
            "bindingDigest": self.binding_digest,
            "sessionDigest": self.session_digest,
        }
        if decision.get("decision") != "allowed" or any(
            decision.get(key) != value for key, value in expected_decision.items()
        ):
            raise FormatError(
                "SOVA-UNIFIED-AUTHORIZATION-BINDING",
                "authorization decision is not allowed or is bound to another action",
            )

    @classmethod
    def issue(  # noqa: PLR0913 - the grant intentionally binds every trust dimension
        cls,
        *,
        grant_id: str,
        proposal: BoundActionProposal,
        binding: CapabilityBinding,
        session: SessionEnvelope,
        target: TargetInstance,
        observation: ObservationVersion,
        authorization_decision: Mapping[str, Any],
        issued_monotonic_ns: int,
        expires_monotonic_ns: int,
    ) -> ExecutionGrant:
        binding.assert_admits(proposal, session, target)
        _assert_fresh_observation(proposal, observation, session, target)
        decision = dict(authorization_decision)
        expected = {
            "proposalDigest": proposal.digest,
            "bindingDigest": binding.digest,
            "sessionDigest": session.digest,
        }
        if decision.get("decision") != "allowed" or any(
            decision.get(key) != value for key, value in expected.items()
        ):
            raise FormatError(
                "SOVA-UNIFIED-AUTHORIZATION-BINDING",
                "authorization decision is not allowed or is bound to another action",
            )
        decision_bytes = canonical_json_bytes(decision)
        return cls(
            grant_id,
            proposal.digest,
            binding.digest,
            session.digest,
            target.digest,
            target.environment_digest,
            observation.digest,
            binding.backend_generation_digest,
            binding.capability_contract_digest,
            decision_bytes,
            sha256_digest(decision_bytes),
            issued_monotonic_ns,
            expires_monotonic_ns,
        )

    def assert_valid(  # noqa: PLR0913 - validation repeats every bound trust dimension
        self,
        proposal: BoundActionProposal,
        binding: CapabilityBinding,
        session: SessionEnvelope,
        target: TargetInstance,
        observation: ObservationVersion,
        *,
        now_monotonic_ns: int | None = None,
    ) -> None:
        binding.assert_admits(proposal, session, target)
        _assert_fresh_observation(proposal, observation, session, target)
        expected = {
            "proposal": proposal.digest,
            "binding": binding.digest,
            "session": session.digest,
            "target": target.digest,
            "environment": target.environment_digest,
            "observation": observation.digest,
            "backend-generation": binding.backend_generation_digest,
            "capability-contract": binding.capability_contract_digest,
        }
        actual = {
            "proposal": self.proposal_digest,
            "binding": self.binding_digest,
            "session": self.session_digest,
            "target": self.target_instance_digest,
            "environment": self.environment_digest,
            "observation": self.observation_version_digest,
            "backend-generation": self.backend_generation_digest,
            "capability-contract": self.capability_contract_digest,
        }
        mismatches = sorted(key for key, value in expected.items() if actual[key] != value)
        if mismatches:
            raise FormatError(
                "SOVA-UNIFIED-GRANT-SUBSTITUTION",
                "execution grant binding changed before dispatch",
                details={"dimensions": mismatches},
            )
        current = time.monotonic_ns() if now_monotonic_ns is None else now_monotonic_ns
        if current < self.issued_monotonic_ns or current >= self.expires_monotonic_ns:
            raise FormatError(
                "SOVA-UNIFIED-GRANT-EXPIRED",
                "execution grant is outside its monotonic validity window",
            )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "grantId": self.grant_id,
            "proposalDigest": self.proposal_digest,
            "bindingDigest": self.binding_digest,
            "sessionDigest": self.session_digest,
            "targetInstanceDigest": self.target_instance_digest,
            "environmentDigest": self.environment_digest,
            "observationVersionDigest": self.observation_version_digest,
            "backendGenerationDigest": self.backend_generation_digest,
            "capabilityContractDigest": self.capability_contract_digest,
            "authorizationDecision": self.authorization_decision,
            "authorizationDecisionDigest": self.authorization_decision_digest,
            "issuedMonotonicNs": self.issued_monotonic_ns,
            "expiresMonotonicNs": self.expires_monotonic_ns,
        }

    @property
    def authorization_decision(self) -> dict[str, Any]:
        value = strict_json_loads(
            self.canonical_authorization_decision,
            max_bytes=_MAX_ARGUMENT_BYTES,
        )
        if not isinstance(value, dict):  # pragma: no cover - constructor proves this
            raise TypeError
        return value

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))


def _assert_fresh_observation(
    proposal: BoundActionProposal,
    observation: ObservationVersion,
    session: SessionEnvelope,
    target: TargetInstance,
) -> None:
    if (
        observation.session_digest != session.digest
        or observation.target_instance_digest != target.digest
    ):
        raise FormatError(
            "SOVA-UNIFIED-OBSERVATION-AFFINITY",
            "current observation belongs to another target or session generation",
        )
    if (
        proposal.observation_version_digest != observation.digest
        or proposal.observation_sequence != observation.sequence
    ):
        raise FormatError(
            "SOVA-UNIFIED-STALE-OBSERVATION",
            "action proposal was derived from a stale observation",
        )


@dataclass(frozen=True, slots=True)
class ScheduleLease:
    """One deterministic scheduler ticket and its exclusive resource set."""

    ticket: int
    resources: tuple[str, ...]


class MutationScheduler:
    """Serialize intersecting resources in deterministic submission order.

    Disjoint resource sets may run concurrently.  Among intersecting requests,
    the lower ticket always enters first, preventing lock-order deadlocks and
    later conflicting requests from bypassing an earlier waiter.
    """

    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._next_ticket = 0
        self._waiting: dict[int, frozenset[str]] = {}
        self._active: dict[int, frozenset[str]] = {}

    @staticmethod
    def _resources(
        affinity_resources: tuple[str, ...],
        effect_resources: tuple[str, ...],
    ) -> tuple[str, ...]:
        combined = tuple(sorted({*affinity_resources, *effect_resources}))
        resources = _canonical_identifiers(
            combined,
            "scheduler resource",
        )
        if not resources:
            raise FormatError(
                "SOVA-UNIFIED-SCHEDULER-RESOURCE",
                "scheduler requires at least one resource",
            )
        return resources

    def _eligible(self, ticket: int, resources: frozenset[str]) -> bool:
        if any(resources & active for active in self._active.values()):
            return False
        return not any(
            earlier < ticket and bool(resources & waiting)
            for earlier, waiting in self._waiting.items()
        )

    @contextmanager
    def hold(
        self,
        affinity_resources: tuple[str, ...],
        effect_resources: tuple[str, ...] = (),
        *,
        timeout_seconds: float | None = None,
    ) -> Iterator[ScheduleLease]:
        """Acquire all resources atomically and release them on every exit path."""
        if timeout_seconds is not None and (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or timeout_seconds <= 0
        ):
            raise FormatError(
                "SOVA-UNIFIED-SCHEDULER-TIMEOUT",
                "scheduler timeout must be positive",
            )
        ordered = self._resources(affinity_resources, effect_resources)
        resources = frozenset(ordered)
        deadline = None if timeout_seconds is None else time.monotonic() + timeout_seconds
        with self._condition:
            ticket = self._next_ticket
            self._next_ticket += 1
            self._waiting[ticket] = resources
            while not self._eligible(ticket, resources):
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    self._waiting.pop(ticket, None)
                    self._condition.notify_all()
                    raise FormatError(
                        "SOVA-UNIFIED-SCHEDULER-TIMEOUT",
                        "timed out before all action resources became available",
                    )
                self._condition.wait(remaining)
            self._waiting.pop(ticket)
            self._active[ticket] = resources
        lease = ScheduleLease(ticket, ordered)
        try:
            yield lease
        finally:
            with self._condition:
                self._active.pop(ticket, None)
                self._condition.notify_all()

    @property
    def active(self) -> tuple[ScheduleLease, ...]:
        with self._condition:
            return tuple(
                ScheduleLease(ticket, tuple(sorted(resources)))
                for ticket, resources in sorted(self._active.items())
            )

    @property
    def waiting(self) -> tuple[ScheduleLease, ...]:
        with self._condition:
            return tuple(
                ScheduleLease(ticket, tuple(sorted(resources)))
                for ticket, resources in sorted(self._waiting.items())
            )


@runtime_checkable
class CoordinatorEventEvidenceSink(Protocol):
    """Persistence interface owned by exactly one trusted coordinator thread."""

    @property
    def coordinator_id(self) -> str: ...

    def append_event(
        self,
        kind: str,
        payload: dict[str, Any],
        *,
        parents: tuple[str, ...] = (),
    ) -> str | None: ...

    def persist_evidence(
        self,
        role: str,
        media_type: str,
        data: bytes,
    ) -> EvidenceReference: ...


class SingleCoordinatorSink:
    """Thread-affine guard around an event/evidence persistence implementation."""

    def __init__(self, delegate: CoordinatorEventEvidenceSink) -> None:
        _require_identifier(delegate.coordinator_id, "coordinator id")
        self._delegate = delegate
        self._owner_thread = threading.get_ident()

    @property
    def coordinator_id(self) -> str:
        return self._delegate.coordinator_id

    def _require_owner(self) -> None:
        if threading.get_ident() != self._owner_thread:
            raise FormatError(
                "SOVA-UNIFIED-COORDINATOR-THREAD",
                "event and evidence persistence is restricted to the coordinator thread",
            )

    def append_event(
        self,
        kind: str,
        payload: dict[str, Any],
        *,
        parents: tuple[str, ...] = (),
    ) -> str | None:
        self._require_owner()
        _require_identifier(kind, "event kind")
        for parent in parents:
            _require_identifier(parent, "event parent id")
        # Validate a detached canonical copy before it reaches the persistence boundary.
        value = strict_json_loads(canonical_json_bytes(payload), max_bytes=_MAX_ARGUMENT_BYTES)
        if not isinstance(value, dict):  # pragma: no cover - payload is statically a dict
            raise TypeError
        return self._delegate.append_event(kind, value, parents=parents)

    def persist_evidence(
        self,
        role: str,
        media_type: str,
        data: bytes,
    ) -> EvidenceReference:
        self._require_owner()
        _require_identifier(role, "evidence role")
        if (
            not isinstance(media_type, str)
            or not media_type
            or len(media_type) > _MAX_MEDIA_TYPE_CHARS
        ):
            raise FormatError("SOVA-UNIFIED-EVIDENCE", "evidence media type is invalid")
        reference = self._delegate.persist_evidence(role, media_type, data)
        if not isinstance(reference, EvidenceReference) or (
            reference.role != role
            or reference.media_type != media_type
            or reference.digest != sha256_digest(data)
            or reference.size != len(data)
        ):
            raise FormatError(
                "SOVA-UNIFIED-EVIDENCE-SUBSTITUTION",
                "evidence sink returned a reference that does not resolve to supplied bytes",
            )
        return reference


__all__ = [
    "BoundActionProposal",
    "CapabilityBinding",
    "CompletionState",
    "CoordinatorEventEvidenceSink",
    "ExecutionGrant",
    "MutationScheduler",
    "ObservationVersion",
    "ScheduleLease",
    "SingleCoordinatorSink",
]
