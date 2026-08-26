# SPDX-License-Identifier: Apache-2.0
"""Construct an exact target/session/capability environment from trusted adapters.

This module is intentionally a trusted-coordinator API.  It converts already
admitted executor objects and operator-attested target metadata into immutable
generation bindings.  It does not discover targets, infer authorization, or
turn arbitrary model output into host authority.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING

from sova.contracts.identifiers import IdentifierKind, new_stable_identifier
from sova.executors import Capability, Executor, SideEffect
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.runtime.bound_environment import (
    BoundExecutorChamberEnvironment,
    EnvironmentCleanup,
    EvidenceReader,
    IndependentVerifierCallback,
    RedactedObservationCallback,
)
from sova.runtime.target_environment import (
    BackendGeneration,
    CapabilityGeneration,
    SessionEnvelope,
    TargetInstance,
    TargetLifecycle,
)
from sova.runtime.unified_execution import CapabilityBinding

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

    from sova.executors import SecretProvider


def capability_contract_digest(capability: Capability) -> str:
    """Return the canonical digest used by generations, bindings, and validation."""
    return sha256_digest(
        canonical_json_bytes(
            {
                "name": capability.name,
                "version": capability.version,
                "sideEffect": capability.side_effect.value,
                "idempotent": capability.idempotent,
                "evidence": list(capability.evidence),
            }
        )
    )


@dataclass(frozen=True, slots=True)
class TargetEnvironmentAdmission:
    """Operator/attestor supplied identity for one ready target generation."""

    instance_id: str
    target_manifest_digest: str
    environment_digest: str
    containment_digest: str
    identity_digest: str
    clock_domain: str
    generation: int = 1
    process_id: int | None = None
    process_start_digest: str | None = None
    browser_context_digest: str | None = None
    window_handle_digest: str | None = None
    endpoint_digest: str | None = None
    profile_lease_digest: str | None = None

    def target(self) -> TargetInstance:
        return TargetInstance(
            instance_id=self.instance_id,
            target_manifest_digest=self.target_manifest_digest,
            environment_digest=self.environment_digest,
            containment_digest=self.containment_digest,
            generation=self.generation,
            clock_domain=self.clock_domain,
            lifecycle=TargetLifecycle.READY,
            process_id=self.process_id,
            process_start_digest=self.process_start_digest,
            browser_context_digest=self.browser_context_digest,
            window_handle_digest=self.window_handle_digest,
            endpoint_digest=self.endpoint_digest,
        )


@dataclass(frozen=True, slots=True)
class BackendAdmission:
    """One trusted executor generation and its effect-verification policy."""

    backend_id: str
    executor: Executor
    verifier_id: str
    affinity_resources: tuple[str, ...]
    effect_resources: Mapping[str, tuple[str, ...]]
    generation: int = 1
    capability_generation: int = 1

    def __post_init__(self) -> None:
        if not self.backend_id or not self.verifier_id or not self.affinity_resources:
            raise FormatError(
                "SOVA-ENVIRONMENT-BUILDER-BACKEND",
                "backend id, verifier id, and affinity resources are required",
            )
        capabilities = self.executor.capabilities()
        if not isinstance(capabilities, tuple) or not capabilities:
            raise FormatError(
                "SOVA-ENVIRONMENT-BUILDER-CAPABILITY",
                "backend must expose at least one immutable capability",
            )
        actions = {capability.name for capability in capabilities}
        unknown = sorted(set(self.effect_resources) - actions)
        if unknown:
            raise FormatError(
                "SOVA-ENVIRONMENT-BUILDER-EFFECT",
                "effect-resource policy references an absent capability",
                details={"actions": unknown},
            )
        for capability in capabilities:
            resources = self.effect_resources.get(capability.name, ())
            if capability.side_effect != SideEffect.READ and not resources:
                raise FormatError(
                    "SOVA-ENVIRONMENT-BUILDER-EFFECT",
                    "mutating capability requires an explicit serialized effect resource",
                    details={"action": capability.name},
                )
            if capability.side_effect == SideEffect.READ and resources:
                raise FormatError(
                    "SOVA-ENVIRONMENT-BUILDER-EFFECT",
                    "read-only capability cannot claim a mutation effect resource",
                    details={"action": capability.name},
                )


def build_bound_executor_environment(  # noqa: PLR0913
    admission: TargetEnvironmentAdmission,
    backends: tuple[BackendAdmission, ...],
    *,
    observe: RedactedObservationCallback,
    verify: IndependentVerifierCallback,
    workspace_parent: Path | None = None,
    precreated_workspace: Path | None = None,
    evidence_reader: EvidenceReader | None = None,
    secret_provider: SecretProvider | None = None,
    cleanup: EnvironmentCleanup | None = None,
) -> BoundExecutorChamberEnvironment:
    """Build one fresh, immutable environment from an exact backend inventory."""
    if not backends or len({item.backend_id for item in backends}) != len(backends):
        raise FormatError(
            "SOVA-ENVIRONMENT-BUILDER-BACKEND",
            "environment requires a non-empty unique backend set",
        )
    if len({id(item.executor) for item in backends}) != len(backends):
        raise FormatError(
            "SOVA-ENVIRONMENT-BUILDER-BACKEND",
            "one executor object cannot represent multiple backend generations",
        )
    target = admission.target()
    backend_generations: list[BackendGeneration] = []
    capabilities_by_backend: dict[str, tuple[Capability, ...]] = {}
    for backend in sorted(backends, key=lambda item: item.backend_id):
        capabilities = tuple(
            sorted(backend.executor.capabilities(), key=lambda item: item.identifier)
        )
        identifiers = [item.identifier for item in capabilities]
        if len(identifiers) != len(set(identifiers)):
            raise FormatError(
                "SOVA-ENVIRONMENT-BUILDER-CAPABILITY",
                "backend capability identifier is duplicated",
            )
        capabilities_by_backend[backend.backend_id] = capabilities
        backend_generations.append(
            BackendGeneration(
                backend_id=backend.backend_id,
                generation=backend.generation,
                target_instance_digest=target.digest,
                environment_digest=target.environment_digest,
                capabilities=tuple(
                    CapabilityGeneration(
                        capability.identifier,
                        backend.capability_generation,
                        capability_contract_digest(capability),
                    )
                    for capability in capabilities
                ),
            )
        )
    session_resources = tuple(
        sorted(
            {
                f"target:{admission.instance_id}",
                *(resource for backend in backends for resource in backend.affinity_resources),
            }
        )
    )
    session = SessionEnvelope(
        session_id=f"session:{secrets.token_hex(16)}",
        run_id=str(new_stable_identifier(IdentifierKind.RUN)),
        generation=1,
        target_instance_digest=target.digest,
        environment_digest=target.environment_digest,
        containment_digest=target.containment_digest,
        identity_digest=admission.identity_digest,
        clock_domain=target.clock_domain,
        backend_generations=tuple(backend_generations),
        affinity_resources=session_resources,
        profile_lease_digest=admission.profile_lease_digest,
    )
    bindings: dict[str, CapabilityBinding] = {}
    executors: dict[str, Executor] = {}
    for backend in sorted(backends, key=lambda item: item.backend_id):
        executors[backend.backend_id] = backend.executor
        generation = session.backend(backend.backend_id)
        affinity = tuple(sorted({f"target:{admission.instance_id}", *backend.affinity_resources}))
        for capability in capabilities_by_backend[backend.backend_id]:
            capability_generation = generation.capability(capability.identifier)
            binding_id = (
                f"binding:{backend.backend_id}:"
                f"{capability.name.replace('.', '-')}:{capability.version}"
            )
            if binding_id in bindings:
                raise FormatError(
                    "SOVA-ENVIRONMENT-BUILDER-BINDING",
                    "generated capability binding id is duplicated",
                )
            bindings[binding_id] = CapabilityBinding(
                binding_id=binding_id,
                backend_id=backend.backend_id,
                backend_generation=generation.generation,
                backend_generation_digest=generation.digest,
                capability_name=capability.name,
                capability_version=capability.version,
                capability_generation=capability_generation.generation,
                capability_contract_digest=capability_generation.contract_digest,
                session_digest=session.digest,
                target_instance_digest=target.digest,
                environment_digest=target.environment_digest,
                side_effect=capability.side_effect,
                idempotent=capability.idempotent,
                expected_evidence=tuple(sorted(capability.evidence)),
                verifier_id=backend.verifier_id,
                affinity_resources=affinity,
                effect_resources=tuple(sorted(backend.effect_resources.get(capability.name, ()))),
            )
    return BoundExecutorChamberEnvironment(
        target=target,
        session=session,
        bindings=bindings,
        executors=executors,
        observe=observe,
        verify=verify,
        workspace_parent=workspace_parent,
        precreated_workspace=precreated_workspace,
        evidence_reader=evidence_reader,
        secret_provider=secret_provider,
        cleanup=cleanup,
    )


__all__ = [
    "BackendAdmission",
    "TargetEnvironmentAdmission",
    "build_bound_executor_environment",
    "capability_contract_digest",
]
