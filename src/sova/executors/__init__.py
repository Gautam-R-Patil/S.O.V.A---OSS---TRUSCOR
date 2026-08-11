# SPDX-License-Identifier: Apache-2.0
"""Executor abstraction and no-Atlas reference backends."""

from sova.executors.contract import (
    ActionOutcome,
    ActionRequest,
    CancellationToken,
    Capability,
    CapabilityReport,
    EvidenceReference,
    ExecutionContext,
    Executor,
    FailureCause,
    OutcomeStatus,
    SecretProvider,
    SideEffect,
    negotiate,
)
from sova.executors.docker_desktop import (
    BoundedDockerCommandRunner,
    DockerCommandResult,
    DockerDesktopAttestation,
    DockerDesktopIsolationPolicy,
    DockerDesktopOciExecutor,
    attest_docker_desktop,
    docker_desktop_backend_descriptor,
)
from sova.executors.gvisor import (
    GVisorAttestation,
    GVisorOciExecutor,
    attest_gvisor,
    gvisor_backend_descriptor,
)
from sova.executors.local import RestrictedLocalExecutor
from sova.executors.runner import (
    ScenarioRunResult,
    action_intent_for_step,
    expanded_steps,
    run_capsule,
)
from sova.executors.scripted import ScriptedAction, ScriptedExecutor

__all__ = [
    "ActionOutcome",
    "ActionRequest",
    "BoundedDockerCommandRunner",
    "CancellationToken",
    "Capability",
    "CapabilityReport",
    "DockerCommandResult",
    "DockerDesktopAttestation",
    "DockerDesktopIsolationPolicy",
    "DockerDesktopOciExecutor",
    "EvidenceReference",
    "ExecutionContext",
    "Executor",
    "FailureCause",
    "GVisorAttestation",
    "GVisorOciExecutor",
    "OutcomeStatus",
    "RestrictedLocalExecutor",
    "ScenarioRunResult",
    "ScriptedAction",
    "ScriptedExecutor",
    "SecretProvider",
    "SideEffect",
    "action_intent_for_step",
    "attest_docker_desktop",
    "attest_gvisor",
    "docker_desktop_backend_descriptor",
    "expanded_steps",
    "gvisor_backend_descriptor",
    "negotiate",
    "run_capsule",
]
