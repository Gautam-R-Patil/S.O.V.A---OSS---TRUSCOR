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
    OutcomeStatus,
    SideEffect,
    negotiate,
)
from sova.executors.local import RestrictedLocalExecutor
from sova.executors.runner import ScenarioRunResult, run_capsule
from sova.executors.scripted import ScriptedAction, ScriptedExecutor

__all__ = [
    "ActionOutcome",
    "ActionRequest",
    "CancellationToken",
    "Capability",
    "CapabilityReport",
    "EvidenceReference",
    "ExecutionContext",
    "Executor",
    "OutcomeStatus",
    "RestrictedLocalExecutor",
    "ScenarioRunResult",
    "ScriptedAction",
    "ScriptedExecutor",
    "SideEffect",
    "negotiate",
    "run_capsule",
]
