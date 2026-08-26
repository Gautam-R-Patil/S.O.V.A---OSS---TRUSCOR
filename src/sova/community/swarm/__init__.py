# SPDX-License-Identifier: Apache-2.0
"""Concurrent multi-agent SOVA swarm: isolated workers plus a shared blackboard.

A swarm is the existing single-agent Executor Engine, run N times in parallel,
plus a thin communication and coordination layer. Each web worker owns a fresh
browser context, and each software worker owns a fresh measured process/window;
both own disposable workspaces and fresh reproduction generations.
workers never share executor state directly. Findings and observations flow
onto a shared, redacted, hash-chained blackboard and are refreshed into every
planner turn as untrusted data. One aggregate effect ledger gates all workers,
and the coordinator merges every worker's artifacts into one `swarm.sova`.
"""

from sova.community.swarm.blackboard import SwarmBlackboard
from sova.community.swarm.budget import SwarmAggregateBudget, SwarmBudgetLedger
from sova.community.swarm.coordinator import AgentRunResult, SwarmCoordinator
from sova.community.swarm.coverage import SwarmCoverageLedger
from sova.community.swarm.message import SwarmMessage, SwarmMessageKind
from sova.community.swarm.runtime import SwarmArtifacts, run_web_swarm
from sova.community.swarm.software import SoftwareSwarmArtifacts, run_software_swarm
from sova.community.swarm.stress import StressReport, run_stress_profile
from sova.community.swarm.worker import SwarmWorkerSpec, run_swarm_worker

__all__ = [
    "AgentRunResult",
    "SoftwareSwarmArtifacts",
    "StressReport",
    "SwarmAggregateBudget",
    "SwarmArtifacts",
    "SwarmBlackboard",
    "SwarmBudgetLedger",
    "SwarmCoordinator",
    "SwarmCoverageLedger",
    "SwarmMessage",
    "SwarmMessageKind",
    "SwarmWorkerSpec",
    "run_software_swarm",
    "run_stress_profile",
    "run_swarm_worker",
    "run_web_swarm",
]
