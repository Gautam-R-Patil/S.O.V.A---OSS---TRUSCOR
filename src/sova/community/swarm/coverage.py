# SPDX-License-Identifier: Apache-2.0
"""Trusted, event-derived swarm coverage accounting.

Planner supplied coverage labels are useful hints, but they are not evidence.
This ledger derives exercised coverage only from signed coordinator events:
actions requested/completed, independently verified outcomes, observation
content digests, and deterministic oracle results.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from typing import Any


class SwarmCoverageLedger:
    """Thread-safe measured coverage shared by all isolated swarm workers."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._actions_attempted: set[str] = set()
        self._actions_succeeded: set[str] = set()
        self._actions_verified: set[str] = set()
        self._grants: set[str] = set()
        self._states: set[str] = set()
        self._transitions: set[tuple[str, str]] = set()
        self._changed_transitions: set[tuple[str, str]] = set()
        self._oracles_passed: set[str] = set()
        self._evidence_roles: set[str] = set()
        self._attempt_count = 0
        self._completed_count = 0
        self._verified_count = 0
        self._per_agent: dict[str, dict[str, Any]] = defaultdict(self._empty_agent)

    @staticmethod
    def _empty_agent() -> dict[str, Any]:
        return {
            "actionKindsAttempted": set(),
            "actionKindsSucceeded": set(),
            "actionKindsVerified": set(),
            "observedStateDigests": set(),
            "transitionDigests": set(),
            "attemptCount": 0,
            "completedCount": 0,
            "verifiedCount": 0,
        }

    @staticmethod
    def _string(value: object) -> str | None:
        return value if isinstance(value, str) and value else None

    def _observe_requested(self, payload: dict[str, Any], agent: dict[str, Any]) -> None:
        action = self._string(payload.get("action"))
        grant = self._string(payload.get("grantId"))
        if action is not None:
            self._actions_attempted.add(action)
            agent["actionKindsAttempted"].add(action)
        if grant is not None:
            self._grants.add(grant)
        self._attempt_count += 1
        agent["attemptCount"] += 1

    def _observe_transition(
        self,
        payload: dict[str, Any],
        agent: dict[str, Any],
    ) -> None:
        before = self._string(payload.get("observationBeforeContentDigest"))
        after = self._string(payload.get("observationAfterContentDigest"))
        for digest in (before, after):
            if digest is not None:
                self._states.add(digest)
                agent["observedStateDigests"].add(digest)
        if before is None or after is None:
            return
        transition = (before, after)
        self._transitions.add(transition)
        agent["transitionDigests"].add(f"{before}->{after}")
        if before != after:
            self._changed_transitions.add(transition)

    def _observe_completed(self, payload: dict[str, Any], agent: dict[str, Any]) -> None:
        action = self._string(payload.get("action"))
        if action is not None and self._string(payload.get("status")) == "succeeded":
            self._actions_succeeded.add(action)
            agent["actionKindsSucceeded"].add(action)
        self._observe_transition(payload, agent)
        verification = payload.get("verification")
        if isinstance(verification, dict) and verification.get("verified") is True:
            if action is not None:
                self._actions_verified.add(action)
                agent["actionKindsVerified"].add(action)
            self._verified_count += 1
            agent["verifiedCount"] += 1
            roles = verification.get("satisfied_evidence")
            if isinstance(roles, list):
                self._evidence_roles.update(
                    item for item in roles if isinstance(item, str) and item
                )
        self._completed_count += 1
        agent["completedCount"] += 1

    def _observe_state(self, payload: dict[str, Any], agent: dict[str, Any]) -> None:
        digest = self._string(payload.get("projectionDigest"))
        if digest is not None:
            self._states.add(digest)
            agent["observedStateDigests"].add(digest)

    def _observe_oracle(self, payload: dict[str, Any]) -> None:
        if payload.get("status") != "pass":
            return
        oracle = self._string(payload.get("oracleId"))
        if oracle is not None:
            self._oracles_passed.add(oracle)

    def observe(self, agent_id: str, event: dict[str, Any]) -> None:
        """Consume one already-redacted engine event; malformed fields are ignored."""
        kind = self._string(event.get("kind"))
        payload = event.get("payload")
        if kind is None or not isinstance(payload, dict) or not agent_id:
            return
        with self._lock:
            agent = self._per_agent[agent_id]
            if kind == "tool.requested":
                self._observe_requested(payload, agent)
            elif kind == "tool.completed":
                self._observe_completed(payload, agent)
            elif kind == "environment.state":
                self._observe_state(payload, agent)
            elif kind == "oracle.completed":
                self._observe_oracle(payload)

    @staticmethod
    def _agent_mapping(value: dict[str, Any]) -> dict[str, Any]:
        return {
            "actionKindsAttempted": sorted(value["actionKindsAttempted"]),
            "actionKindsSucceeded": sorted(value["actionKindsSucceeded"]),
            "actionKindsVerified": sorted(value["actionKindsVerified"]),
            "observedStateCount": len(value["observedStateDigests"]),
            "uniqueTransitionCount": len(value["transitionDigests"]),
            "attemptCount": value["attemptCount"],
            "completedCount": value["completedCount"],
            "verifiedCount": value["verifiedCount"],
        }

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "contract": "sova.swarm-measured-coverage/0.1.0",
                "measurementSource": "trusted-signed-engine-events",
                "plannerSelfReportsTrusted": False,
                "completeCoverageClaimed": False,
                "actionKindsAttempted": sorted(self._actions_attempted),
                "actionKindsSucceeded": sorted(self._actions_succeeded),
                "actionKindsVerified": sorted(self._actions_verified),
                "grantIdsExercised": sorted(self._grants),
                "evidenceRolesSatisfied": sorted(self._evidence_roles),
                "oracleIdsPassed": sorted(self._oracles_passed),
                "observedStateCount": len(self._states),
                "uniqueTransitionCount": len(self._transitions),
                "changedTransitionCount": len(self._changed_transitions),
                "attemptCount": self._attempt_count,
                "completedCount": self._completed_count,
                "verifiedCount": self._verified_count,
                "perAgent": {
                    key: self._agent_mapping(value)
                    for key, value in sorted(self._per_agent.items())
                },
            }


__all__ = ["SwarmCoverageLedger"]
