# SPDX-License-Identifier: Apache-2.0
"""Local-only sentinel history and deterministic CI policy evaluation."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.monitoring.diff import compare_behavior_snapshots
from sova.monitoring.model import BehaviorDiff, BehaviorSnapshot, DriftClass

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _policy_integer(policy: Mapping[str, Any], name: str, default: int) -> int:
    value = policy.get(name, default)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise FormatError("SOVA-MONITOR-POLICY", f"{name} must be a non-negative integer")
    return value


def _append_history(path: Path, row: Mapping[str, Any]) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = path.read_bytes() if path.exists() else b""
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(existing + canonical_json_bytes(dict(row)) + b"\n")
    temporary.replace(path)


def run_sentinel(
    baseline: BehaviorSnapshot,
    current: BehaviorSnapshot,
    *,
    policy: Mapping[str, Any],
    history_path: Path,
) -> dict[str, Any]:
    """Evaluate one local snapshot and append immutable methodology-aware history."""
    diff = compare_behavior_snapshots(baseline, current)
    environment_count = sum(
        change.classification == DriftClass.ENVIRONMENT for change in diff.changes
    )
    behavior_count = sum(change.classification == DriftClass.BEHAVIOR for change in diff.changes)
    methodology_count = sum(
        change.classification == DriftClass.METHODOLOGY for change in diff.changes
    )
    max_environment = _policy_integer(policy, "maxEnvironmentChanges", 0)
    max_behavior = _policy_integer(policy, "maxBehaviorChanges", 0)
    max_methodology = _policy_integer(policy, "maxMethodologyChanges", 0)
    triggered = []
    if environment_count > max_environment:
        triggered.append("environment-drift-threshold")
    if behavior_count > max_behavior:
        triggered.append("behavioral-drift-threshold")
    if methodology_count > max_methodology:
        triggered.append("methodology-drift-threshold")
    approval_changed = any(change.axis == "approvalSurface" for change in diff.changes)
    if approval_changed:
        triggered.append("approval-surface-changed")
    status = "failed" if triggered else "passed"
    row = {
        "checkedAt": _now(),
        "baseline": baseline.to_mapping()["snapshotDigest"],
        "current": current.to_mapping()["snapshotDigest"],
        "methodologyDigest": current.axis_digests["methodology"],
        "policyDigest": sha256_digest(canonical_json_bytes(policy)),
        "status": status,
        "triggers": triggered,
    }
    _append_history(history_path, row)
    return {
        "artifactType": "sova.sentinel-report",
        "schemaVersion": "0.1.0",
        "status": status,
        "triggers": triggered,
        "diff": diff.to_mapping(),
        "notification": {"mode": "local-output", "silentUpload": False},
        "history": str(history_path.resolve()),
        "thirdPartyAttestation": False,
        "selfMonitoringOnly": True,
    }


def _sarif(diff: BehaviorDiff, *, blocked: bool) -> dict[str, Any]:
    level = "error" if blocked else "note"
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SOVA OSS behavioral CI",
                        "version": "0.1.0",
                        "rules": [],
                    }
                },
                "results": [
                    {
                        "ruleId": f"SOVA-DRIFT-{change.axis.upper()}",
                        "level": level,
                        "message": {
                            "text": f"{change.classification.value}: {change.axis} changed"
                        },
                        "properties": {
                            "beforeDigest": change.before_digest,
                            "afterDigest": change.after_digest,
                            "newSecurityEvidence": False,
                        },
                    }
                    for change in diff.changes
                ],
            }
        ],
    }


def evaluate_ci(diff: BehaviorDiff, policy: Mapping[str, Any]) -> dict[str, Any]:
    """Apply deterministic severity/flakiness policy without patching or uploading."""
    max_behavior = _policy_integer(policy, "maxBehaviorChanges", 0)
    max_environment = _policy_integer(policy, "maxEnvironmentChanges", 0)
    allowed_flaky = _policy_integer(policy, "allowedFlakyReproductions", 0)
    observed_flaky = _policy_integer(policy, "observedFlakyReproductions", 0)
    behavior_count = sum(change.classification == DriftClass.BEHAVIOR for change in diff.changes)
    environment_count = sum(
        change.classification == DriftClass.ENVIRONMENT for change in diff.changes
    )
    reasons: list[str] = []
    if behavior_count > max_behavior:
        reasons.append("behavioral-drift-policy")
    if environment_count > max_environment:
        reasons.append("environment-drift-policy")
    if not diff.comparable:
        reasons.append("methodology-not-comparable")
    if observed_flaky > allowed_flaky:
        reasons.append("flakiness-policy")
    blocked = bool(reasons)
    annotations = [
        {
            "title": f"SOVA drift: {change.axis}",
            "level": "failure" if blocked else "notice",
            "message": change.classification.value,
            "beforeDigest": change.before_digest,
            "afterDigest": change.after_digest,
        }
        for change in diff.changes
    ]
    return {
        "artifactType": "sova.ci-report",
        "schemaVersion": "0.1.0",
        "status": "failed" if blocked else "passed",
        "exitCode": 1 if blocked else 0,
        "reasons": reasons,
        "annotations": annotations,
        "sarif": _sarif(diff, blocked=blocked),
        "artifactPolicy": {
            "retention": str(policy.get("retention", "operator-controlled")),
            "redactionRequired": True,
        },
        "profile": str(policy.get("profile", "standard")),
        "automaticPatching": False,
        "uploadPerformed": False,
    }


__all__ = ["evaluate_ci", "run_sentinel"]
