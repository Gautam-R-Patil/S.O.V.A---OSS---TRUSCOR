# SPDX-License-Identifier: Apache-2.0
"""Typed behavioral snapshot and drift results."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest


class DriftClass(StrEnum):
    ENVIRONMENT = "environment-drift"
    BEHAVIOR = "behavioral-drift"
    METHODOLOGY = "methodology-drift"


@dataclass(frozen=True, slots=True)
class BehaviorSnapshot:
    snapshot_id: str
    trace_reference: str | None
    axes: dict[str, Any]
    axis_digests: dict[str, str]

    def to_mapping(self) -> dict[str, Any]:
        document = {
            "artifactType": "sova.behavior-snapshot",
            "schemaVersion": "0.1.0",
            "id": self.snapshot_id,
            "traceReference": self.trace_reference,
            "axes": self.axes,
            "axisDigests": self.axis_digests,
        }
        document["snapshotDigest"] = sha256_digest(canonical_json_bytes(document))
        return document


@dataclass(frozen=True, slots=True)
class DriftChange:
    axis: str
    classification: DriftClass
    before_digest: str
    after_digest: str

    def to_mapping(self) -> dict[str, str]:
        return {
            "axis": self.axis,
            "classification": self.classification.value,
            "beforeDigest": self.before_digest,
            "afterDigest": self.after_digest,
        }


@dataclass(frozen=True, slots=True)
class BehaviorDiff:
    left_snapshot: str
    right_snapshot: str
    changes: tuple[DriftChange, ...]
    trace_references: tuple[str, ...]
    comparable: bool
    limitations: tuple[str, ...]

    @property
    def environment_drift(self) -> bool:
        return any(change.classification == DriftClass.ENVIRONMENT for change in self.changes)

    @property
    def behavioral_drift(self) -> bool:
        return any(change.classification == DriftClass.BEHAVIOR for change in self.changes)

    @property
    def methodology_drift(self) -> bool:
        return any(change.classification == DriftClass.METHODOLOGY for change in self.changes)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.behavior-diff",
            "schemaVersion": "0.1.0",
            "leftSnapshot": self.left_snapshot,
            "rightSnapshot": self.right_snapshot,
            "changes": [change.to_mapping() for change in self.changes],
            "traceReferences": list(self.trace_references),
            "environmentDrift": self.environment_drift,
            "behavioralDrift": self.behavioral_drift,
            "methodologyDrift": self.methodology_drift,
            "comparable": self.comparable,
            "newSecurityEvidence": False,
            "limitations": list(self.limitations),
        }


__all__ = ["BehaviorDiff", "BehaviorSnapshot", "DriftChange", "DriftClass"]
