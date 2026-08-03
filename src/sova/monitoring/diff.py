# SPDX-License-Identifier: Apache-2.0
"""Deterministic multi-axis behavioral snapshot comparison."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.monitoring.model import BehaviorDiff, BehaviorSnapshot, DriftChange, DriftClass

_ENVIRONMENT_AXES = frozenset(
    {
        "target",
        "model",
        "toolSchemas",
        "permissions",
        "dependencies",
        "environment",
        "registrySnapshot",
        "approvalSurface",
    }
)
_BEHAVIOR_AXES = frozenset({"observedEffects", "reproductionRates", "findings"})
_METHODOLOGY_AXES = frozenset({"methodology", "captureProfile", "taxonomy"})
_ALL_AXES = _ENVIRONMENT_AXES | _BEHAVIOR_AXES | _METHODOLOGY_AXES


def _secret_scan(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise FormatError("SOVA-DIFF-FIELD", "snapshot keys must be strings")
            lowered = key.casefold().replace("_", "").replace("-", "")
            if any(word in lowered for word in ("password", "secret", "apikey", "credential")):
                raise FormatError(
                    "SOVA-DIFF-SECRET",
                    "snapshot contains a credential-shaped field",
                    path=f"{path}.{key}",
                )
            _secret_scan(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _secret_scan(child, f"{path}[{index}]")


def build_behavior_snapshot(specification: Mapping[str, Any]) -> BehaviorSnapshot:
    """Freeze exact behavior, environment, and methodology axes independently."""
    unknown = set(specification) - (_ALL_AXES | {"id", "traceReference"})
    if unknown:
        raise FormatError(
            "SOVA-DIFF-AXIS",
            "snapshot contains unsupported axes",
            details={"unknown": sorted(unknown)},
        )
    identifier = specification.get("id")
    if not isinstance(identifier, str) or not identifier:
        raise FormatError("SOVA-DIFF-ID", "snapshot id is required")
    trace_reference = specification.get("traceReference")
    if trace_reference is not None and not isinstance(trace_reference, str):
        raise FormatError("SOVA-DIFF-TRACE", "traceReference must be a string or null")
    axes: dict[str, Any] = {}
    for name in sorted(_ALL_AXES):
        value = specification.get(name, {"status": "not-recorded"})
        _secret_scan(value, f"$.{name}")
        axes[name] = value
    digests = {name: sha256_digest(canonical_json_bytes(value)) for name, value in axes.items()}
    return BehaviorSnapshot(identifier, trace_reference, axes, digests)


def _classification(axis: str) -> DriftClass:
    if axis in _ENVIRONMENT_AXES:
        return DriftClass.ENVIRONMENT
    if axis in _METHODOLOGY_AXES:
        return DriftClass.METHODOLOGY
    return DriftClass.BEHAVIOR


def compare_behavior_snapshots(
    left: BehaviorSnapshot,
    right: BehaviorSnapshot,
) -> BehaviorDiff:
    changes = tuple(
        DriftChange(axis, _classification(axis), left.axis_digests[axis], right.axis_digests[axis])
        for axis in sorted(_ALL_AXES)
        if left.axis_digests[axis] != right.axis_digests[axis]
    )
    methodology_changed = any(change.classification == DriftClass.METHODOLOGY for change in changes)
    trace_references = tuple(
        reference
        for reference in (left.trace_reference, right.trace_reference)
        if reference is not None
    )
    limitations = (
        ("Methodology changed; behavioral comparisons are not directly comparable.",)
        if methodology_changed
        else (
            "Digest differences identify changed declared axes; they do not establish causation.",
            "A behavioral difference is not automatically new security evidence.",
        )
    )
    return BehaviorDiff(
        left.snapshot_id,
        right.snapshot_id,
        changes,
        trace_references,
        not methodology_changed,
        limitations,
    )


__all__ = ["build_behavior_snapshot", "compare_behavior_snapshots"]
