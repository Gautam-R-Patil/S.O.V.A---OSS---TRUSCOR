# SPDX-License-Identifier: Apache-2.0
"""Claim-conditioned observability ledger tests."""

from __future__ import annotations

import pytest

from sova.detonation import (
    CaptureMode,
    CoverageRequirement,
    OrderingGuarantee,
    SensorCoverageLedger,
    SensorCoveragePolicy,
    SensorDeclaration,
    SensorKind,
    SensorSurface,
)
from sova.formats.errors import FormatError


def _sensor(  # noqa: PLR0913 - fixture declarations deliberately expose each evidence axis
    identity: str,
    kind: SensorKind,
    surface: SensorSurface,
    *,
    health: str = "healthy",
    mode: CaptureMode = CaptureMode.DIRECT,
    emitted: int = 1,
    dropped: int = 0,
    blind_spots: tuple[str, ...] = (),
) -> SensorDeclaration:
    return SensorDeclaration(
        identity,
        kind,
        surface,
        health,
        "owned-acceptance-fixture",
        mode,
        "sova-monotonic-1",
        OrderingGuarantee.PARTIAL,
        emitted,
        dropped,
        blind_spots,
    )


def _policy() -> SensorCoveragePolicy:
    return SensorCoveragePolicy(
        "sova:coverage:web-agent-observable/0.1",
        "browser action and observable model/tool effects were captured",
        (
            CoverageRequirement(SensorSurface.SOVA, SensorKind.AUTHORIZATION),
            CoverageRequirement(SensorSurface.BROWSER, SensorKind.BROWSER),
            CoverageRequirement(SensorSurface.MODEL, SensorKind.MODEL),
            CoverageRequirement(SensorSurface.EXTERNAL, SensorKind.NETWORK),
        ),
    )


def test_complete_declared_coverage_passes_without_total_observability_claim() -> None:
    ledger = SensorCoverageLedger(
        (
            _sensor("authorization", SensorKind.AUTHORIZATION, SensorSurface.SOVA),
            _sensor("browser", SensorKind.BROWSER, SensorSurface.BROWSER),
            _sensor(
                "model",
                SensorKind.MODEL,
                SensorSurface.MODEL,
                mode=CaptureMode.PROVIDER,
                blind_spots=("private model state is unavailable",),
            ),
            _sensor("network", SensorKind.NETWORK, SensorSurface.EXTERNAL),
        )
    )
    report = ledger.evaluate(_policy())
    assert report.accepted
    assert report.coverage_ratio == "1"
    document = report.to_mapping()
    assert document["claims"] == {
        "totalSensorCoverage": False,
        "hiddenModelThoughtsObserved": False,
        "absenceOfEvidenceMeansAbsenceOfBehavior": False,
    }
    assert document["blindSpots"] == ["private model state is unavailable"]
    assert document["digest"].startswith("sha256:")


def test_missing_activity_drop_and_unavailable_sensor_fail_closed() -> None:
    ledger = SensorCoverageLedger(
        (
            _sensor("authorization", SensorKind.AUTHORIZATION, SensorSurface.SOVA),
            _sensor("browser", SensorKind.BROWSER, SensorSurface.BROWSER, emitted=0),
            _sensor(
                "model",
                SensorKind.MODEL,
                SensorSurface.MODEL,
                health="degraded",
                mode=CaptureMode.PROVIDER,
                emitted=3,
                dropped=1,
            ),
            _sensor(
                "network",
                SensorKind.NETWORK,
                SensorSurface.EXTERNAL,
                health="missing",
                mode=CaptureMode.UNAVAILABLE,
                emitted=0,
            ),
        )
    )
    report = ledger.evaluate(_policy())
    assert not report.accepted
    assert report.coverage_ratio == "0.25"
    assert report.degraded == (
        "browser/browser",
        "external-service/network",
        "model-or-agent/model",
    )


def test_sensor_declarations_reject_overclaiming_and_duplicates() -> None:
    with pytest.raises(FormatError, match="dropped events"):
        _sensor(
            "dishonest",
            SensorKind.HOST,
            SensorSurface.HOST,
            health="healthy",
            dropped=1,
        )
    with pytest.raises(FormatError, match="unavailable capture"):
        _sensor(
            "contradictory",
            SensorKind.KERNEL,
            SensorSurface.HOST,
            mode=CaptureMode.UNAVAILABLE,
        )
    duplicate = _sensor("same", SensorKind.HOST, SensorSurface.HOST)
    with pytest.raises(FormatError, match="duplicated"):
        SensorCoverageLedger((duplicate, duplicate))


def test_coverage_policy_rejects_duplicate_requirements() -> None:
    requirement = CoverageRequirement(SensorSurface.HOST, SensorKind.PROCESS)
    with pytest.raises(FormatError, match="unique"):
        SensorCoveragePolicy("policy", "claim", (requirement, requirement))
