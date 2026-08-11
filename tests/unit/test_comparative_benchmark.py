# SPDX-License-Identifier: Apache-2.0
"""Matched comparative benchmark protocol tests."""

from __future__ import annotations

import pytest

from sova.benchmarks import (
    BenchmarkObservation,
    ComparativeBenchmarkProtocol,
    evaluate_comparative_benchmark,
)
from sova.formats.errors import FormatError


def _protocol() -> ComparativeBenchmarkProtocol:
    return ComparativeBenchmarkProtocol(
        "sova:benchmark:fixture",
        "sova-oss",
        ("baseline-a", "baseline-b"),
        ("task-1", "task-2"),
        2,
        19,
    )


def _observations(protocol: ComparativeBenchmarkProtocol) -> tuple[BenchmarkObservation, ...]:
    rows = []
    for tool in protocol.tools:
        for case_id in protocol.case_ids:
            for trial in range(protocol.trials):
                passed = tool == protocol.candidate or (
                    tool == "baseline-a" and case_id == "task-1"
                )
                rows.append(
                    BenchmarkObservation(
                        protocol.digest,
                        tool,
                        case_id,
                        trial,
                        "pass" if passed else "fail",
                        1,
                        10,
                        "sha256:" + ("a" * 64),
                        "fixture-environment",
                    )
                )
    return tuple(rows)


def test_comparative_benchmark_reports_descriptive_not_general_advantage() -> None:
    protocol = _protocol()
    report = evaluate_comparative_benchmark(protocol, _observations(protocol))
    assert report["status"] == "complete"
    assert report["observedPrimaryMetricAdvantage"] is True
    assert report["candidatePassDeltaVsBestBaseline"] == 2
    assert report["claims"]["generalBenchmarkAdvantageEstablished"] is False
    assert report["claims"]["strongestBaselinesExternallyVerified"] is False


def test_comparative_benchmark_exposes_missing_or_inconclusive_runs() -> None:
    protocol = _protocol()
    observations = _observations(protocol)
    missing = evaluate_comparative_benchmark(protocol, observations[:-1])
    assert missing["status"] == "incomplete"
    assert len(missing["missing"]) == 1
    assert missing["observedPrimaryMetricAdvantage"] is False

    first = observations[0]
    inconclusive = BenchmarkObservation(
        first.protocol_digest,
        first.tool,
        first.case_id,
        first.trial,
        "inconclusive",
        first.attempts,
        first.duration_ms,
        first.artifact_digest,
        first.environment_id,
    )
    report = evaluate_comparative_benchmark(protocol, (inconclusive, *observations[1:]))
    assert report["status"] == "incomplete"


def test_comparative_benchmark_refuses_drift_duplicates_and_unknown_scope() -> None:
    protocol = _protocol()
    observations = _observations(protocol)
    with pytest.raises(FormatError, match="digest drifted"):
        evaluate_comparative_benchmark(
            protocol,
            (
                BenchmarkObservation(
                    "sha256:" + ("0" * 64),
                    "sova-oss",
                    "task-1",
                    0,
                    "pass",
                    1,
                    1,
                    "sha256:" + ("a" * 64),
                    "environment",
                ),
            ),
        )
    with pytest.raises(FormatError, match="duplicated"):
        evaluate_comparative_benchmark(protocol, (observations[0], observations[0]))
    with pytest.raises(FormatError, match="outside"):
        evaluate_comparative_benchmark(
            protocol,
            (
                BenchmarkObservation(
                    protocol.digest,
                    "unknown",
                    "task-1",
                    0,
                    "pass",
                    1,
                    1,
                    "sha256:" + ("a" * 64),
                    "environment",
                ),
            ),
        )


def test_comparative_protocol_and_observation_reject_invalid_shapes() -> None:
    with pytest.raises(FormatError, match="identity"):
        ComparativeBenchmarkProtocol("", "sova", ("baseline",), ("case",), 1, 1)
    with pytest.raises(FormatError, match="unique"):
        ComparativeBenchmarkProtocol("id", "same", ("same",), ("case",), 1, 1)
    with pytest.raises(FormatError, match="cases"):
        ComparativeBenchmarkProtocol("id", "sova", ("base",), ("case", "case"), 1, 1)
    with pytest.raises(FormatError, match="trials"):
        ComparativeBenchmarkProtocol("id", "sova", ("base",), ("case",), 0, 1)
    with pytest.raises(FormatError, match="result"):
        BenchmarkObservation(
            "sha256:" + "a" * 64,
            "sova",
            "case",
            0,
            "great",
            1,
            1,
            "sha256:" + "b" * 64,
            "env",
        )
    with pytest.raises(FormatError, match="counters"):
        BenchmarkObservation(
            "sha256:" + "a" * 64,
            "sova",
            "case",
            -1,
            "pass",
            1,
            1,
            "sha256:" + "b" * 64,
            "env",
        )
    with pytest.raises(FormatError, match="digest"):
        BenchmarkObservation("bad", "sova", "case", 0, "pass", 1, 1, "bad", "env")
