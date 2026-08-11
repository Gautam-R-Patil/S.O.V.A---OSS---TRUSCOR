# SPDX-License-Identifier: Apache-2.0
"""Matched-task comparative benchmark protocol and honest advantage accounting."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

_MAX_CASES = 10_000
_MAX_TRIALS = 100
_DIGEST_LENGTH = 71


@dataclass(frozen=True, slots=True)
class ComparativeBenchmarkProtocol:
    identifier: str
    candidate: str
    baselines: tuple[str, ...]
    case_ids: tuple[str, ...]
    trials: int
    seed: int

    def __post_init__(self) -> None:
        tools = (self.candidate, *self.baselines)
        if not self.identifier or not self.candidate or not self.baselines:
            raise FormatError("SOVA-BENCHMARK-PROTOCOL", "protocol identity and baseline required")
        if len(set(tools)) != len(tools) or any(not item for item in tools):
            raise FormatError("SOVA-BENCHMARK-PROTOCOL", "benchmark tool identities must be unique")
        if not 1 <= len(self.case_ids) <= _MAX_CASES or len(set(self.case_ids)) != len(
            self.case_ids
        ):
            raise FormatError("SOVA-BENCHMARK-PROTOCOL", "benchmark cases are invalid")
        if any(not item for item in self.case_ids) or not 1 <= self.trials <= _MAX_TRIALS:
            raise FormatError("SOVA-BENCHMARK-PROTOCOL", "benchmark trials are invalid")

    @property
    def tools(self) -> tuple[str, ...]:
        return (self.candidate, *self.baselines)

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.comparative-benchmark-protocol",
            "schemaVersion": "0.1.0",
            "id": self.identifier,
            "candidate": self.candidate,
            "baselines": list(self.baselines),
            "caseIds": list(self.case_ids),
            "trials": self.trials,
            "seed": self.seed,
            "primaryMetric": "objective-oracle-success-count",
            "secondaryMetrics": ["attempts", "durationMilliseconds"],
        }


@dataclass(frozen=True, slots=True)
class BenchmarkObservation:
    protocol_digest: str
    tool: str
    case_id: str
    trial: int
    result: str
    attempts: int
    duration_ms: int
    artifact_digest: str
    environment_id: str
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.result not in {"pass", "fail", "inconclusive"}:
            raise FormatError("SOVA-BENCHMARK-OBSERVATION", "benchmark result is invalid")
        if self.trial < 0 or self.attempts < 0 or self.duration_ms < 0 or not self.environment_id:
            raise FormatError("SOVA-BENCHMARK-OBSERVATION", "benchmark counters are invalid")
        for digest in (self.protocol_digest, self.artifact_digest):
            if not digest.startswith("sha256:") or len(digest) != _DIGEST_LENGTH:
                raise FormatError("SOVA-BENCHMARK-OBSERVATION", "benchmark digest is invalid")


def _expected(protocol: ComparativeBenchmarkProtocol) -> set[tuple[str, str, int]]:
    return {
        (tool, case_id, trial)
        for tool in protocol.tools
        for case_id in protocol.case_ids
        for trial in range(protocol.trials)
    }


def evaluate_comparative_benchmark(
    protocol: ComparativeBenchmarkProtocol,
    observations: tuple[BenchmarkObservation, ...],
) -> dict[str, Any]:
    """Evaluate complete matched-task outcomes without manufacturing a superiority claim."""
    if any(item.protocol_digest != protocol.digest for item in observations):
        raise FormatError("SOVA-BENCHMARK-PROTOCOL", "observation protocol digest drifted")
    keys = [(item.tool, item.case_id, item.trial) for item in observations]
    if len(keys) != len(set(keys)):
        raise FormatError("SOVA-BENCHMARK-DUPLICATE", "benchmark observation is duplicated")
    unknown = set(keys) - _expected(protocol)
    if unknown:
        raise FormatError("SOVA-BENCHMARK-SCOPE", "observation is outside benchmark protocol")
    indexed = dict(zip(keys, observations, strict=True))
    missing = sorted(_expected(protocol) - set(indexed))
    aggregates: list[dict[str, Any]] = []
    passes_by_tool: dict[str, int] = {}
    for tool in protocol.tools:
        selected = [item for item in observations if item.tool == tool]
        passes = sum(item.result == "pass" for item in selected)
        conclusive = sum(item.result != "inconclusive" for item in selected)
        passes_by_tool[tool] = passes
        aggregates.append(
            {
                "tool": tool,
                "observedRuns": len(selected),
                "passes": passes,
                "conclusiveRuns": conclusive,
                "successRate": f"{passes}/{len(selected)}" if selected else None,
                "attempts": sum(item.attempts for item in selected),
                "durationMilliseconds": sum(item.duration_ms for item in selected),
            }
        )
    complete = not missing and all(item.result != "inconclusive" for item in observations)
    best_baseline_passes = max(passes_by_tool[item] for item in protocol.baselines)
    candidate_passes = passes_by_tool[protocol.candidate]
    observed_advantage = complete and candidate_passes > best_baseline_passes
    report = {
        "artifactType": "sova.comparative-benchmark-report",
        "schemaVersion": "0.1.0",
        "protocolDigest": protocol.digest,
        "status": "complete" if complete else "incomplete",
        "expectedRuns": len(_expected(protocol)),
        "observedRuns": len(observations),
        "missing": [
            {"tool": tool, "caseId": case_id, "trial": trial} for tool, case_id, trial in missing
        ],
        "aggregate": aggregates,
        "observedPrimaryMetricAdvantage": observed_advantage,
        "candidatePassDeltaVsBestBaseline": candidate_passes - best_baseline_passes,
        "claims": {
            "matchedProtocolComplete": complete,
            "strongestBaselinesExternallyVerified": False,
            "statisticalSignificanceEstablished": False,
            "independentlyReplicated": False,
            "generalBenchmarkAdvantageEstablished": False,
        },
        "limitations": [
            "The protocol author must justify that named baselines are the strongest "
            "relevant ones.",
            "Primary-metric advantage is descriptive until uncertainty and independent "
            "replication pass.",
            "Tool instrumentation and execution environments may introduce unequal blind spots.",
        ],
    }
    report["digest"] = sha256_digest(canonical_json_bytes(report))
    return report


__all__ = [
    "BenchmarkObservation",
    "ComparativeBenchmarkProtocol",
    "evaluate_comparative_benchmark",
]
