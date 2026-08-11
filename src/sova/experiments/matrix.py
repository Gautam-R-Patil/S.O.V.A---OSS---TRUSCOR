# SPDX-License-Identifier: Apache-2.0
"""Predeclared, provider-neutral behavioral experiment matrix."""

from __future__ import annotations

from dataclasses import dataclass
from random import Random
from typing import Any, Protocol

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

_MAX_CASES = 1_000
_MAX_REPETITIONS = 100
_MAX_RUNS = 10_000
_MAX_PROMPT_BYTES = 1024 * 1024
_MIN_MODELS = 2


class ObservableResponse(Protocol):
    @property
    def response_text(self) -> str: ...


class ExperimentModel(Protocol):
    @property
    def model_id(self) -> str: ...

    def respond(self, prompt: str) -> ObservableResponse: ...


@dataclass(frozen=True, slots=True)
class BehavioralCase:
    identifier: str
    prompt: str
    oracle_contains: str

    def __post_init__(self) -> None:
        if (
            not self.identifier
            or not self.prompt
            or not self.oracle_contains
            or len(self.prompt.encode()) > _MAX_PROMPT_BYTES
        ):
            raise FormatError("SOVA-EXPERIMENT-CASE", "behavioral case is invalid")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "id": self.identifier,
            "promptDigest": sha256_digest(self.prompt.encode()),
            "oracle": {"kind": "text-contains", "value": self.oracle_contains},
        }


@dataclass(frozen=True, slots=True)
class ExperimentPlan:
    identifier: str
    cases: tuple[BehavioralCase, ...]
    model_ids: tuple[str, ...]
    repetitions: int
    seed: int

    def __post_init__(self) -> None:
        if not self.identifier or not 1 <= len(self.cases) <= _MAX_CASES:
            raise FormatError("SOVA-EXPERIMENT-PLAN", "experiment id or case count is invalid")
        if len({case.identifier for case in self.cases}) != len(self.cases):
            raise FormatError("SOVA-EXPERIMENT-PLAN", "experiment case ids must be unique")
        if len(self.model_ids) < _MIN_MODELS or len(set(self.model_ids)) != len(self.model_ids):
            raise FormatError(
                "SOVA-EXPERIMENT-PLAN",
                "cross-model experiment requires at least two unique model ids",
            )
        if any(not item for item in self.model_ids) or not (
            1 <= self.repetitions <= _MAX_REPETITIONS
        ):
            raise FormatError("SOVA-EXPERIMENT-PLAN", "model ids or repetition count is invalid")
        if self.run_count > _MAX_RUNS:
            raise FormatError("SOVA-EXPERIMENT-BUDGET", "experiment exceeds 10,000 runs")

    @property
    def run_count(self) -> int:
        return len(self.cases) * len(self.model_ids) * self.repetitions

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.provider-experiment-plan",
            "schemaVersion": "0.1.0",
            "id": self.identifier,
            "cases": [case.to_mapping() for case in self.cases],
            "models": list(self.model_ids),
            "repetitions": self.repetitions,
            "seed": self.seed,
            "runCount": self.run_count,
            "rawPromptsEmbedded": False,
        }


@dataclass(frozen=True, slots=True)
class ExperimentObservation:
    schedule_index: int
    model_id: str
    case_id: str
    repetition: int
    status: str
    oracle_passed: bool
    response_digest: str | None
    response_bytes: int | None
    token_count: int | None
    failure_class: str | None

    def to_mapping(self) -> dict[str, Any]:
        return {
            "scheduleIndex": self.schedule_index,
            "modelId": self.model_id,
            "caseId": self.case_id,
            "repetition": self.repetition,
            "status": self.status,
            "oraclePassed": self.oracle_passed,
            "responseDigest": self.response_digest,
            "responseBytes": self.response_bytes,
            "tokenCount": self.token_count,
            "failureClass": self.failure_class,
        }


def _token_count(response: ObservableResponse) -> int | None:
    value = getattr(response, "token_count", None)
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _schedule(plan: ExperimentPlan) -> list[tuple[str, BehavioralCase, int]]:
    rows = [
        (model_id, case, repetition)
        for repetition in range(plan.repetitions)
        for case in plan.cases
        for model_id in plan.model_ids
    ]
    Random(plan.seed).shuffle(rows)  # noqa: S311 - reproducible experimental schedule
    return rows


def _aggregate(
    plan: ExperimentPlan,
    observations: tuple[ExperimentObservation, ...],
) -> list[dict[str, Any]]:
    rows = []
    for model_id in plan.model_ids:
        selected = [item for item in observations if item.model_id == model_id]
        passed = sum(item.oracle_passed for item in selected)
        completed = sum(item.status == "completed" for item in selected)
        lengths = [item.response_bytes for item in selected if item.response_bytes is not None]
        rows.append(
            {
                "modelId": model_id,
                "runs": len(selected),
                "completed": completed,
                "failed": len(selected) - completed,
                "oraclePasses": passed,
                "oraclePassRate": f"{passed}/{len(selected)}",
                "meanResponseBytes": (None if not lengths else str(sum(lengths) // len(lengths))),
            }
        )
    return rows


def _pairwise(
    plan: ExperimentPlan,
    observations: tuple[ExperimentObservation, ...],
) -> list[dict[str, Any]]:
    indexed = {
        (item.model_id, item.case_id, item.repetition): item.oracle_passed for item in observations
    }
    rows: list[dict[str, Any]] = []
    for left_index, left in enumerate(plan.model_ids):
        for right in plan.model_ids[left_index + 1 :]:
            pairs = [
                (
                    indexed[(left, case.identifier, repetition)],
                    indexed[(right, case.identifier, repetition)],
                )
                for repetition in range(plan.repetitions)
                for case in plan.cases
            ]
            rows.append(
                {
                    "left": left,
                    "right": right,
                    "bothPass": sum(a and b for a, b in pairs),
                    "leftOnlyPass": sum(a and not b for a, b in pairs),
                    "rightOnlyPass": sum(b and not a for a, b in pairs),
                    "bothFail": sum(not a and not b for a, b in pairs),
                    "statisticalSignificanceClaimed": False,
                }
            )
    return rows


def run_experiment_matrix(
    plan: ExperimentPlan,
    models: dict[str, ExperimentModel],
) -> dict[str, Any]:
    """Execute a randomized, paired schedule and retain observable digests only."""
    if set(models) != set(plan.model_ids):
        raise FormatError("SOVA-EXPERIMENT-MODELS", "runtime models differ from preregistration")
    if any(models[key].model_id != key for key in models):
        raise FormatError("SOVA-EXPERIMENT-MODELS", "runtime model identity drifted")
    observations: list[ExperimentObservation] = []
    for index, (model_id, case, repetition) in enumerate(_schedule(plan)):
        try:
            response = models[model_id].respond(case.prompt)
            encoded = response.response_text.encode()
            observations.append(
                ExperimentObservation(
                    index,
                    model_id,
                    case.identifier,
                    repetition,
                    "completed",
                    case.oracle_contains in response.response_text,
                    sha256_digest(encoded),
                    len(encoded),
                    _token_count(response),
                    None,
                )
            )
        except (FormatError, RuntimeError) as error:
            observations.append(
                ExperimentObservation(
                    schedule_index=index,
                    model_id=model_id,
                    case_id=case.identifier,
                    repetition=repetition,
                    status="failed",
                    oracle_passed=False,
                    response_digest=None,
                    response_bytes=None,
                    token_count=None,
                    failure_class=type(error).__name__,
                )
            )
    result_rows = tuple(observations)
    report = {
        "artifactType": "sova.provider-experiment-report",
        "schemaVersion": "0.1.0",
        "planDigest": plan.digest,
        "runCount": len(result_rows),
        "observations": [item.to_mapping() for item in result_rows],
        "aggregate": _aggregate(plan, result_rows),
        "pairedComparisons": _pairwise(plan, result_rows),
        "privacy": {
            "rawPromptsRecorded": False,
            "rawResponsesRecorded": False,
            "credentialsRecorded": False,
        },
        "claims": {
            "crossModelExecution": True,
            "crossProviderExecution": len({item.split(":", 1)[0] for item in plan.model_ids}) > 1,
            "semanticEquivalenceJudged": False,
            "benchmarkSuperiorityEstablished": False,
            "privateThoughtsCaptured": False,
        },
        "limitations": [
            "Oracle validity is limited to the predeclared observable text predicate.",
            "Provider labels are declarations unless corroborated by provider receipts.",
            "A completed matrix is not independent validation or proof of generality.",
        ],
    }
    report["digest"] = sha256_digest(canonical_json_bytes(report))
    return report


__all__ = [
    "BehavioralCase",
    "ExperimentModel",
    "ExperimentObservation",
    "ExperimentPlan",
    "ObservableResponse",
    "run_experiment_matrix",
]
