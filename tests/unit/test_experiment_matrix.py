# SPDX-License-Identifier: Apache-2.0
"""Provider-neutral experiment-matrix tests."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from sova.experiments import BehavioralCase, ExperimentPlan, run_experiment_matrix
from sova.formats.errors import FormatError


@dataclass(frozen=True, slots=True)
class _Response:
    response_text: str
    token_count: int | None = None


class _Model:
    def __init__(self, model_id: str, *, oracle_case: str | None = None) -> None:
        self.model_id = model_id
        self.oracle_case = oracle_case
        self.prompts: list[str] = []

    def respond(self, prompt: str) -> _Response:
        self.prompts.append(prompt)
        marker = " ACCEPT" if self.oracle_case is None or self.oracle_case in prompt else " REFUSE"
        return _Response(prompt.split(":", 1)[0] + marker, 4)


class _FailingModel(_Model):
    def respond(self, prompt: str) -> _Response:
        del prompt
        raise RuntimeError("synthetic provider failure")  # noqa: TRY003


class _NoTokenModel(_Model):
    def respond(self, prompt: str) -> _Response:
        del prompt
        return _Response("ACCEPT", -1)


def _plan(*, repetitions: int = 2) -> ExperimentPlan:
    return ExperimentPlan(
        "sova:experiment:fixture",
        (
            BehavioralCase("safe", "safe: respond", "ACCEPT"),
            BehavioralCase("conditional", "conditional: respond", "ACCEPT"),
        ),
        ("provider-a:model-1", "provider-b:model-2"),
        repetitions,
        19,
    )


def test_matrix_runs_paired_randomized_schedule_without_raw_content() -> None:
    plan = _plan()
    report = run_experiment_matrix(
        plan,
        {
            "provider-a:model-1": _Model("provider-a:model-1"),
            "provider-b:model-2": _Model(
                "provider-b:model-2",
                oracle_case="safe:",
            ),
        },
    )

    assert report["runCount"] == 8
    assert report["claims"]["crossProviderExecution"] is True
    assert report["claims"]["benchmarkSuperiorityEstablished"] is False
    aggregates = {row["modelId"]: row for row in report["aggregate"]}
    assert aggregates["provider-a:model-1"]["oraclePassRate"] == "4/4"
    assert aggregates["provider-b:model-2"]["oraclePassRate"] == "2/4"
    paired = report["pairedComparisons"][0]
    assert paired["leftOnlyPass"] == 2
    assert paired["statisticalSignificanceClaimed"] is False
    assert "safe: respond" not in str(report)
    assert "conditional: respond" not in str(report)


def test_matrix_records_provider_failure_class_without_error_text() -> None:
    plan = _plan(repetitions=1)
    report = run_experiment_matrix(
        plan,
        {
            "provider-a:model-1": _Model("provider-a:model-1"),
            "provider-b:model-2": _FailingModel("provider-b:model-2"),
        },
    )
    failures = [row for row in report["observations"] if row["status"] == "failed"]
    assert len(failures) == 2
    assert {row["failureClass"] for row in failures} == {"RuntimeError"}
    assert "synthetic provider failure" not in str(report)


def test_matrix_fails_closed_on_plan_and_runtime_identity_drift() -> None:
    with pytest.raises(FormatError, match="at least two"):
        ExperimentPlan(
            "one",
            (BehavioralCase("case", "prompt", "oracle"),),
            ("one:model",),
            1,
            1,
        )
    plan = _plan(repetitions=1)
    with pytest.raises(FormatError, match="differ"):
        run_experiment_matrix(plan, {"provider-a:model-1": _Model("provider-a:model-1")})
    with pytest.raises(FormatError, match="identity drifted"):
        run_experiment_matrix(
            plan,
            {
                "provider-a:model-1": _Model("wrong"),
                "provider-b:model-2": _Model("provider-b:model-2"),
            },
        )


def test_experiment_case_plan_budget_and_token_metadata_edges() -> None:
    with pytest.raises(FormatError, match="case"):
        BehavioralCase("", "prompt", "oracle")
    case = BehavioralCase("case", "prompt", "oracle")
    with pytest.raises(FormatError, match="case count"):
        ExperimentPlan("", (case,), ("a:model", "b:model"), 1, 1)
    with pytest.raises(FormatError, match="unique"):
        ExperimentPlan("id", (case, case), ("a:model", "b:model"), 1, 1)
    with pytest.raises(FormatError, match="repetition"):
        ExperimentPlan("id", (case,), ("a:model", "b:model"), 0, 1)
    with pytest.raises(FormatError, match="10,000"):
        ExperimentPlan(
            "large",
            tuple(BehavioralCase(f"case-{index}", "prompt", "oracle") for index in range(101)),
            ("a:model", "b:model"),
            50,
            1,
        )

    plan = ExperimentPlan("tokens", (case,), ("a:model", "b:model"), 1, 1)
    report = run_experiment_matrix(
        plan,
        {"a:model": _NoTokenModel("a:model"), "b:model": _NoTokenModel("b:model")},
    )
    assert all(row["tokenCount"] is None for row in report["observations"])
    assert report["claims"]["crossProviderExecution"] is True
