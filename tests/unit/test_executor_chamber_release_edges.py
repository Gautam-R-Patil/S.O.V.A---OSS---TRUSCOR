# SPDX-License-Identifier: Apache-2.0
"""Release-gate coverage for executor-chamber fail-closed contracts."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest

import sova.community.executor_chamber as chamber
from sova.community.executor_chamber import (
    ChamberObservation,
    ChamberVerification,
    CompositeProjectionOracle,
    ExecutorChamberBudget,
    ExecutorChamberCase,
    ExecutorChamberGrant,
    ExecutorChamberParticipant,
    OracleAssessment,
    ProjectionFieldOracle,
    ProjectionPredicateOracle,
)
from sova.executors import SideEffect
from sova.formats.errors import FormatError
from sova.safety import EffectClass

_DIGEST = "sha256:" + "a" * 64


def _observation(projection: dict[str, Any]) -> ChamberObservation:
    return ChamberObservation(cast("Any", SimpleNamespace(content_digest=_DIGEST)), projection)


@pytest.mark.parametrize(
    "changes",
    [
        {"rounds": 0},
        {"max_total_actions": True},
        {"max_duration_seconds": 0},
        {"max_output_bytes": 1},
        {"max_mutations": -1},
        {"max_processes": -1},
        {"max_files": -1},
        {"max_network_requests": -1},
        {"action_timeout_seconds": 0},
        {"max_total_tokens": True},
        {"max_total_tokens": 0},
        {"capture_profile": "minimal"},
    ],
)
def test_chamber_budget_rejects_every_out_of_contract_dimension(
    changes: dict[str, object],
) -> None:
    with pytest.raises(FormatError):
        ExecutorChamberBudget(**cast("Any", changes))


def test_chamber_public_contract_dataclasses_reject_ambiguous_or_sensitive_values() -> None:
    schema = {"type": "object"}
    with pytest.raises(FormatError, match="id"):
        ExecutorChamberGrant("bad id", "binding", "codec", "description", schema)
    with pytest.raises(FormatError, match="description"):
        ExecutorChamberGrant("grant", "binding", "codec", "", schema)
    with pytest.raises(FormatError, match="64 KiB"):
        ExecutorChamberGrant(
            "grant",
            "binding",
            "codec",
            "description",
            {"large": "x" * (64 * 1024)},
        )
    with pytest.raises(FormatError, match="secret-shaped"):
        ExecutorChamberGrant(
            "grant",
            "binding",
            "codec",
            "description",
            {"example": "sk-" + "syntheticcredential123456789"},
        )
    grant = ExecutorChamberGrant("grant", "binding", "codec", "description", schema)
    with pytest.raises(FormatError, match="another capability"):
        grant.prompt_mapping(cast("Any", SimpleNamespace(binding_id="other")))

    with pytest.raises(FormatError, match="objective"):
        ExecutorChamberParticipant("agent", "", ("grant",))
    with pytest.raises(FormatError, match="at least one"):
        ExecutorChamberParticipant("agent", "objective", ())
    with pytest.raises(FormatError, match="duplicated"):
        ExecutorChamberParticipant("agent", "objective", ("grant", "grant"))
    participant = ExecutorChamberParticipant("agent", "objective", ("grant",))
    with pytest.raises(FormatError, match="title and objective"):
        ExecutorChamberCase("case", "", "objective", (participant, participant))
    with pytest.raises(FormatError, match="between two and eight"):
        ExecutorChamberCase("case", "title", "objective", (participant,))
    with pytest.raises(FormatError, match="duplicated"):
        ExecutorChamberCase("case", "title", "objective", (participant, participant))


def test_observation_and_verification_contracts_reject_invalid_evidence() -> None:
    with pytest.raises(FormatError, match="256 KiB"):
        _observation({"large": "x" * (256 * 1024)})
    with pytest.raises(FormatError, match="redaction count"):
        ChamberObservation(cast("Any", SimpleNamespace(content_digest=_DIGEST)), {}, -1)
    with pytest.raises(FormatError, match="independence"):
        ChamberVerification(
            verified=True, independence="model-self-report", method="method", evidence_digests=()
        )
    with pytest.raises(FormatError, match="method"):
        ChamberVerification(
            verified=True, independence="agent-independent", method="", evidence_digests=()
        )
    with pytest.raises(FormatError, match="digest"):
        ChamberVerification(
            verified=True,
            independence="agent-independent",
            method="method",
            evidence_digests=("bad",),
        )
    with pytest.raises(FormatError, match="duplicated"):
        ChamberVerification(
            verified=True,
            independence="agent-independent",
            method="method",
            evidence_digests=(_DIGEST,),
            satisfied_evidence=("snapshot", "snapshot"),
        )


def test_projection_oracles_cover_missing_wrong_type_numeric_count_and_composition() -> None:
    with pytest.raises(FormatError, match="projection field oracle"):
        ProjectionFieldOracle((), "marker")
    with pytest.raises(FormatError, match="projection field oracle"):
        ProjectionFieldOracle(("state",), "")
    with pytest.raises(FormatError, match="typed projection"):
        ProjectionPredicateOracle((), "equals", expected=True)
    with pytest.raises(FormatError, match="exact boolean"):
        ProjectionPredicateOracle(("state",), "exists", 1)
    with pytest.raises(FormatError, match="finite number"):
        ProjectionPredicateOracle(("state",), "number-gt", expected=True)

    observation = _observation(
        {
            "state": {
                "text": "SOVA MARKER",
                "number": 4,
                "truth": True,
                "items": [1, 2, 3],
                "object": {"a": 1, "b": 2},
            }
        }
    )
    verification = ChamberVerification(
        verified=True,
        independence="agent-independent",
        method="fixture",
        evidence_digests=("sha256:" + "b" * 64,),
    )
    field = ProjectionFieldOracle(("state", "text"), "MARKER", "oracle-field")
    assert field.evaluate(observation, (), (verification,)).assessment is OracleAssessment.OBSERVED
    assert (
        ProjectionFieldOracle(("state", "missing"), "x", "oracle-missing")
        .evaluate(observation, (), ())
        .assessment
        is OracleAssessment.NOT_OBSERVED
    )

    rows = (
        ("exists", True, ("state", "number"), True),
        ("exists", False, ("state", "missing"), True),
        ("equals", 4, ("state", "number"), True),
        ("number-eq", 4, ("state", "number"), True),
        ("number-gt", 3, ("state", "number"), True),
        ("number-gte", 4, ("state", "number"), True),
        ("number-lt", 5, ("state", "number"), True),
        ("number-lte", 4, ("state", "number"), True),
        ("count-eq", 3, ("state", "items"), True),
        ("count-gt", 2, ("state", "items"), True),
        ("count-gte", 2, ("state", "object"), True),
        ("count-lt", 4, ("state", "items"), True),
        ("count-lte", 3, ("state", "items"), True),
        ("number-gt", 1, ("state", "truth"), False),
        ("count-eq", 1, ("state", "number"), False),
        ("number-eq", 1, ("state", "missing"), False),
    )
    children = []
    for index, (operator, expected, path, matched) in enumerate(rows):
        oracle = ProjectionPredicateOracle(path, operator, expected, f"oracle-{index}")
        result = oracle.evaluate(observation, (), (verification,))
        assert (result.assessment is OracleAssessment.OBSERVED) is matched
        children.append(oracle)

    with pytest.raises(FormatError, match="composite oracle"):
        CompositeProjectionOracle("none", (children[0], children[1]))
    with pytest.raises(FormatError, match="composite oracle"):
        CompositeProjectionOracle("all", (children[0],))
    all_oracle = CompositeProjectionOracle("all", (children[0], children[2]))
    any_oracle = CompositeProjectionOracle("any", (children[0], children[-1]))
    assert all_oracle.evaluate(observation, (), ()).assessment is OracleAssessment.OBSERVED
    assert any_oracle.evaluate(observation, (), ()).assessment is OracleAssessment.OBSERVED


def test_chamber_private_boundary_helpers_reject_malformed_model_and_coordination_data() -> None:
    assert chamber._coordination_context(None, "agent") == {}
    with pytest.raises(FormatError, match="must return an object"):
        chamber._coordination_context(cast("Any", lambda _agent: []), "agent")
    with pytest.raises(FormatError, match="64 KiB"):
        chamber._coordination_context(lambda _agent: {"large": "x" * (64 * 1024)}, "agent")
    with pytest.raises(FormatError, match="secret-shaped"):
        chamber._coordination_context(
            lambda _agent: {"value": "sk-" + "syntheticcredential123456789"},
            "agent",
        )

    budget = ExecutorChamberBudget(max_output_bytes=1024)

    def model(response: object) -> SimpleNamespace:
        return SimpleNamespace(
            model_id="fixture-model",
            respond=lambda _prompt: response,
        )

    valid = {
        "status": "stop",
        "message": "done",
        "actions": [],
        "coverage": ["fixture"],
        "reason": "bounded",
    }
    invalid = (
        SimpleNamespace(response_text="", structured=valid, tool_calls=({},), token_count=1),
        SimpleNamespace(response_text="x" * 2000, structured=valid, tool_calls=(), token_count=1),
        SimpleNamespace(response_text="", structured=[], tool_calls=(), token_count=1),
        SimpleNamespace(
            response_text="",
            structured={**valid, "status": "invalid"},
            tool_calls=(),
            token_count=1,
        ),
        SimpleNamespace(
            response_text="",
            structured={**valid, "message": 1},
            tool_calls=(),
            token_count=1,
        ),
        SimpleNamespace(
            response_text="",
            structured={**valid, "reason": 1},
            tool_calls=(),
            token_count=1,
        ),
        SimpleNamespace(
            response_text="",
            structured={**valid, "actions": [{"bad": True}]},
            tool_calls=(),
            token_count=1,
        ),
        SimpleNamespace(
            response_text="",
            structured={**valid, "status": "continue"},
            tool_calls=(),
            token_count=1,
        ),
        SimpleNamespace(
            response_text="",
            structured={
                **valid,
                "actions": [{"grantId": "grant", "arguments": {}}],
            },
            tool_calls=(),
            token_count=1,
        ),
        SimpleNamespace(
            response_text="",
            structured={**valid, "coverage": [1]},
            tool_calls=(),
            token_count=1,
        ),
        SimpleNamespace(
            response_text="",
            structured={**valid, "message": "sk-" + "syntheticcredential123456789"},
            tool_calls=(),
            token_count=1,
        ),
        SimpleNamespace(response_text="", structured=valid, tool_calls=(), token_count=True),
    )
    for response in invalid:
        with pytest.raises(FormatError):
            chamber._model_output(model(response), "prompt", budget)

    safe, usage = chamber._model_output(
        model(SimpleNamespace(response_text="", structured=valid, tool_calls=(), token_count=None)),
        "prompt",
        budget,
    )
    assert safe == valid and usage["tokenCount"] is None

    chamber._safe_public_value({"safe": True}, code="SAFE", message="safe")
    with pytest.raises(FormatError, match="sensitive"):
        chamber._safe_public_value(
            {"secret": "sk-" + "syntheticcredential123456789"},
            code="SENSITIVE",
            message="sensitive",
        )


def test_effect_and_approval_classification_covers_read_mutate_external_and_destructive() -> None:
    def binding(action: str, side_effect: SideEffect) -> Any:
        return SimpleNamespace(capability_name=action, side_effect=side_effect)

    assert chamber._effect_class(binding("fixture.read", SideEffect.READ)) is EffectClass.READ
    assert chamber._effect_class(binding("fixture.write", SideEffect.MUTATE)) is EffectClass.MUTATE
    assert (
        chamber._effect_class(binding("browser.click", SideEffect.MUTATE)) is EffectClass.EXTERNAL
    )
    assert (
        chamber._effect_class(binding("fixture.delete", SideEffect.DESTRUCTIVE))
        is EffectClass.DESTRUCTIVE
    )
    assert (
        chamber._approval_level(
            cast("Any", SimpleNamespace(offensive=False, effect=EffectClass.READ))
        )
        is None
    )
