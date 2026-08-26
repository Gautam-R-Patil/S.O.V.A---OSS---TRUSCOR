# SPDX-License-Identifier: Apache-2.0
"""Strict configuration tests for the unified executor chamber."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import FrozenInstanceError
from typing import TYPE_CHECKING, Any, NoReturn

import pytest

import sova.community.executor_chamber_config as config_module
from sova.community.executor_chamber import (
    CompositeProjectionOracle,
    ExecutorChamberArtifacts,
    ProjectionFieldOracle,
    ProjectionPredicateOracle,
)
from sova.community.executor_chamber_config import (
    ExecutorChamberAuthorityPolicy,
    ParsedExecutorChamberPlan,
    ValidatedExecutorChamberDocument,
    parse_executor_chamber_document,
    run_executor_chamber_document,
    validate_executor_chamber_document,
)
from sova.formats.errors import FormatError
from sova.models import ScriptedModel, ScriptedTurn
from sova.providers import ProviderRoleModel
from sova.runtime import GVisorOciAgentAdapter, OciAgentRuntime

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

_IMAGE = "fixture/sova-agent@sha256:" + "a" * 64
_AUTHORITY_TARGET = "sova:sandbox:owned-executor-fixture"
_BOUNDARY_ERROR = "external boundary was reached before configuration admission"
_MODEL_ORDER_ERROR = "model materialized before complete validation"
_ENVIRONMENT_ORDER_ERROR = "environment created before complete validation"


def _scripted(identifier: str, value: str) -> dict[str, Any]:
    return {
        "adapter": "scripted",
        "modelId": f"fixture-{identifier}",
        "turns": [
            {
                "expectedContains": "sova.executor-chamber-planner/0.1.0",
                "responseText": "",
                "structured": {
                    "status": "continue",
                    "message": "bounded fixture proposal",
                    "actions": [{"grantId": "set-state", "arguments": {"value": value}}],
                    "coverage": ["fixture-state"],
                    "reason": "exercise the declared state transition",
                },
                "tokenCount": 1,
            }
        ],
    }


def _participant(identifier: str, value: str) -> dict[str, Any]:
    return {
        "id": identifier,
        "objective": "Exercise only the declared bounded state transition.",
        "allowedGrants": ["set-state"],
        "model": _scripted(identifier, value),
    }


def _document() -> dict[str, Any]:
    return {
        "artifactType": "sova.executor-chamber",
        "schemaVersion": "0.1.0",
        "authorization": {
            "authorityTarget": _AUTHORITY_TARGET,
            "providerCalls": False,
            "offensive": False,
        },
        "case": {
            "id": "owned-executor-fixture",
            "title": "Owned executor fixture",
            "objective": "Find and reproduce the declared observable state.",
        },
        "budget": {
            "rounds": 1,
            "maxActionsPerTurn": 1,
            "maxTotalActions": 2,
            "maxDurationSeconds": 30,
            "maxOutputBytes": 4096,
            "maxTotalTokens": 4,
            "maxMutations": 2,
            "maxProcesses": 0,
            "maxFiles": 0,
            "maxNetworkRequests": 0,
            "actionTimeoutSeconds": 5,
            "stopOnSuccess": True,
            "captureProfile": "forensic",
        },
        "grants": [
            {
                "id": "set-state",
                "bindingId": "fixture-binding",
                "codecId": "fixture-codec",
                "description": "Set one owned in-memory fixture value.",
                "argumentSchema": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["value"],
                    "properties": {"value": {"type": "string", "maxLength": 64}},
                },
            }
        ],
        "participants": [
            _participant("agent-a", "scanned"),
            _participant("agent-b", "vulnerable-observed"),
        ],
        "oracle": {
            "kind": "projection-field-contains",
            "fieldPath": ["state"],
            "contains": "vulnerable",
        },
    }


def _runtime(identifier: str, marker: str = "a") -> OciAgentRuntime:
    return OciAgentRuntime(
        identifier,
        f"fixture/sova-agent@sha256:{marker * 64}",
        "/opt/sova/agent",
    )


def _oci_adapter(runtime: OciAgentRuntime, workspace: Path) -> GVisorOciAgentAdapter:
    adapter = object.__new__(GVisorOciAgentAdapter)
    adapter.runtime = runtime
    adapter.executor = object()  # type: ignore[assignment]
    adapter.workspace = workspace
    return adapter


def _oci_document() -> dict[str, Any]:
    document = _document()
    document["participants"] = [document["participants"][0]]
    runtime = _runtime("agent-b")
    document["ociParticipants"] = [
        {
            "id": "agent-b",
            "objective": "Propose only the declared bounded state transition.",
            "allowedGrants": ["set-state"],
            "runtime": runtime.to_mapping(),
        }
    ]
    return document


def _provider_model() -> dict[str, Any]:
    return {
        "adapter": "provider",
        "provider": "openrouter",
        "model": "fixture/model",
        "temperature": 0,
        "maxOutputTokens": 128,
        "timeoutSeconds": 10,
    }


def _never(*_args: object, **_kwargs: object) -> NoReturn:
    raise AssertionError(_BOUNDARY_ERROR)


def test_parser_builds_frozen_secret_free_plan() -> None:
    plan = parse_executor_chamber_document(
        _document(),
        secret_resolver=lambda _name: None,
        provider_calls_authorized=False,
    )

    assert isinstance(plan, ParsedExecutorChamberPlan)
    assert plan.authority == ExecutorChamberAuthorityPolicy(
        authority_target=_AUTHORITY_TARGET,
        provider_calls=False,
        offensive=False,
    )
    assert plan.case.identifier == "owned-executor-fixture"
    assert [participant.identifier for participant in plan.case.participants] == [
        "agent-a",
        "agent-b",
    ]
    assert plan.budget.action_timeout_seconds == 5
    assert [grant.identifier for grant in plan.grants] == ["set-state"]
    assert set(plan.models) == {"agent-a", "agent-b"}
    assert all(type(model) is ScriptedModel for model in plan.models.values())
    assert isinstance(plan.oracle, ProjectionFieldOracle)
    assert plan.oracle.field_path == ("state",)
    assert plan.oci_participants == ()
    with pytest.raises(FrozenInstanceError):
        plan.case = plan.case  # type: ignore[misc]
    with pytest.raises(TypeError):
        plan.models["intruder"] = next(iter(plan.models.values()))  # type: ignore[index]


def test_parser_builds_typed_cross_surface_composite_oracle() -> None:
    document = _document()
    document["oracle"] = {
        "kind": "projection-all",
        "oracles": [
            {
                "kind": "projection-field-equals",
                "fieldPath": ["browser", "authenticated"],
                "value": True,
            },
            {
                "kind": "projection-field-number",
                "fieldPath": ["process", "output", "returncode"],
                "operator": "eq",
                "value": 0,
            },
            {
                "kind": "projection-field-count",
                "fieldPath": ["workspace", "documents"],
                "operator": "gte",
                "value": 2,
            },
        ],
    }
    plan = parse_executor_chamber_document(
        document,
        secret_resolver=lambda _name: None,
        provider_calls_authorized=False,
    )
    assert isinstance(plan.oracle, CompositeProjectionOracle)
    assert plan.oracle.mode == "all"
    assert all(isinstance(item, ProjectionPredicateOracle) for item in plan.oracle.children)


def test_pure_validator_returns_immutable_oci_admission_without_external_setup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = _oci_document()
    calls = {"model": 0, "run": 0}

    def model(*_args: object, **_kwargs: object) -> NoReturn:
        calls["model"] += 1
        raise AssertionError(_MODEL_ORDER_ERROR)

    def run(*_args: object, **_kwargs: object) -> NoReturn:
        calls["run"] += 1
        raise AssertionError(_BOUNDARY_ERROR)

    monkeypatch.setattr(config_module, "_model", model)
    monkeypatch.setattr(config_module, "run_executor_chamber", run)
    validated = validate_executor_chamber_document(
        document,
        provider_calls_authorized=False,
    )

    assert isinstance(validated, ValidatedExecutorChamberDocument)
    assert validated.document_digest.startswith("sha256:")
    assert validated.case.identifier == "owned-executor-fixture"
    assert validated.authority.authority_target == _AUTHORITY_TARGET
    assert [(model.participant_id, model.adapter) for model in validated.models] == [
        ("agent-a", "scripted"),
        ("agent-b", "gvisor-oci"),
    ]
    assert validated.models[-1].runtime_digest == validated.oci_participants[0].runtime.digest
    assert validated.grants[0].identifier == "set-state"
    assert validated.grants[0].argument_schema_digest.startswith("sha256:")
    assert calls == {"model": 0, "run": 0}

    document["grants"][0]["id"] = "source-mutated"
    document["ociParticipants"][0]["runtime"]["runtime"] = "runc"
    assert validated.grants[0].identifier == "set-state"
    assert validated.oci_participants[0].runtime.runtime == "runsc"
    with pytest.raises(FrozenInstanceError):
        validated.document_digest = _AUTHORITY_TARGET  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        validated.grants[0].identifier = "mutated"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("grant", "unknown grant"),
        ("budget", "participant-round action ceiling"),
        ("participant", "participant id is duplicated"),
        ("runtime", "fail-closed gVisor profile"),
    ),
)
def test_pure_validator_rejects_hostile_static_inputs_before_external_setup(
    mutation: str,
    message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = _oci_document() if mutation == "runtime" else _document()
    if mutation == "grant":
        document["participants"][0]["allowedGrants"] = ["undeclared"]
    elif mutation == "budget":
        document["budget"]["maxTotalActions"] = 3
    elif mutation == "participant":
        document["participants"].append(deepcopy(document["participants"][0]))
    else:
        document["ociParticipants"][0]["runtime"]["security"]["network"] = "bridge"
    calls = {"model": 0, "run": 0}

    def model(*_args: object, **_kwargs: object) -> NoReturn:
        calls["model"] += 1
        raise AssertionError(_MODEL_ORDER_ERROR)

    def run(*_args: object, **_kwargs: object) -> NoReturn:
        calls["run"] += 1
        raise AssertionError(_BOUNDARY_ERROR)

    monkeypatch.setattr(config_module, "_model", model)
    monkeypatch.setattr(config_module, "run_executor_chamber", run)
    with pytest.raises(FormatError, match=message):
        validate_executor_chamber_document(
            document,
            provider_calls_authorized=False,
        )
    assert calls == {"model": 0, "run": 0}


def test_pure_validator_enforces_provider_and_offensive_controls_without_materialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = _document()
    document["participants"][0]["model"] = _provider_model()
    document["authorization"]["providerCalls"] = True
    document["authorization"]["offensive"] = True
    monkeypatch.setattr(config_module, "_model", _never)

    with pytest.raises(FormatError, match="explicit runtime authorization"):
        validate_executor_chamber_document(
            document,
            provider_calls_authorized=False,
            offensive=True,
        )
    with pytest.raises(FormatError, match="must exactly match"):
        validate_executor_chamber_document(
            document,
            provider_calls_authorized=True,
            offensive=False,
        )

    validated = validate_executor_chamber_document(
        document,
        provider_calls_authorized=True,
        offensive=True,
    )
    assert validated.models[0].adapter == "provider"
    assert validated.authority.provider_calls is True
    assert validated.authority.offensive is True


def test_run_wrapper_routes_only_the_fully_parsed_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    expected = ExecutorChamberArtifacts(
        "not-observed",
        tmp_path / "report.json",
        tmp_path / "primary.sova-trace",
        None,
        None,
        tmp_path / "events.jsonl",
    )

    def fake_run(*args: object, **kwargs: object) -> ExecutorChamberArtifacts:
        captured["args"] = args
        captured["kwargs"] = kwargs
        return expected

    monkeypatch.setattr(config_module, "run_executor_chamber", fake_run)
    destination = tmp_path / "run"
    result = run_executor_chamber_document(
        _document(),
        destination,
        environment_factory=_never,
        authorization_factory=_never,
        codec_resolver=_never,
        secret_resolver=lambda _name: None,
        provider_calls_authorized=False,
    )

    assert result is expected
    args = captured["args"]
    kwargs = captured["kwargs"]
    assert args[0].identifier == "owned-executor-fixture"
    assert args[1][0].identifier == "set-state"
    assert set(args[2]) == {"agent-a", "agent-b"}
    assert args[3].max_total_actions == 2
    assert args[4] == destination
    assert isinstance(kwargs["oracle"], ProjectionFieldOracle)
    assert kwargs["authority_target"] == _AUTHORITY_TARGET
    assert kwargs["provider_calls_authorized"] is False
    assert kwargs["offensive"] is False


def test_complete_static_validation_precedes_model_or_environment_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = _document()
    document["participants"][0]["model"] = _provider_model()
    document["authorization"]["providerCalls"] = True
    document["oracle"]["kind"] = "model-judge"
    calls = {"model": 0, "environment": 0, "secret": 0}

    def materialize(*_args: object, **_kwargs: object) -> NoReturn:
        calls["model"] += 1
        raise AssertionError(_MODEL_ORDER_ERROR)

    def environment(_phase: str) -> NoReturn:
        calls["environment"] += 1
        raise AssertionError(_ENVIRONMENT_ORDER_ERROR)

    def secret(_name: str) -> None:
        calls["secret"] += 1

    monkeypatch.setattr(config_module, "_model", materialize)
    with pytest.raises(FormatError, match="oracle kind is unsupported"):
        run_executor_chamber_document(
            document,
            tmp_path / "invalid",
            environment_factory=environment,
            authorization_factory=_never,
            codec_resolver=_never,
            secret_resolver=secret,
            provider_calls_authorized=True,
        )
    assert calls == {"model": 0, "environment": 0, "secret": 0}


@pytest.mark.parametrize(
    ("failure", "message"),
    (
        ("missing", "exactly match declared OCI"),
        ("wrong-type", "exact gVisor OCI"),
        ("substitution", "runtime digest"),
        ("undeclared", "exactly match declared OCI"),
    ),
)
def test_oci_participants_reject_missing_wrong_substituted_or_undeclared_models(
    failure: str,
    message: str,
    tmp_path: Path,
) -> None:
    document = _oci_document()
    runtime = _runtime("agent-b")
    external: Mapping[str, Any]
    if failure == "missing":
        external = {}
    elif failure == "wrong-type":
        external = {
            "agent-b": ScriptedModel([ScriptedTurn("x", "", structured={})], model_id="wrong-type")
        }
    elif failure == "substitution":
        external = {"agent-b": _oci_adapter(_runtime("agent-b", "b"), tmp_path)}
    else:
        external = {
            "agent-b": _oci_adapter(runtime, tmp_path),
            "undeclared": _oci_adapter(_runtime("undeclared"), tmp_path),
        }

    with pytest.raises(FormatError, match=message):
        run_executor_chamber_document(
            document,
            tmp_path / failure,
            environment_factory=_never,
            authorization_factory=_never,
            codec_resolver=_never,
            secret_resolver=lambda _name: None,
            provider_calls_authorized=False,
            external_models=external,
        )


def test_exact_oci_adapter_and_runtime_digest_are_preserved_in_plan(tmp_path: Path) -> None:
    runtime = _runtime("agent-b")
    adapter = _oci_adapter(runtime, tmp_path)
    plan = parse_executor_chamber_document(
        _oci_document(),
        secret_resolver=lambda _name: None,
        provider_calls_authorized=False,
        external_models={"agent-b": adapter},
    )

    assert plan.models["agent-b"] is adapter
    assert type(plan.models["agent-b"]) is GVisorOciAgentAdapter
    assert plan.oci_participants[0].runtime.digest == adapter.runtime.digest
    assert plan.case.participants[-1] == plan.oci_participants[0].participant


def test_provider_models_require_document_policy_and_runtime_opt_in() -> None:
    document = _document()
    document["participants"][0]["model"] = _provider_model()
    document["authorization"]["providerCalls"] = True
    resolver_calls: list[str] = []

    def resolve(name: str) -> None:
        resolver_calls.append(name)

    with pytest.raises(FormatError, match="explicit runtime authorization"):
        parse_executor_chamber_document(
            document,
            secret_resolver=resolve,
            provider_calls_authorized=False,
        )
    assert resolver_calls == []

    document["authorization"]["providerCalls"] = False
    with pytest.raises(FormatError, match="policy does not admit"):
        parse_executor_chamber_document(
            document,
            secret_resolver=resolve,
            provider_calls_authorized=True,
        )
    assert resolver_calls == []

    document["authorization"]["providerCalls"] = True
    plan = parse_executor_chamber_document(
        document,
        secret_resolver=resolve,
        provider_calls_authorized=True,
    )
    assert type(plan.models["agent-a"]) is ProviderRoleModel
    assert resolver_calls == []


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("version", "unsupported"),
        ("unknown-field", "fields are invalid"),
        ("secret", "credential-shaped"),
        ("duplicate-participant", "participant id is duplicated"),
        ("duplicate-grant", "grant id is duplicated"),
        ("unknown-grant", "unknown grant"),
        ("unknown-model-field", "fields are invalid"),
        ("direct-tools", "cannot declare direct tool calls"),
        ("loose-action-budget", "participant-round action ceiling"),
    ),
)
def test_parser_rejects_hostile_document_shapes(mutation: str, message: str) -> None:
    document = deepcopy(_document())
    if mutation == "version":
        document["schemaVersion"] = "0.2.0"
    elif mutation == "unknown-field":
        document["unexpected"] = True
    elif mutation == "secret":
        document["case"]["objective"] = "Use Bearer abcdefghijklmnopqrstuvwxyz"
    elif mutation == "duplicate-participant":
        document["participants"].append(deepcopy(document["participants"][0]))
    elif mutation == "duplicate-grant":
        document["grants"].append(deepcopy(document["grants"][0]))
    elif mutation == "unknown-grant":
        document["participants"][0]["allowedGrants"] = ["undeclared"]
    elif mutation == "unknown-model-field":
        document["participants"][0]["model"]["unexpected"] = True
    elif mutation == "direct-tools":
        document["participants"][0]["model"]["turns"][0]["toolCalls"] = [
            {"name": "shell", "arguments": {}}
        ]
    else:
        document["budget"]["maxTotalActions"] = 3

    with pytest.raises(FormatError, match=message):
        parse_executor_chamber_document(
            document,
            secret_resolver=lambda _name: None,
            provider_calls_authorized=False,
        )


def test_offensive_policy_requires_exact_runtime_control() -> None:
    document = _document()
    document["authorization"]["offensive"] = True
    with pytest.raises(FormatError, match="must exactly match"):
        parse_executor_chamber_document(
            document,
            secret_resolver=lambda _name: None,
            provider_calls_authorized=False,
            offensive=False,
        )

    plan = parse_executor_chamber_document(
        document,
        secret_resolver=lambda _name: None,
        provider_calls_authorized=False,
        offensive=True,
    )
    assert plan.authority.offensive is True
