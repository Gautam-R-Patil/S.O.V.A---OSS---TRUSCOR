# SPDX-License-Identifier: Apache-2.0
"""Validation and safety edge cases for the Arena chamber."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from sova.community import (
    ArenaChamberAction,
    ArenaChamberBudget,
    ArenaChamberCase,
    ArenaChamberMode,
    ArenaChamberParticipant,
    run_arena_chamber,
    run_arena_chamber_document,
)
from sova.community import chamber as chamber_module
from sova.community import chamber_config as config_module
from sova.community.chamber import LiveEventJournal, SyntheticArenaEnvironment
from sova.formats.errors import FormatError
from sova.models import ScriptedModel, ScriptedTurn

if TYPE_CHECKING:
    from pathlib import Path

    from sova.runtime import RoleModel


def _action(
    identifier: str = "read",
    action: str = "filesystem.read",
    inputs: dict[str, Any] | None = None,
) -> ArenaChamberAction:
    return ArenaChamberAction(
        identifier,
        action,
        "safe fixture action",
        inputs or {"path": "/home/researcher/README.txt"},
    )


def _participant(
    identifier: str = "agent",
    allowed: tuple[str, ...] = ("read",),
) -> ArenaChamberParticipant:
    return ArenaChamberParticipant(identifier, "observe the fixture", allowed)


def _case(
    participants: tuple[ArenaChamberParticipant, ...] | None = None,
    *,
    mode: ArenaChamberMode = ArenaChamberMode.AGENT_VS_ENVIRONMENT,
    judge: str | None = None,
) -> ArenaChamberCase:
    return ArenaChamberCase(
        "case",
        "case title",
        mode,
        participants or (_participant(),),
        judge,
        ("filesystem.read",),
        "seed",
    )


@pytest.mark.parametrize(
    "values",
    [
        {"rounds": 0},
        {"max_actions_per_turn": 17},
        {"max_total_actions": 0},
        {"max_duration_seconds": 0},
        {"max_output_bytes": 10},
        {"max_total_tokens": 0},
        {"capture_profile": "lite"},
    ],
)
def test_budget_rejects_invalid_limits(values: dict[str, Any]) -> None:
    with pytest.raises(FormatError):
        ArenaChamberBudget(**values)


@pytest.mark.parametrize(
    ("identifier", "action", "description", "inputs"),
    [
        ("bad id", "filesystem.read", "safe", {"path": "/home/researcher/x"}),
        ("ok", "process.spawn", "safe", {}),
        ("ok", "filesystem.read", "", {"path": "/home/researcher/x"}),
        ("ok", "filesystem.read", "safe", {"text": "x" * 70_000}),
    ],
)
def test_action_contract_rejects_unsafe_shape(
    identifier: str,
    action: str,
    description: str,
    inputs: dict[str, Any],
) -> None:
    with pytest.raises(FormatError):
        ArenaChamberAction(identifier, action, description, inputs)


def test_case_and_participant_topology_validation() -> None:
    with pytest.raises(FormatError):
        _participant("bad id")
    with pytest.raises(FormatError):
        _participant(allowed=("read", "read"))
    with pytest.raises(FormatError):
        _case(mode=ArenaChamberMode.AGENT_VS_AGENT)
    with pytest.raises(FormatError):
        _case(mode=ArenaChamberMode.MULTI_AGENT)
    with pytest.raises(FormatError):
        _case((_participant(), _participant()), mode=ArenaChamberMode.AGENT_VS_AGENT)
    with pytest.raises(FormatError):
        _case(judge="agent")
    with pytest.raises(FormatError):
        ArenaChamberParticipant("agent", "", ())
    for identifier, title, participants, seed in (
        ("bad id", "title", (_participant(),), "seed"),
        ("case", "", (_participant(),), "seed"),
        ("case", "title", (), "seed"),
        ("case", "title", (_participant(),), ""),
    ):
        with pytest.raises(FormatError):
            ArenaChamberCase(
                identifier,
                title,
                ArenaChamberMode.AGENT_VS_ENVIRONMENT,
                participants,
                None,
                ("filesystem.read",),
                seed,
            )
    with pytest.raises(FormatError):
        ArenaChamberCase(
            "case",
            "title",
            ArenaChamberMode.AGENT_VS_ENVIRONMENT,
            (_participant(),),
            None,
            ("not-an-event",),
            "seed",
        )


def test_synthetic_environment_enforces_closed_paths_and_sink_only_network() -> None:
    environment = SyntheticArenaEnvironment("sova:run:test", "seed")
    try:
        with pytest.raises(FormatError, match="stay under"):
            environment.execute(
                "agent",
                _action(inputs={"path": "C:/host/secret"}),
                {"path": "C:/host/secret"},
            )
        write = _action(
            "write",
            "filesystem.write",
            {"path": "/home/researcher/private.txt", "content": "x"},
        )
        with pytest.raises(FormatError, match="workspace or notes"):
            environment.execute("agent", write, write.inputs)
        network = _action(
            "send",
            "network.send",
            {"destination": "example.com", "body": "x"},
        )
        with pytest.raises(FormatError, match=r"\.invalid"):
            environment.execute("agent", network, network.inputs)
        oversized = _action(inputs={"path": "/home/researcher/README.txt"})
        with pytest.raises(FormatError, match="64 KiB"):
            environment.execute("agent", oversized, {"text": "x" * 70_000})
    finally:
        environment.close()


def test_synthetic_environment_supports_declared_service_families() -> None:
    environment = SyntheticArenaEnvironment("sova:run:services", "seed")
    cases: tuple[tuple[str, dict[str, Any]], ...] = (
        ("database.read", {"table": "customers", "id": "CUST-001"}),
        (
            "database.update",
            {"table": "billing", "id": "BILL-001", "changes": {"status": "review"}},
        ),
        ("api.email.send", {"to": "fixture@example.invalid", "body": "hello"}),
        ("api.messaging.send", {"to": "fixture", "body": "hello"}),
        ("api.storage.put", {"key": "result", "value": "ok"}),
        ("api.storage.get", {"key": "result"}),
        ("api.payment.prepare", {"amountMinor": 1}),
        ("api.payment.release", {"amountMinor": 1, "approved": False}),
        ("network.send", {"destination": "sink.sova.invalid", "body": "fixture"}),
    )
    try:
        for index, (name, inputs) in enumerate(cases):
            result = environment.execute(
                "agent",
                ArenaChamberAction(f"a{index}", name, "fixture operation", inputs),
                inputs,
            )
            assert result.state_digest.startswith("sha256:")
            assert result.observations
        observed = environment.observe_message("agent", (), "sha256:" + "0" * 64)
        assert observed.kind == "inter-agent.message"
        assert environment.health_report()["process"] == "missing"
    finally:
        environment.close()


def test_run_requires_exact_authority_models_and_action_grants(tmp_path: Path) -> None:
    case = _case()
    model = ScriptedModel(
        [
            ScriptedTurn(
                '"id":"agent"',
                "",
                {"message": "ok", "actions": [], "signals": []},
            )
        ]
    )
    with pytest.raises(FormatError, match="explicit authorization"):
        run_arena_chamber(
            case,
            (_action(),),
            {"agent": model},
            ArenaChamberBudget(),
            tmp_path / "unauthorized",
            contained_fixture_authorized=False,
            provider_calls_authorized=False,
        )
    with pytest.raises(FormatError, match="missing"):
        run_arena_chamber(
            case,
            (_action(),),
            {},
            ArenaChamberBudget(),
            tmp_path / "missing",
            contained_fixture_authorized=True,
            provider_calls_authorized=False,
        )
    bad_case = _case((_participant(allowed=("unknown",)),))
    with pytest.raises(FormatError, match="unknown actions"):
        run_arena_chamber(
            bad_case,
            (_action(),),
            {"agent": model},
            ArenaChamberBudget(),
            tmp_path / "unknown",
            contained_fixture_authorized=True,
            provider_calls_authorized=False,
        )
    with pytest.raises(FormatError, match="empty or duplicated"):
        run_arena_chamber(
            case,
            (),
            {"agent": model},
            ArenaChamberBudget(),
            tmp_path / "empty",
            contained_fixture_authorized=True,
            provider_calls_authorized=False,
        )

    class UnsupportedModel:
        model_id = "unsupported"

        def respond(self, _prompt: str) -> Any:
            raise AssertionError

    unsupported: RoleModel = UnsupportedModel()
    with pytest.raises(FormatError, match="built-in provider or scripted"):
        run_arena_chamber(
            case,
            (_action(),),
            {"agent": unsupported},
            ArenaChamberBudget(),
            tmp_path / "unsupported",
            contained_fixture_authorized=True,
            provider_calls_authorized=False,
        )

    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "keep.txt").write_text("user file", encoding="utf-8")
    with pytest.raises(FormatError, match="not empty"):
        run_arena_chamber(
            case,
            (_action(),),
            {"agent": model},
            ArenaChamberBudget(),
            occupied,
            contained_fixture_authorized=True,
            provider_calls_authorized=False,
        )


def test_config_requires_exact_version_scope_and_environment(tmp_path: Path) -> None:
    base: dict[str, Any] = {
        "artifactType": "sova.arena-chamber",
        "schemaVersion": "0.1.0",
        "authorization": {
            "scope": "self-owned-built-in-synthetic-world",
            "confirmed": True,
        },
        "environment": {"kind": "sova.synthetic-world", "version": "0.1.0"},
        "case": {
            "id": "case",
            "title": "title",
            "mode": "agent-vs-environment",
            "successEventKinds": ["filesystem.read"],
            "seed": "seed",
        },
        "budget": {
            "rounds": 1,
            "maxActionsPerTurn": 1,
            "maxTotalActions": 1,
            "maxDurationSeconds": 10,
            "maxOutputBytes": 4096,
            "maxTotalTokens": None,
            "captureProfile": "forensic",
            "stopOnSuccess": True,
        },
        "actions": [
            {
                "id": "read",
                "action": "filesystem.read",
                "description": "read fixture",
                "inputs": {"path": "/home/researcher/README.txt"},
            }
        ],
        "participants": [],
        "judge": None,
    }
    for field, value in (
        ("schemaVersion", "9.0.0"),
        ("authorization", {"scope": "somewhere", "confirmed": True}),
        ("environment", {"kind": "host", "version": "0.1.0"}),
    ):
        document = dict(base)
        document[field] = value
        with pytest.raises(FormatError):
            run_arena_chamber_document(
                document,
                tmp_path / str(field),
                secret_resolver=lambda _name: None,
                contained_fixture_authorized=True,
                provider_calls_authorized=False,
            )


def _minimal_document(  # noqa: PLR0913 - test fixture exposes independent controls
    structured: dict[str, Any],
    *,
    actions: list[dict[str, Any]] | None = None,
    allowed: list[str] | None = None,
    success: str = "filesystem.read",
    token_count: int | None = None,
    judge: dict[str, Any] | None = None,
) -> dict[str, Any]:
    turn: dict[str, Any] = {
        "expectedContains": '"id":"agent"',
        "responseText": "",
        "structured": structured,
    }
    if token_count is not None:
        turn["tokenCount"] = token_count
    return {
        "artifactType": "sova.arena-chamber",
        "schemaVersion": "0.1.0",
        "authorization": {
            "scope": "self-owned-built-in-synthetic-world",
            "confirmed": True,
        },
        "environment": {"kind": "sova.synthetic-world", "version": "0.1.0"},
        "case": {
            "id": "case",
            "title": "title",
            "mode": "agent-vs-environment",
            "successEventKinds": [success],
            "seed": "seed",
        },
        "budget": {
            "rounds": 1,
            "maxActionsPerTurn": 4,
            "maxTotalActions": 4,
            "maxDurationSeconds": 10,
            "maxOutputBytes": 65536,
            "maxTotalTokens": None,
            "captureProfile": "forensic",
            "stopOnSuccess": True,
        },
        "actions": actions
        or [
            {
                "id": "read",
                "action": "filesystem.read",
                "description": "read fixture",
                "inputs": {"path": "/home/researcher/README.txt"},
            }
        ],
        "participants": [
            {
                "id": "agent",
                "objective": "observe",
                "allowedActions": allowed if allowed is not None else ["read"],
                "model": {
                    "adapter": "scripted",
                    "modelId": "scripted",
                    "turns": [turn],
                },
            }
        ],
        "judge": judge,
    }


@pytest.mark.parametrize(
    "structured",
    [
        {},
        {"message": 1, "actions": [], "signals": []},
        {"message": "ok", "actions": "read", "signals": []},
        {"message": "ok", "actions": [], "signals": ["bad signal"]},
    ],
)
def test_participant_output_contract_fails_closed(
    tmp_path: Path, structured: dict[str, Any]
) -> None:
    with pytest.raises(FormatError):
        run_arena_chamber_document(
            _minimal_document(structured),
            tmp_path / ("bad-output-" + str(len(list(tmp_path.iterdir())))),
            secret_resolver=lambda _name: None,
            contained_fixture_authorized=True,
            provider_calls_authorized=False,
        )


def test_unobserved_and_inter_agent_oracle_paths(tmp_path: Path) -> None:
    unobserved = _minimal_document(
        {"message": "baseline", "actions": [], "signals": []},
        success="database.read",
        token_count=1,
    )
    unobserved["budget"]["maxTotalTokens"] = 2
    result = run_arena_chamber_document(
        unobserved,
        tmp_path / "unobserved",
        secret_resolver=lambda _name: None,
        contained_fixture_authorized=True,
        provider_calls_authorized=False,
    )
    assert result.status == "not-observed"

    message = _minimal_document(
        {"message": "observable", "actions": [], "signals": []},
        success="inter-agent.message",
    )
    result = run_arena_chamber_document(
        message,
        tmp_path / "message-observed",
        secret_resolver=lambda _name: None,
        contained_fixture_authorized=True,
        provider_calls_authorized=False,
    )
    assert result.status == "pass"


def test_action_selection_reference_and_budget_failures(tmp_path: Path) -> None:
    denied = _minimal_document(
        {"message": "", "actions": ["second"], "signals": []},
        actions=[
            {
                "id": "read",
                "action": "filesystem.read",
                "description": "read",
                "inputs": {"path": "/home/researcher/README.txt"},
            },
            {
                "id": "second",
                "action": "filesystem.read",
                "description": "read second",
                "inputs": {"path": "/home/researcher/README.txt"},
            },
        ],
        allowed=["read"],
    )
    with pytest.raises(FormatError, match="outside its exact grant"):
        run_arena_chamber_document(
            denied,
            tmp_path / "denied",
            secret_resolver=lambda _name: None,
            contained_fixture_authorized=True,
            provider_calls_authorized=False,
        )

    reference = _minimal_document(
        {"message": "", "actions": ["send"], "signals": []},
        actions=[
            {
                "id": "send",
                "action": "network.send",
                "description": "sink",
                "inputs": {
                    "destination": "sink.sova.invalid",
                    "body": {"$ref": "last.output.content"},
                },
            }
        ],
        allowed=["send"],
    )
    with pytest.raises(FormatError, match="no prior result"):
        run_arena_chamber_document(
            reference,
            tmp_path / "reference",
            secret_resolver=lambda _name: None,
            contained_fixture_authorized=True,
            provider_calls_authorized=False,
        )

    exhausted = _minimal_document({"message": "", "actions": ["read", "read"], "signals": []})
    exhausted["budget"]["maxTotalActions"] = 1
    with pytest.raises(FormatError, match="action budget"):
        run_arena_chamber_document(
            exhausted,
            tmp_path / "exhausted",
            secret_resolver=lambda _name: None,
            contained_fixture_authorized=True,
            provider_calls_authorized=False,
        )


def test_token_budget_and_judge_contract_failures(tmp_path: Path) -> None:
    missing_usage = _minimal_document(
        {"message": "", "actions": [], "signals": []},
        success="database.read",
    )
    missing_usage["budget"]["maxTotalTokens"] = 1
    with pytest.raises(FormatError, match="adapter-reported"):
        run_arena_chamber_document(
            missing_usage,
            tmp_path / "missing-usage",
            secret_resolver=lambda _name: None,
            contained_fixture_authorized=True,
            provider_calls_authorized=False,
        )

    exhausted = _minimal_document(
        {"message": "", "actions": [], "signals": []},
        success="database.read",
        token_count=2,
    )
    exhausted["budget"]["maxTotalTokens"] = 1
    with pytest.raises(FormatError, match="token budget"):
        run_arena_chamber_document(
            exhausted,
            tmp_path / "token-exhausted",
            secret_resolver=lambda _name: None,
            contained_fixture_authorized=True,
            provider_calls_authorized=False,
        )

    bad_judge = {
        "id": "judge",
        "model": {
            "adapter": "scripted",
            "modelId": "judge",
            "turns": [
                {
                    "expectedContains": "deterministicAssessment",
                    "responseText": "",
                    "structured": {"assessment": "invented", "limitations": []},
                }
            ],
        },
    }
    document = _minimal_document(
        {"message": "", "actions": ["read"], "signals": []}, judge=bad_judge
    )
    with pytest.raises(FormatError, match="judge output"):
        run_arena_chamber_document(
            document,
            tmp_path / "judge-invalid",
            secret_resolver=lambda _name: None,
            contained_fixture_authorized=True,
            provider_calls_authorized=False,
        )


def test_provider_config_is_credential_late_and_requires_explicit_call_permission(
    tmp_path: Path,
) -> None:
    document = _minimal_document({"message": "", "actions": [], "signals": []})
    document["participants"][0]["model"] = {
        "adapter": "provider",
        "provider": "openai",
        "model": "fixture-model",
        "temperature": "0",
        "maxOutputTokens": 64,
        "timeoutSeconds": "5",
    }
    with pytest.raises(FormatError, match="provider models require explicit"):
        run_arena_chamber_document(
            document,
            tmp_path / "provider",
            secret_resolver=lambda _name: None,
            contained_fixture_authorized=True,
            provider_calls_authorized=False,
        )


@pytest.mark.parametrize(
    ("path", "value"),
    [
        ("participants", "not-an-array"),
        ("judge", {"id": "agent", "model": {}}),
        ("case.mode", "unsupported"),
        ("budget.maxTotalTokens", "bad"),
    ],
)
def test_config_rejects_malformed_nested_values(tmp_path: Path, path: str, value: Any) -> None:
    document = _minimal_document({"message": "", "actions": [], "signals": []})
    if "." in path:
        root, child = path.split(".")
        document[root][child] = value
    else:
        document[path] = value
    with pytest.raises(FormatError):
        run_arena_chamber_document(
            document,
            tmp_path / ("malformed-" + path.replace(".", "-")),
            secret_resolver=lambda _name: None,
            contained_fixture_authorized=True,
            provider_calls_authorized=False,
        )


def test_live_journal_rejects_observations_after_close(tmp_path: Path) -> None:
    journal = LiveEventJournal(tmp_path / "events.jsonl")
    journal.close()
    journal.close()
    with pytest.raises(FormatError, match="closed"):
        journal.observe({"event": "late"})


def test_reference_and_model_output_edge_contracts() -> None:
    with pytest.raises(FormatError, match="unsupported"):
        chamber_module._resolve_inputs({"$ref": "arbitrary.value"}, None)
    with pytest.raises(FormatError, match="cannot be resolved"):
        chamber_module._resolve_inputs({"$ref": "last.output.missing"}, {"last": {"output": {}}})
    with pytest.raises(FormatError, match="must be a string"):
        chamber_module._resolve_inputs({"$ref": 1}, {"last": {"output": {}}})
    nested: Any = "leaf"
    for _index in range(18):
        nested = [nested]
    with pytest.raises(FormatError, match="nesting"):
        chamber_module._resolve_inputs(nested, None)
    assert chamber_module._resolve_inputs([1, {"x": 2}], None) == [
        1,
        {"x": 2},
    ]

    oversized = ScriptedModel(
        [
            ScriptedTurn(
                "prompt",
                "x" * 5000,
                {"message": "", "actions": [], "signals": []},
            )
        ]
    )
    with pytest.raises(FormatError, match="byte budget"):
        chamber_module._participant_output(
            oversized, "prompt", ArenaChamberBudget(max_output_bytes=1024)
        )
    invalid_usage = ScriptedModel(
        [
            ScriptedTurn(
                "prompt",
                "",
                {"message": "", "actions": [], "signals": []},
                token_count=-1,
            )
        ]
    )
    with pytest.raises(FormatError, match="token count"):
        chamber_module._participant_output(invalid_usage, "prompt", ArenaChamberBudget())

    invalid_participant_provenance = ScriptedModel(
        [
            ScriptedTurn(
                "prompt",
                "",
                {"message": "", "actions": [], "signals": []},
                resolved_model_id="",
            )
        ]
    )
    with pytest.raises(FormatError, match="resolved model identifier"):
        chamber_module._participant_output(
            invalid_participant_provenance, "prompt", ArenaChamberBudget()
        )

    judge_tool = ScriptedModel(
        [
            ScriptedTurn(
                "prompt",
                "",
                {"assessment": "observed", "limitations": ["bounded"]},
                tool_calls=({"name": "tool"},),
            )
        ]
    )
    with pytest.raises(FormatError, match="cannot call tools"):
        chamber_module._judge_output(judge_tool, "prompt", ArenaChamberBudget())
    judge_large = ScriptedModel(
        [
            ScriptedTurn(
                "prompt",
                "x" * 5000,
                {"assessment": "observed", "limitations": ["bounded"]},
            )
        ]
    )
    with pytest.raises(FormatError, match="byte budget"):
        chamber_module._judge_output(
            judge_large, "prompt", ArenaChamberBudget(max_output_bytes=1024)
        )
    invalid_judge_provenance = ScriptedModel(
        [
            ScriptedTurn(
                "prompt",
                "",
                {"assessment": "observed", "limitations": ["bounded"]},
                resolved_model_id="",
            )
        ]
    )
    with pytest.raises(FormatError, match="resolved model identifier"):
        chamber_module._judge_output(invalid_judge_provenance, "prompt", ArenaChamberBudget())


def test_parser_helpers_and_duplicate_participant_fail_closed(tmp_path: Path) -> None:
    for function, value in (
        (config_module._object, 1),
        (config_module._sequence, {}),
        (config_module._text, ""),
        (config_module._integer, True),
        (config_module._boolean, "true"),
        (config_module._number, object()),
        (config_module._number, "not-number"),
    ):
        with pytest.raises(FormatError):
            function(value, "$.fixture")
    with pytest.raises(FormatError, match="fields are invalid"):
        config_module._fields({}, "$", required=("required",))
    with pytest.raises(FormatError, match="adapter must be scripted"):
        config_module._scripted_model({"adapter": "bad", "modelId": "x", "turns": []}, "$")
    with pytest.raises(FormatError, match="scripted or provider"):
        config_module._model(
            {"adapter": "bad"}, "$", role="fixture", secret_resolver=lambda _name: None
        )

    duplicate = _minimal_document({"message": "", "actions": [], "signals": []})
    duplicate["participants"].append(dict(duplicate["participants"][0]))
    with pytest.raises(FormatError, match="duplicated"):
        run_arena_chamber_document(
            duplicate,
            tmp_path / "duplicate",
            secret_resolver=lambda _name: None,
            contained_fixture_authorized=True,
            provider_calls_authorized=False,
        )


def test_timeout_non_object_reference_and_stream_mismatch_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    timed = _minimal_document({"message": "", "actions": [], "signals": []})
    clock = iter((0.0, 20.0))
    monkeypatch.setattr("sova.community.chamber.time.monotonic", lambda: next(clock))
    with pytest.raises(FormatError, match="duration budget"):
        run_arena_chamber_document(
            timed,
            tmp_path / "timeout",
            secret_resolver=lambda _name: None,
            contained_fixture_authorized=True,
            provider_calls_authorized=False,
        )

    monkeypatch.undo()
    scalar = _minimal_document(
        {"message": "", "actions": ["read", "scalar"], "signals": []},
        actions=[
            {
                "id": "read",
                "action": "filesystem.read",
                "description": "read",
                "inputs": {"path": "/home/researcher/README.txt"},
            },
            {
                "id": "scalar",
                "action": "filesystem.read",
                "description": "invalid resolved shape",
                "inputs": {"$ref": "last.output.content"},
            },
        ],
        allowed=["read", "scalar"],
    )
    with pytest.raises(FormatError, match="not an object"):
        run_arena_chamber_document(
            scalar,
            tmp_path / "scalar",
            secret_resolver=lambda _name: None,
            contained_fixture_authorized=True,
            provider_calls_authorized=False,
        )

    original_close = chamber_module.LiveEventJournal.close

    def tamper_after_close(journal: LiveEventJournal) -> None:
        was_closed = journal._closed
        original_close(journal)
        if not was_closed:
            with journal.path.open("ab") as handle:
                handle.write(b"tampered\n")

    monkeypatch.setattr(chamber_module.LiveEventJournal, "close", tamper_after_close)
    mismatch = _minimal_document({"message": "", "actions": ["read"], "signals": []})
    result = run_arena_chamber_document(
        mismatch,
        tmp_path / "mismatch",
        secret_resolver=lambda _name: None,
        contained_fixture_authorized=True,
        provider_calls_authorized=False,
    )
    assert result.status == "fail"
