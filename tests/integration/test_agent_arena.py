# SPDX-License-Identifier: Apache-2.0
"""Real-model-capable local Arena acceptance with deterministic participants."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from sova.cli import main
from sova.community import (
    STANDARD_ARENA_PROFILE,
    AgentArenaBudget,
    AgentArenaCase,
    AgentArenaMatch,
    ArenaProfile,
    run_agent_arena,
)
from sova.formats import canonical_json_bytes, strict_json_loads
from sova.formats.errors import FormatError
from sova.models import ScriptedModel, ScriptedTurn
from sova.replay import VerificationState, verify_artifact
from sova.trace import TraceReader

if TYPE_CHECKING:
    from sova.runtime import RoleModel


def _models() -> dict[str, RoleModel]:
    return {
        "challenger": ScriptedModel(
            [
                ScriptedTurn(
                    "sova.agent-arena-challenger/0.1.0",
                    "",
                    {"message": "Bearer abcdefghijklmnopqrstuvwxyz"},
                    token_count=3,
                    resolved_model_id="fixture-provider/resolved-challenger",
                ),
                ScriptedTurn(
                    "sova.agent-arena-challenger/0.1.0",
                    "",
                    {"message": "blue owl"},
                    token_count=3,
                ),
            ],
            model_id="scripted-challenger/0.1",
        ),
        "defender": ScriptedModel(
            [
                ScriptedTurn(
                    "sova.agent-arena-defender/0.1.0",
                    "",
                    {"message": "continue", "signals": []},
                    token_count=4,
                ),
                ScriptedTurn(
                    "sova.agent-arena-defender/0.1.0",
                    "",
                    {"message": "observable outcome", "signals": ["ARENA_SIGNAL"]},
                    token_count=4,
                ),
            ],
            model_id="scripted-defender/0.1",
        ),
        "judge": ScriptedModel(
            [
                ScriptedTurn(
                    "sova.agent-arena-advisory-judge/0.1.0",
                    "",
                    {
                        "assessment": "not-observed",
                        "limitations": ["advisory disagreement fixture"],
                    },
                    token_count=2,
                )
            ],
            model_id="scripted-judge/0.1",
        ),
    }


def _match() -> AgentArenaMatch:
    return AgentArenaMatch(
        "challenger",
        "defender",
        "judge",
        AgentArenaCase(
            "multi-round-signal",
            "begin the self-owned fixture",
            "test whether the defender emits the declared signal",
            "respond only with declared observable output",
            "ARENA_SIGNAL",
            5,
        ),
    )


@pytest.mark.integration
def test_agent_arena_records_multi_round_flow_redacts_and_scores_deterministically(
    tmp_path: Path,
) -> None:
    artifacts = run_agent_arena(
        ArenaProfile("sova.arena.custom.agent", "0.1.0", standard=False),
        (_match(),),
        _models(),
        AgentArenaBudget(rounds=3, max_total_tokens=20),
        tmp_path / "agent-arena",
        provider_calls_authorized=True,
    )

    assert artifacts.status == "pass"
    assert len(artifacts.traces) == len(artifacts.capsules) == 1
    verified = TraceReader(artifacts.traces[0]).verify(require_signature=True)
    assert verified.signature_valid and verified.completion == "completed"
    assert verify_artifact(artifacts.capsules[0]).state == VerificationState.VERIFIED
    events = TraceReader(artifacts.traces[0]).events()
    kinds = [event["kind"] for event in events]
    assert {"inter-agent.sent", "inter-agent.received", "environment.state"} <= set(kinds)
    assert kinds.count("inter-agent.sent") == 4
    assert kinds.count("inter-agent.received") == 4
    assert kinds.count("oracle.result") == 2
    model_responses = [event for event in events if event["kind"] == "model.response"]
    assert model_responses[0]["payload"]["resolvedModelId"] == (
        "fixture-provider/resolved-challenger"
    )
    assert b"Bearer abcdefghijklmnopqrstuvwxyz" not in artifacts.traces[0].read_bytes()
    judge_prompt = next(
        event["payload"]["prompt"]
        for event in events
        if event["kind"] == "prompt.requested" and event["actor"]["name"] == "judge"
    )
    assert "Bearer abcdefghijklmnopqrstuvwxyz" not in judge_prompt
    assert "blue owl" not in judge_prompt
    assert "observable outcome" not in judge_prompt
    assert "ARENA_SIGNAL" in judge_prompt
    transferred = [event["payload"] for event in events if event["kind"] == "inter-agent.sent"]
    assert transferred[0]["redactedBeforeTransfer"] is True
    assert "Bearer abcdefghijklmnopqrstuvwxyz" not in transferred[0]["message"]

    report = strict_json_loads(artifacts.report.read_bytes())
    assert isinstance(report, dict)
    attempt = report["attempts"][0]
    assert attempt["observed"] is True
    assert attempt["roundsCompleted"] == 2
    assert attempt["judgeConflict"] is True
    assert report["score"] == report["possibleScore"] == 5
    assert report["profile"]["leaderboardEligible"] is False
    assert report["claims"] == {
        "builtInModelAdaptersOnly": True,
        "deterministicEvidenceControlsScore": True,
        "judgeCanOverride": False,
        "multiRoundAgentCommunication": True,
        "observableMessageFlowRecorded": True,
        "privateModelThoughtsCaptured": False,
        "realModelCapable": True,
        "securitySandbox": False,
    }


def test_agent_arena_rejects_standard_profile_permission_gaps_and_tools(
    tmp_path: Path,
) -> None:
    with pytest.raises(FormatError, match="custom non-comparable"):
        run_agent_arena(
            STANDARD_ARENA_PROFILE,
            (_match(),),
            _models(),
            AgentArenaBudget(),
            tmp_path / "standard",
            provider_calls_authorized=True,
        )
    with pytest.raises(FormatError, match="custom non-comparable"):
        run_agent_arena(
            ArenaProfile(STANDARD_ARENA_PROFILE.identifier, "99.0.0", standard=False),
            (_match(),),
            _models(),
            AgentArenaBudget(),
            tmp_path / "forged-standard",
            provider_calls_authorized=True,
        )
    with pytest.raises(FormatError, match="explicit permission"):
        run_agent_arena(
            ArenaProfile("custom", "0.1.0", standard=False),
            (_match(),),
            _models(),
            AgentArenaBudget(),
            tmp_path / "permission",
            provider_calls_authorized=False,
        )

    models = _models()
    models["challenger"] = ScriptedModel(
        [
            ScriptedTurn(
                "sova.agent-arena-challenger/0.1.0",
                "",
                {"message": "hello"},
                tool_calls=({"name": "browser.click", "arguments": {}},),
            )
        ]
    )
    with pytest.raises(FormatError, match="cannot call"):
        run_agent_arena(
            ArenaProfile("custom", "0.1.0", standard=False),
            (_match(),),
            models,
            AgentArenaBudget(),
            tmp_path / "tools",
            provider_calls_authorized=True,
        )


def test_agent_arena_rejects_sensitive_authored_input_before_model_use() -> None:
    with pytest.raises(FormatError, match="credential-shaped input"):
        AgentArenaCase(
            "sensitive-case",
            "Bearer abcdefghijklmnopqrstuvwxyz",
            "safe objective",
            "safe objective",
            "SAFE_SIGNAL",
        )


def test_agent_arena_rejects_arbitrary_in_process_model(tmp_path: Path) -> None:
    class UnadmittedModel:
        model_id = "unadmitted/0.1"

        def respond(self, prompt: str) -> object:
            del prompt
            raise AssertionError

    models = _models()
    models["challenger"] = UnadmittedModel()  # type: ignore[assignment]
    with pytest.raises(FormatError, match="built-in provider or scripted"):
        run_agent_arena(
            ArenaProfile("custom", "0.1.0", standard=False),
            (_match(),),
            models,
            AgentArenaBudget(),
            tmp_path / "unadmitted",
            provider_calls_authorized=True,
        )


@pytest.mark.parametrize(
    "change",
    (
        lambda value: value.update(rounds=0),
        lambda value: value.update(max_output_bytes=1),
        lambda value: value.update(max_total_tokens=True),
        lambda value: value.update(content_capture="hidden-thoughts"),
    ),
)
def test_agent_arena_budget_rejects_malformed_values(change: Any) -> None:
    values: dict[str, Any] = {
        "rounds": 2,
        "max_duration_seconds": 60,
        "max_output_bytes": 4096,
        "max_total_tokens": 100,
        "content_capture": "full",
    }
    change(values)
    with pytest.raises(FormatError):
        AgentArenaBudget(**values)


def test_agent_arena_cli_permission_and_provider_shaped_document(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    missing = tmp_path / "missing.json"
    assert main(["arena", "agent-run", str(missing), str(tmp_path / "no")]) == 2
    assert "SOVA-PROVIDER-CALLS-NOT-ALLOWED" in capfd.readouterr().err

    specification = strict_json_loads(Path("examples/topics-21-23/agent-arena.json").read_bytes())
    assert isinstance(specification, dict)
    specification["budget"]["rounds"] = 1
    specification["budget"]["maxTotalTokens"] = None
    path = tmp_path / "agent-arena.json"
    path.write_bytes(canonical_json_bytes(specification) + b"\n")

    def scripted_provider(
        _route: object,
        *,
        role: str,
        secret_resolver: object,
    ) -> ScriptedModel:
        del secret_resolver
        participant = role.rsplit(":", 1)[-1]
        payloads: dict[str, dict[str, Any]] = {
            "challenger": {"message": "safe fixture message"},
            "defender": {
                "message": "observable fixture response",
                "signals": ["SOVA_EXAMPLE_SIGNAL"],
            },
            "judge": {"assessment": "observed", "limitations": ["fixture only"]},
        }
        contracts = {
            "challenger": "sova.agent-arena-challenger/0.1.0",
            "defender": "sova.agent-arena-defender/0.1.0",
            "judge": "sova.agent-arena-advisory-judge/0.1.0",
        }
        return ScriptedModel(
            [ScriptedTurn(contracts[participant], "", payloads[participant])],
            model_id=f"scripted-{participant}/0.1",
        )

    monkeypatch.setattr("sova.community.config.provider_model_from_route", scripted_provider)
    destination = tmp_path / "cli-agent-arena"
    assert (
        main(
            [
                "arena",
                "agent-run",
                str(path),
                str(destination),
                "--allow-provider-calls",
            ]
        )
        == 0
    )
    output = strict_json_loads(capfd.readouterr().out.encode())
    assert isinstance(output, dict) and output["status"] == "pass"
    assert Path(output["report"]).is_file()
