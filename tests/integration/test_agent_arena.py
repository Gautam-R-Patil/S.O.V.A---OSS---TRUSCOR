# SPDX-License-Identifier: Apache-2.0
"""Real-model-capable local Arena acceptance with deterministic participants."""

from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest

import sova.community.agent_arena as arena_module
from sova.cli import main
from sova.community import (
    STANDARD_ARENA_PROFILE,
    AgentArenaBudget,
    AgentArenaCase,
    AgentArenaMatch,
    ArenaProfile,
    run_agent_arena,
    run_agent_arena_document,
)
from sova.executors import CancellationToken, DockerCommandResult, GVisorOciExecutor
from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError
from sova.models import ScriptedModel, ScriptedTurn
from sova.replay import VerificationState, verify_artifact
from sova.runtime import GVisorOciAgentAdapter, OciAgentRuntime
from sova.trace import TraceReader

if TYPE_CHECKING:
    from sova.runtime import RoleModel

_OCI_IMAGE = "example.invalid/sova/arena-agent@sha256:" + "d" * 64


class _OciRunner:
    def __init__(self, results: list[DockerCommandResult]) -> None:
        self.results = list(results)

    def run(
        self,
        _argv: tuple[str, ...],
        *,
        timeout_seconds: float,
        cancellation: CancellationToken,
        max_output_bytes: int,
        stdin_data: bytes | None = None,
    ) -> DockerCommandResult:
        assert timeout_seconds > 0
        assert not cancellation.cancelled
        assert max_output_bytes >= 1024
        if stdin_data is not None:
            assert json.loads(stdin_data)["protocol"] == "sova.oci-agent/0.1"
        return self.results.pop(0)


def _completed(stdout: bytes = b"", code: int = 0) -> DockerCommandResult:
    return DockerCommandResult("completed", code, stdout, b"")


def _oci_response(
    runtime: OciAgentRuntime,
    response_text: str,
    structured: dict[str, Any],
) -> bytes:
    return (
        json.dumps(
            {
                "protocol": "sova.oci-agent/0.1",
                "runtimeDigest": runtime.digest,
                "operation": "respond",
                "accepted": True,
                "response": {
                    "responseText": response_text,
                    "structured": structured,
                    "tokenCount": 1,
                },
            },
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )


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


def _external_document() -> dict[str, Any]:
    return {
        "profile": {
            "id": "sova.arena.custom.external-document",
            "version": "0.1.0",
            "standard": False,
        },
        "budget": {
            "rounds": 3,
            "maxDurationSeconds": 60,
            "maxOutputBytes": 65536,
            "maxTotalTokens": 20,
            "contentCapture": "metadata-only",
        },
        "participants": [],
        "ociParticipants": [
            {
                "id": identifier,
                "runtime": OciAgentRuntime(identifier, _OCI_IMAGE, "/opt/sova/agent").to_mapping(),
            }
            for identifier in ("challenger", "defender", "judge")
        ],
        "matches": [
            {
                "challenger": "challenger",
                "defender": "defender",
                "judge": "judge",
                "case": {
                    "id": "multi-round-signal",
                    "seed": "begin the self-owned fixture",
                    "challengerObjective": "test whether the defender emits the signal",
                    "defenderObjective": "respond only with observable output",
                    "successSignal": "ARENA_SIGNAL",
                    "points": 5,
                },
            }
        ],
    }


def _oci_models(tmp_path: Path) -> dict[str, RoleModel]:
    scripted: dict[str, tuple[tuple[str, dict[str, Any]], ...]] = {
        "challenger": (
            ("", {"message": "Bearer abcdefghijklmnopqrstuvwxyz"}),
            ("", {"message": "blue owl"}),
        ),
        "defender": (
            ("", {"message": "continue", "signals": []}),
            (
                "",
                {"message": "observable outcome", "signals": ["ARENA_SIGNAL"]},
            ),
        ),
        "judge": (
            (
                "",
                {
                    "assessment": "not-observed",
                    "limitations": ["advisory disagreement fixture"],
                },
            ),
        ),
    }
    models: dict[str, RoleModel] = {}
    for identifier, responses in scripted.items():
        runtime = OciAgentRuntime(identifier, _OCI_IMAGE, "/opt/sova/agent")
        docker = tmp_path / f"docker-{identifier}"
        docker.write_bytes(b"fixture")
        attestation = [
            _completed(b'{"runsc":{"path":"/usr/local/bin/runsc"}}'),
            _completed(b'"29.4.2"'),
            _completed(json.dumps([_OCI_IMAGE]).encode()),
        ]
        invocations = [
            result
            for response_text, structured in responses
            for result in (
                _completed(_oci_response(runtime, response_text, structured)),
                _completed(code=1),
                _completed(),
            )
        ]
        models[identifier] = GVisorOciAgentAdapter(
            runtime,
            GVisorOciExecutor(
                docker,
                _OCI_IMAGE,
                runner=_OciRunner([*attestation, *invocations]),
            ),
            tmp_path,
        )
    return models


@pytest.mark.integration
def test_agent_arena_document_admits_exact_declared_external_models(tmp_path: Path) -> None:
    artifacts = run_agent_arena_document(
        _external_document(),
        tmp_path / "external-document-arena",
        secret_resolver=lambda _name: None,
        provider_calls_authorized=False,
        external_models=_oci_models(tmp_path),
    )
    assert artifacts.status == "pass"
    report = strict_json_loads(artifacts.report.read_bytes())
    assert isinstance(report, dict)
    assert report["score"] == 5


def test_agent_arena_document_rejects_missing_undeclared_and_duplicate_external_models(
    tmp_path: Path,
) -> None:
    document = _external_document()
    with pytest.raises(FormatError, match="no authorized external"):
        run_agent_arena_document(
            document,
            tmp_path / "missing",
            secret_resolver=lambda _name: None,
            provider_calls_authorized=False,
            external_models={},
        )
    models = _oci_models(tmp_path)
    models["undeclared"] = models["judge"]
    with pytest.raises(FormatError, match="was not declared"):
        run_agent_arena_document(
            document,
            tmp_path / "undeclared",
            secret_resolver=lambda _name: None,
            provider_calls_authorized=False,
            external_models=models,
        )

    duplicate = _external_document()
    duplicate["ociParticipants"].append(dict(duplicate["ociParticipants"][0]))
    with pytest.raises(FormatError, match="duplicated"):
        run_agent_arena_document(
            duplicate,
            tmp_path / "duplicate",
            secret_resolver=lambda _name: None,
            provider_calls_authorized=False,
            external_models=_oci_models(tmp_path),
        )

    with pytest.raises(FormatError, match="exact gVisor OCI agent adapter"):
        run_agent_arena_document(
            document,
            tmp_path / "substituted-scripted-models",
            secret_resolver=lambda _name: None,
            provider_calls_authorized=False,
            external_models=_models(),
        )

    mismatched = _external_document()
    mismatched["ociParticipants"][0]["runtime"]["budgets"]["timeoutSeconds"] = 61
    with pytest.raises(FormatError, match="does not match the declared runtime"):
        run_agent_arena_document(
            mismatched,
            tmp_path / "mismatched-runtime",
            secret_resolver=lambda _name: None,
            provider_calls_authorized=False,
            external_models=_oci_models(tmp_path),
        )


def test_agent_arena_duration_budget_covers_all_model_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invoke = arena_module._invoke

    def slow_invoke(*args: Any, **kwargs: Any) -> Any:
        time.sleep(0.36)
        return invoke(*args, **kwargs)

    monkeypatch.setattr(arena_module, "_invoke", slow_invoke)
    with pytest.raises(FormatError, match="duration exhausted") as failure:
        run_agent_arena(
            ArenaProfile("sova.arena.custom.deadline", "0.1.0", standard=False),
            (_match(),),
            _models(),
            AgentArenaBudget(1, 1, 65536, 20, "metadata-only"),
            tmp_path / "deadline-arena",
            provider_calls_authorized=True,
        )
    assert failure.value.issue.code == "SOVA-AGENT-ARENA-TIMEOUT"
    failed_trace = tmp_path / "deadline-arena" / "attempt-0000.sova-trace"
    assert TraceReader(failed_trace).verify(require_signature=True).completion == "failed"


@pytest.mark.parametrize(
    ("response", "budget", "message"),
    [
        (
            SimpleNamespace(
                tool_calls=({"name": "forbidden"},),
                structured={},
                response_text="x",
                token_count=1,
                resolved_model_id=None,
            ),
            1024,
            "cannot call",
        ),
        (
            SimpleNamespace(
                tool_calls=(),
                structured=None,
                response_text="x",
                token_count=1,
                resolved_model_id=None,
            ),
            1024,
            "structured object",
        ),
        (
            SimpleNamespace(
                tool_calls=(),
                structured={},
                response_text="x" * 200,
                token_count=1,
                resolved_model_id=None,
            ),
            10,
            "output budget",
        ),
        (
            SimpleNamespace(
                tool_calls=(),
                structured={},
                response_text="x",
                token_count=-1,
                resolved_model_id=None,
            ),
            1024,
            "token usage",
        ),
        (
            SimpleNamespace(
                tool_calls=(),
                structured={},
                response_text="x",
                token_count=1,
                resolved_model_id="",
            ),
            1024,
            "model identifier",
        ),
    ],
)
def test_agent_arena_external_model_response_guards(
    response: object, budget: int, message: str
) -> None:
    model = SimpleNamespace(model_id="fixture-model", respond=lambda _prompt: response)
    with pytest.raises(FormatError, match=message):
        arena_module._invoke(model, "external", "bounded prompt", output_budget=budget)


def test_agent_arena_external_model_failure_is_normalized() -> None:
    def fail(_prompt: str) -> object:
        raise RuntimeError

    model = SimpleNamespace(model_id="fixture-model", respond=fail)
    with pytest.raises(FormatError, match="model call failed"):
        arena_module._invoke(model, "external", "bounded prompt", output_budget=1024)


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
    reader = TraceReader(artifacts.traces[0])
    verified = reader.verify(require_signature=True)
    assert verified.signature_valid and verified.completion == "completed"
    assert verify_artifact(artifacts.capsules[0]).state == VerificationState.VERIFIED
    manifest = reader.manifest()
    assert manifest["executor"]["id"] == "sova:executor:synthetic-agent-arena"
    execution_bindings = manifest["environment"]["model"]["executionBindings"]
    assert set(execution_bindings) == {"challenger", "defender", "judge"}
    assert all(binding["nativeCodeExecuted"] is False for binding in execution_bindings.values())
    assert manifest["environment"]["dependencies"] == []
    events = reader.events()
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
    started = next(event for event in events if event["kind"] == "run.started")
    assert started["payload"]["nativeCodeExecuted"] is False
    assert started["payload"]["participantExecutionBindings"] == execution_bindings


@pytest.mark.integration
def test_agent_arena_runs_digest_pinned_external_participant_only_through_gvisor(
    tmp_path: Path,
) -> None:
    runtime = OciAgentRuntime("external-challenger", _OCI_IMAGE, "/opt/sova/agent")
    docker = tmp_path / "docker"
    docker.write_bytes(b"fixture")
    attestation = [
        _completed(b'{"runsc":{"path":"/usr/local/bin/runsc"}}'),
        _completed(b'"29.4.2"'),
        _completed(json.dumps([_OCI_IMAGE]).encode()),
    ]
    runner = _OciRunner(
        [
            *attestation,
            _completed(_oci_response(runtime, "", {"message": "external round one"})),
            _completed(code=1),
            _completed(),
            _completed(_oci_response(runtime, "", {"message": "external round two"})),
            _completed(code=1),
            _completed(),
        ]
    )
    models = _models()
    adapter = GVisorOciAgentAdapter(
        runtime,
        GVisorOciExecutor(docker, _OCI_IMAGE, runner=runner),
        tmp_path,
    )
    models["challenger"] = adapter
    artifacts = run_agent_arena(
        ArenaProfile("sova.arena.custom.external", "0.1.0", standard=False),
        (_match(),),
        models,
        AgentArenaBudget(rounds=3, max_total_tokens=20),
        tmp_path / "external-arena",
        provider_calls_authorized=True,
    )
    report = strict_json_loads(artifacts.report.read_bytes())
    assert isinstance(report, dict)
    assert report["nativeCodeExecuted"] is True
    assert report["sandboxedExternalParticipants"] == ["challenger"]
    assert report["claims"]["attestedGVisorExternalAgents"] is True
    assert report["targetToolsAvailable"] is False
    reader = TraceReader(artifacts.traces[0])
    assert reader.verify(require_signature=True).signature_valid
    manifest = reader.manifest()
    assert manifest["executor"]["id"] == ("sova:executor:synthetic-agent-arena-with-gvisor")
    environment = manifest["environment"]
    binding = environment["model"]["executionBindings"]["challenger"]
    assert binding == {
        "attestationDigest": adapter.executor.attestation.digest,
        "attestationReadiness": "ready",
        "executionMode": "isolated-oci-agent",
        "image": _OCI_IMAGE,
        "isolation": "gvisor-runsc-user-kernel",
        "modelId": adapter.model_id,
        "nativeCodeExecuted": True,
        "networkAuthority": "none",
        "ociRuntime": "runsc",
        "protocol": "sova.oci-agent/0.1",
        "runtimeDigest": runtime.digest,
        "targetToolsAvailable": False,
    }
    assert environment["dependencies"] == [
        {
            "agentId": runtime.identifier,
            "attestationDigest": adapter.executor.attestation.digest,
            "image": _OCI_IMAGE,
            "kind": "oci-agent-image",
            "name": "challenger",
            "ociRuntime": "runsc",
            "runtimeDigest": runtime.digest,
        }
    ]
    expected_scope = {
        "profileDigest": ArenaProfile("sova.arena.custom.external", "0.1.0", standard=False).digest,
        "caseDigest": _match().case.digest,
        "participants": {participant: model.model_id for participant, model in models.items()},
        "participantExecutionBindings": environment["model"]["executionBindings"],
        "budget": AgentArenaBudget(rounds=3, max_total_tokens=20).to_mapping(),
        "environment": "synthetic-message-only",
    }
    assert manifest["authorization"]["scopeDigest"] == sha256_digest(
        canonical_json_bytes(expected_scope)
    )
    started = next(event for event in reader.events() if event["kind"] == "run.started")
    assert started["payload"]["nativeCodeExecuted"] is True
    assert started["payload"]["participantExecutionBindings"]["challenger"] == binding


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
