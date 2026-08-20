# SPDX-License-Identifier: Apache-2.0
"""Sandboxed external-agent runtime and protocol conformance tests."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import pytest

import sova.runtime.oci_agent as oci_module
from sova.executors import (
    ActionOutcome,
    CancellationToken,
    DockerCommandResult,
    GVisorOciExecutor,
    OutcomeStatus,
    SideEffect,
)
from sova.formats.errors import FormatError
from sova.runtime import (
    GVisorOciAgentAdapter,
    OciAgentRuntime,
    authorize_oci_agent_adapter,
    oci_agent_runtime_from_mapping,
    run_oci_agent_conformance,
)
from sova.trace import TraceReader

if TYPE_CHECKING:
    from pathlib import Path

IMAGE = "example.invalid/sova/agent@sha256:" + "a" * 64


def _completed(stdout: bytes = b"", code: int = 0) -> DockerCommandResult:
    return DockerCommandResult("completed", code, stdout, b"")


class _Runner:
    def __init__(self, results: list[DockerCommandResult]) -> None:
        self.results = list(results)
        self.calls: list[tuple[str, ...]] = []
        self.stdin: list[bytes | None] = []

    def run(
        self,
        argv: tuple[str, ...],
        *,
        timeout_seconds: float,
        cancellation: CancellationToken,
        max_output_bytes: int,
        stdin_data: bytes | None = None,
    ) -> DockerCommandResult:
        assert timeout_seconds > 0
        assert not cancellation.cancelled
        assert max_output_bytes >= 1024
        self.calls.append(argv)
        self.stdin.append(stdin_data)
        return self.results.pop(0)


def _attestation() -> list[DockerCommandResult]:
    return [
        _completed(b'{"runc":{},"runsc":{"path":"/usr/local/bin/runsc"}}'),
        _completed(b'"29.4.2"'),
        _completed(json.dumps([IMAGE]).encode()),
    ]


def _docker(tmp_path: Path) -> Path:
    path = tmp_path / "docker"
    path.write_bytes(b"fixture")
    return path


def _runtime() -> OciAgentRuntime:
    return OciAgentRuntime("fixture-agent", IMAGE, "/opt/sova/agent")


def _response(runtime: OciAgentRuntime, operation: str, response: dict[str, object]) -> bytes:
    return (
        json.dumps(
            {
                "protocol": "sova.oci-agent/0.1",
                "runtimeDigest": runtime.digest,
                "operation": operation,
                "accepted": True,
                "response": response,
            },
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )


def _execution(stdout: bytes) -> list[DockerCommandResult]:
    return [_completed(stdout), _completed(code=1), _completed()]


def test_oci_agent_runtime_round_trips_and_rejects_weaker_security() -> None:
    runtime = _runtime()
    assert oci_agent_runtime_from_mapping(runtime.to_mapping()) == runtime
    weakened = runtime.to_mapping()
    weakened["security"]["network"] = "bridge"
    with pytest.raises(FormatError, match="fail-closed gVisor"):
        oci_agent_runtime_from_mapping(weakened)
    with pytest.raises(FormatError, match="repository@sha256"):
        OciAgentRuntime("agent", "example.invalid/latest", "/agent")


def test_gvisor_oci_agent_conforms_and_responds_without_host_authority(tmp_path: Path) -> None:
    runtime = _runtime()
    runner = _Runner(
        [
            *_attestation(),
            *_execution(
                _response(
                    runtime,
                    "describe",
                    {
                        "agentId": "fixture-agent",
                        "operations": ["describe", "self-test", "respond"],
                        "capabilities": ["semantic-action-planner", "arena-message"],
                    },
                )
            ),
            *_execution(_response(runtime, "self-test", {"status": "pass"})),
            *_execution(
                _response(
                    runtime,
                    "respond",
                    {
                        "responseText": "planned",
                        "structured": {"status": "blocked"},
                        "tokenCount": 17,
                    },
                )
            ),
        ]
    )
    adapter = GVisorOciAgentAdapter(
        runtime,
        GVisorOciExecutor(_docker(tmp_path), IMAGE, runner=runner),
        tmp_path,
    )
    report = adapter.conform()
    assert report["status"] == "pass"
    assert report["isolation"] == "gvisor-runsc-user-kernel"
    assert report["targetAuthorityInherited"] is False
    response = adapter.respond("Return one bounded JSON planning decision.")
    assert response.structured == {"status": "blocked"}
    assert response.token_count == 17
    run_commands = [call for call in runner.calls if len(call) > 1 and call[1] == "run"]
    assert len(run_commands) == 3
    for command in run_commands:
        assert command[command.index("--runtime") + 1] == "runsc"
        assert command[command.index("--network") + 1] == "none"
        assert "--read-only" in command
        assert "--interactive" in command
        assert "--sova-request-stdin" in command
        assert "--mount" not in command
        assert "--volume" not in command
        assert "Return one bounded JSON planning decision." not in command
    requests = [json.loads(value) for value in runner.stdin if value is not None]
    assert len(requests) == 3
    assert requests[-1]["payload"]["prompt"] == "Return one bounded JSON planning decision."


def test_gvisor_oci_agent_fails_closed_on_binding_and_sensitive_input(tmp_path: Path) -> None:
    runtime = _runtime()
    wrong = {
        "protocol": "sova.oci-agent/0.1",
        "runtimeDigest": "sha256:" + "0" * 64,
        "operation": "respond",
        "accepted": True,
        "response": {"responseText": "x", "structured": {}, "tokenCount": None},
    }
    runner = _Runner(
        [
            *_attestation(),
            *_execution(json.dumps(wrong).encode() + b"\n"),
        ]
    )
    adapter = GVisorOciAgentAdapter(
        runtime,
        GVisorOciExecutor(_docker(tmp_path), IMAGE, runner=runner),
        tmp_path,
    )
    with pytest.raises(FormatError, match="binding failed"):
        adapter.respond("Return a safe JSON object.")

    safe_runner = _Runner(_attestation())
    safe_adapter = GVisorOciAgentAdapter(
        runtime,
        GVisorOciExecutor(_docker(tmp_path), IMAGE, runner=safe_runner),
        tmp_path,
    )
    with pytest.raises(FormatError, match="credential-shaped"):
        safe_adapter.respond("Use token Bearer abcdefghijklmnopqrstuvwxyz")
    assert len(safe_runner.calls) == 3


def test_oci_agent_conformance_writes_signed_digest_bound_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime()

    class _Attestation:
        ready = True
        image = IMAGE
        runtime = "runsc"
        digest = "sha256:" + "9" * 64
        limitations = ("fixture gVisor limitation",)

        @staticmethod
        def to_mapping() -> dict[str, object]:
            return {"readiness": "ready", "digest": "sha256:" + "9" * 64}

    class _Executor:
        attestation = _Attestation()

        def execute(
            self, request: object, _context: object, _cancellation: object
        ) -> ActionOutcome:
            argv = request.inputs["argv"]  # type: ignore[attr-defined]
            assert argv == [runtime.entrypoint, "--sova-request-stdin"]
            parsed = json.loads(request.inputs["stdin"])  # type: ignore[attr-defined]
            operation = parsed["operation"]
            response: dict[str, object]
            if operation == "describe":
                response = {
                    "agentId": runtime.identifier,
                    "operations": ["describe", "self-test", "respond"],
                    "capabilities": ["semantic-action-planner"],
                }
            else:
                response = {"status": "pass"}
            stdout = _response(runtime, operation, response).decode()
            return ActionOutcome(
                request.id,  # type: ignore[attr-defined]
                OutcomeStatus.SUCCEEDED,
                SideEffect.MUTATE,
                {
                    "stdout": stdout,
                    "attestationDigest": self.attestation.digest,
                },
                verification="gvisor-fixture-verified",
            )

    monkeypatch.setattr(oci_module, "GVisorOciExecutor", lambda *_args, **_kwargs: _Executor())
    artifacts = run_oci_agent_conformance(
        runtime,
        tmp_path / "docker",
        tmp_path / "conformance",
        approval_prompt=lambda challenge: challenge.exact_phrase,
    )
    assert artifacts.status == "pass"
    assert TraceReader(artifacts.trace).verify(require_signature=True).signature_valid
    report = json.loads(artifacts.report.read_text(encoding="utf-8"))
    assert report["claims"]["gvisorAttestedBeforeAndAfterApproval"] is True
    assert report["claims"]["targetAuthorityInherited"] is False


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (("Bad Agent", IMAGE, "/agent"), "identifier"),
        (("agent", IMAGE, "relative"), "absolute POSIX"),
        (("agent", IMAGE, "/agent", "RUNSC"), "exactly runsc"),
        (("agent", IMAGE, "/agent", "runc"), "exactly runsc"),
        (("agent", IMAGE, "/agent", "runsc", 0), "timeout"),
        (("agent", IMAGE, "/agent", "runsc", 60, 100), "prompt budget"),
        (("agent", IMAGE, "/agent", "runsc", 60, 1024, 100), "response budget"),
    ],
)
def test_oci_runtime_constructor_rejects_invalid_identity_and_budgets(
    arguments: tuple[object, ...], message: str
) -> None:
    with pytest.raises(FormatError, match=message):
        OciAgentRuntime(*arguments)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda value: value.update(extra=True), "fields"),
        (lambda value: value.update(schemaVersion="2"), "unsupported"),
        (lambda value: value.update(budgets=[]), "budgets"),
        (lambda value: value["budgets"].update(timeoutSeconds="60"), "values"),
        (lambda value: value.update(id=1), "values"),
        (lambda value: value.update(runtime="runc"), "exactly runsc"),
    ],
)
def test_oci_runtime_parser_rejects_hostile_shapes(change: object, message: str) -> None:
    value = _runtime().to_mapping()
    change(value)  # type: ignore[operator]
    with pytest.raises(FormatError, match=message):
        oci_agent_runtime_from_mapping(value)


def _fake_attestation(**changes: object) -> SimpleNamespace:
    values: dict[str, object] = {
        "ready": True,
        "image": IMAGE,
        "runtime": "runsc",
        "digest": "sha256:" + "9" * 64,
        "limitations": ("fixture limitation",),
    }
    values.update(changes)
    values["to_mapping"] = lambda: {
        "readiness": "ready" if values["ready"] else "degraded",
        "image": values["image"],
        "runtime": values["runtime"],
        "digest": values["digest"],
    }
    return SimpleNamespace(**values)


class _DirectExecutor:
    def __init__(self, outcomes: list[ActionOutcome], **attestation: object) -> None:
        self.attestation = _fake_attestation(**attestation)
        self.outcomes = list(outcomes)
        self.refreshed: _DirectExecutor | None = None

    def execute(self, *_args: object, **_kwargs: object) -> ActionOutcome:
        return self.outcomes.pop(0)

    def reattest(self) -> _DirectExecutor:
        return self.refreshed or self


def _direct_executor(outcomes: list[ActionOutcome], **attestation: object) -> GVisorOciExecutor:
    return cast("GVisorOciExecutor", _DirectExecutor(outcomes, **attestation))


def _direct_outcome(
    stdout: object, *, status: OutcomeStatus = OutcomeStatus.SUCCEEDED
) -> ActionOutcome:
    return ActionOutcome(
        "oci-agent-test",
        status,
        SideEffect.MUTATE,
        {"stdout": stdout, "attestationDigest": "sha256:" + "9" * 64},
        error_code=None if status == OutcomeStatus.SUCCEEDED else "fixture-failed",
        verification="gvisor-fixture-verified",
    )


@pytest.mark.parametrize(
    ("attestation", "message"),
    [
        ({"ready": False}, "ready gVisor"),
        ({"image": "example.invalid/other@sha256:" + "b" * 64}, "image does not match"),
        ({"runtime": "other"}, "exactly runsc"),
    ],
)
def test_adapter_constructor_rejects_unattested_or_substituted_runtime(
    tmp_path: Path, attestation: dict[str, object], message: str
) -> None:
    executor = _direct_executor([], **attestation)
    with pytest.raises(FormatError, match=message):
        GVisorOciAgentAdapter(_runtime(), executor, tmp_path)


def test_adapter_invoke_refuses_unsupported_budget_workspace_and_execution(
    tmp_path: Path,
) -> None:
    adapter = GVisorOciAgentAdapter(
        _runtime(),
        _direct_executor([]),
        tmp_path,
    )
    with pytest.raises(FormatError, match="unsupported"):
        adapter.invoke("shell", {})

    small = OciAgentRuntime("fixture-agent", IMAGE, "/agent", max_prompt_bytes=1024)
    limited = GVisorOciAgentAdapter(
        small,
        _direct_executor([]),
        tmp_path,
    )
    with pytest.raises(FormatError, match="request exceeds"):
        limited.invoke("respond", {"prompt": "x" * 2000})

    missing = GVisorOciAgentAdapter(
        _runtime(),
        _direct_executor([]),
        tmp_path / "missing",
    )
    with pytest.raises(FormatError, match="workspace is missing"):
        missing.invoke("describe", {})

    failed = GVisorOciAgentAdapter(
        _runtime(),
        _direct_executor([_direct_outcome("", status=OutcomeStatus.FAILED)]),
        tmp_path,
    )
    with pytest.raises(FormatError, match="execution failed"):
        failed.invoke("describe", {})


@pytest.mark.parametrize(
    ("stdout", "message"),
    [
        (7, "output is invalid"),
        ("{}\n{}\n", "exactly one JSON row"),
        ("{}\n", "response fields"),
    ],
)
def test_adapter_rejects_malformed_protocol_output(
    tmp_path: Path, stdout: object, message: str
) -> None:
    adapter = GVisorOciAgentAdapter(
        _runtime(),
        _direct_executor([_direct_outcome(stdout)]),
        tmp_path,
    )
    with pytest.raises(FormatError, match=message):
        adapter.invoke("describe", {})


def test_adapter_conformance_and_response_values_fail_closed(tmp_path: Path) -> None:
    runtime = _runtime()
    invalid_description = _response(runtime, "describe", {"agentId": runtime.identifier})
    adapter = GVisorOciAgentAdapter(
        runtime,
        _direct_executor(
            [
                _direct_outcome(invalid_description.decode()),
                _direct_outcome(_response(runtime, "self-test", {"status": "pass"}).decode()),
            ]
        ),
        tmp_path,
    )
    with pytest.raises(FormatError, match="describe response"):
        adapter.conform()

    rejected = {
        "protocol": "sova.oci-agent/0.1",
        "runtimeDigest": runtime.digest,
        "operation": "respond",
        "accepted": False,
        "response": {"responseText": "", "structured": {}, "tokenCount": None},
    }
    adapter = GVisorOciAgentAdapter(
        runtime,
        _direct_executor([_direct_outcome(json.dumps(rejected) + "\n")]),
        tmp_path,
    )
    with pytest.raises(FormatError, match="response is invalid"):
        adapter.respond("safe")

    invalid_values = _response(
        runtime,
        "respond",
        {"responseText": 1, "structured": {}, "tokenCount": -1},
    )
    adapter = GVisorOciAgentAdapter(
        runtime,
        _direct_executor([_direct_outcome(invalid_values.decode())]),
        tmp_path,
    )
    with pytest.raises(FormatError, match="response values"):
        adapter.respond("safe")


def test_external_agent_authorization_scope_and_exact_phrase(tmp_path: Path) -> None:
    runtime = _runtime()
    executor = _direct_executor([])
    with pytest.raises(FormatError, match="scope is required"):
        authorize_oci_agent_adapter(
            runtime, executor, tmp_path, use_scope={}, approval_prompt=lambda _value: ""
        )
    with pytest.raises(FormatError, match="credential-shaped"):
        authorize_oci_agent_adapter(
            runtime,
            executor,
            tmp_path,
            use_scope={"token": "Bearer abcdefghijklmnopqrstuvwxyz"},
            approval_prompt=lambda _value: "",
        )
    with pytest.raises(FormatError, match="approval was not granted"):
        authorize_oci_agent_adapter(
            runtime,
            executor,
            tmp_path,
            use_scope={"purpose": "fixture"},
            approval_prompt=lambda _value: "wrong",
        )
    adapter = authorize_oci_agent_adapter(
        runtime,
        executor,
        tmp_path,
        use_scope={"purpose": "fixture"},
        approval_prompt=lambda value: value.exact_phrase,
    )
    assert adapter.model_id.startswith("oci-agent:fixture-agent:sha256:")

    before = _DirectExecutor([], digest="sha256:" + "1" * 64)
    before.refreshed = _DirectExecutor([], digest="sha256:" + "2" * 64)
    with pytest.raises(FormatError, match="scope changed"):
        authorize_oci_agent_adapter(
            runtime,
            cast("GVisorOciExecutor", before),
            tmp_path,
            use_scope={"purpose": "fixture"},
            approval_prompt=lambda value: value.exact_phrase,
        )


def test_conformance_rejects_destination_attestation_approval_and_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "occupied"
    destination.mkdir()
    (destination / "file").write_text("x", encoding="utf-8")
    with pytest.raises(FormatError, match="empty real directory"):
        run_oci_agent_conformance(
            _runtime(),
            tmp_path / "docker",
            destination,
            approval_prompt=lambda value: value.exact_phrase,
        )

    monkeypatch.setattr(
        oci_module,
        "GVisorOciExecutor",
        lambda *_args, **_kwargs: _DirectExecutor([], ready=False),
    )
    with pytest.raises(FormatError, match="ready gVisor"):
        run_oci_agent_conformance(
            _runtime(),
            tmp_path / "docker",
            tmp_path / "not-ready",
            approval_prompt=lambda value: value.exact_phrase,
        )

    monkeypatch.setattr(
        oci_module,
        "GVisorOciExecutor",
        lambda *_args, **_kwargs: _DirectExecutor([]),
    )
    with pytest.raises(FormatError, match="approval was not granted"):
        run_oci_agent_conformance(
            _runtime(),
            tmp_path / "docker",
            tmp_path / "denied",
            approval_prompt=lambda _value: "no",
        )

    executors = iter(
        (
            _DirectExecutor([], digest="sha256:" + "1" * 64),
            _DirectExecutor([], digest="sha256:" + "2" * 64),
        )
    )
    monkeypatch.setattr(
        oci_module,
        "GVisorOciExecutor",
        lambda *_args, **_kwargs: next(executors),
    )
    with pytest.raises(FormatError, match="scope changed"):
        run_oci_agent_conformance(
            _runtime(),
            tmp_path / "docker",
            tmp_path / "drift",
            approval_prompt=lambda value: value.exact_phrase,
        )
