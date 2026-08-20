# SPDX-License-Identifier: Apache-2.0
"""gVisor runsc attestation and executor conformance."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from sova.executors import (
    ActionRequest,
    CancellationToken,
    DockerCommandResult,
    ExecutionContext,
    GVisorOciExecutor,
    OutcomeStatus,
    attest_gvisor,
    gvisor_backend_descriptor,
)
from sova.formats.errors import FormatError
from sova.safety import ContainmentGate, ContainmentRequirements, IsolationKind

IMAGE = "example.invalid/sova/fixture@sha256:" + "b" * 64


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


def _attestation_results() -> list[DockerCommandResult]:
    return [
        _completed(json.dumps({"runc": {}, "runsc": {"path": "/usr/local/bin/runsc"}}).encode()),
        _completed(json.dumps("29.4.2").encode()),
        _completed(json.dumps([IMAGE]).encode()),
    ]


def _docker(tmp_path: Path) -> Path:
    executable = tmp_path / "docker"
    executable.write_bytes(b"fixture")
    return executable


def test_gvisor_attestation_requires_registered_runtime_and_cached_digest(tmp_path: Path) -> None:
    runner = _Runner(_attestation_results())
    attestation = attest_gvisor(_docker(tmp_path), IMAGE, runner=runner)
    assert attestation.ready
    assert attestation.runtime_registered
    assert attestation.image_cached
    descriptor = gvisor_backend_descriptor(attestation)
    assert descriptor.isolation == IsolationKind.USER_KERNEL
    assert (
        ContainmentGate()
        .assess(
            descriptor,
            ContainmentRequirements(minimum_isolation=IsolationKind.USER_KERNEL),
        )
        .allowed
    )

    missing_runtime = _Runner(
        [
            _completed(json.dumps({"runc": {}}).encode()),
            _completed(json.dumps("29.4.2").encode()),
            _completed(json.dumps([IMAGE]).encode()),
        ]
    )
    degraded = attest_gvisor(_docker(tmp_path), IMAGE, runner=missing_runtime)
    assert degraded.readiness == "degraded"
    assert "runsc-runtime-not-registered" in degraded.reasons


def test_gvisor_executor_emits_hardened_runtime_and_verifies_cleanup(tmp_path: Path) -> None:
    runner = _Runner(
        [
            *_attestation_results(),
            _completed(b"65534\n"),
            _completed(code=1),
            _completed(),
        ]
    )
    executor = GVisorOciExecutor(_docker(tmp_path), IMAGE, runner=runner)
    outcome = executor.execute(
        ActionRequest("run", "process.exec", {"argv": ["/usr/bin/id", "-u"]}, 10),
        ExecutionContext(tmp_path, {"decision": "allowed"}),
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.SUCCEEDED
    assert outcome.output["runtime"] == "runsc"
    assert outcome.output["cleanupVerified"] is True
    command = runner.calls[3]
    assert command[command.index("--runtime") + 1] == "runsc"
    for required in (
        "--pull",
        "never",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "no-new-privileges:true",
        "--user",
        "65534:65534",
    ):
        assert required in command
    assert not {"--mount", "--volume", "--privileged"} & set(command)
    assert "--interactive" not in command
    assert runner.stdin[3] is None


def test_gvisor_executor_passes_bounded_stdin_without_command_line_exposure(
    tmp_path: Path,
) -> None:
    runner = _Runner(
        [
            *_attestation_results(),
            _completed(b"ok\n"),
            _completed(code=1),
            _completed(),
        ]
    )
    executor = GVisorOciExecutor(_docker(tmp_path), IMAGE, runner=runner)
    payload = '{"mission":"bounded"}'
    outcome = executor.execute(
        ActionRequest(
            "stdin",
            "process.exec",
            {"argv": ["/opt/sova/agent", "--sova-request-stdin"], "stdin": payload},
            10,
        ),
        ExecutionContext(tmp_path, {"decision": "allowed"}),
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.SUCCEEDED
    command = runner.calls[3]
    assert "--interactive" in command
    assert payload not in command
    assert runner.stdin[3] == payload.encode()


def test_gvisor_executor_fails_closed_on_bad_inputs_and_unready_runtime(tmp_path: Path) -> None:
    with pytest.raises(FormatError, match="must exist"):
        attest_gvisor(tmp_path / "missing-docker", IMAGE, runner=_Runner([]))
    with pytest.raises(FormatError, match="repository@sha256"):
        attest_gvisor(_docker(tmp_path), "example.invalid/latest", runner=_Runner([]))
    with pytest.raises(FormatError, match="exactly runsc"):
        attest_gvisor(_docker(tmp_path), IMAGE, runtime="../runsc", runner=_Runner([]))
    with pytest.raises(FormatError, match="exactly runsc"):
        attest_gvisor(_docker(tmp_path), IMAGE, runtime="runc", runner=_Runner([]))

    unavailable = GVisorOciExecutor(
        _docker(tmp_path),
        IMAGE,
        runner=_Runner([_completed(code=1), _completed(code=1), _completed(code=1)]),
    )
    assert unavailable.capabilities() == ()
    denied = unavailable.execute(
        ActionRequest("run", "process.exec", {"argv": ["/bin/true"]}, 10),
        ExecutionContext(tmp_path, {"decision": "allowed"}),
        CancellationToken(),
    )
    assert denied.status == OutcomeStatus.DENIED

    ready = GVisorOciExecutor(_docker(tmp_path), IMAGE, runner=_Runner(_attestation_results()))
    with pytest.raises(FormatError, match="only argv"):
        ready.execute(
            ActionRequest(
                "bad",
                "process.exec",
                {"argv": ["/bin/true"], "env": {"SECRET": "no"}},
                10,
            ),
            ExecutionContext(tmp_path, {"decision": "allowed"}),
            CancellationToken(),
        )


def test_gvisor_attestation_handles_engine_failures_malformed_json_and_missing_image(
    tmp_path: Path,
) -> None:
    unavailable = attest_gvisor(
        _docker(tmp_path),
        IMAGE,
        runner=_Runner([_completed(code=1), _completed(code=1), _completed(code=1)]),
    )
    assert unavailable.readiness == "unavailable"
    assert len(unavailable.reasons) == 3
    assert gvisor_backend_descriptor(unavailable).readiness.value == "unavailable"

    with pytest.raises(FormatError, match="malformed JSON"):
        attest_gvisor(
            _docker(tmp_path),
            IMAGE,
            runner=_Runner([_completed(b"not-json"), _completed(b'"1"'), _completed(b"[]")]),
        )

    degraded = attest_gvisor(
        _docker(tmp_path),
        IMAGE,
        runner=_Runner(
            [
                _completed(b'{"runsc":{}}'),
                _completed(b"null"),
                _completed(b"[]"),
            ]
        ),
    )
    assert degraded.engine_server_version is None
    assert "exact-image-digest-not-confirmed" in degraded.reasons


def test_gvisor_executor_cancellation_status_cleanup_and_argv_bounds(tmp_path: Path) -> None:
    ready_runner = _Runner(_attestation_results())
    executor = GVisorOciExecutor(_docker(tmp_path), IMAGE, runner=ready_runner)
    unsupported = executor.execute(
        ActionRequest("read", "filesystem.read", {}, 1),
        ExecutionContext(tmp_path, {"decision": "allowed"}),
        CancellationToken(),
    )
    token = CancellationToken()
    token.cancel()
    cancelled = executor.execute(
        ActionRequest("cancel", "process.exec", {"argv": ["/bin/true"]}, 1),
        ExecutionContext(tmp_path, {"decision": "allowed"}),
        token,
    )
    assert unsupported.status == OutcomeStatus.UNSUPPORTED
    assert cancelled.status == OutcomeStatus.CANCELLED

    invalid_inputs: tuple[dict[str, object], ...] = (
        {"argv": []},
        {"argv": ["relative"]},
        {"argv": [r"/bin\bad"]},
        {"argv": ["/bin/echo", "x" * (64 * 1024)]},
        {"argv": ["/bin/true"], "stdin": b"not text"},
        {"argv": ["/bin/true"], "stdin": "x" * (64 * 1024 + 1)},
    )
    for inputs in invalid_inputs:
        with pytest.raises(FormatError):
            executor.execute(
                ActionRequest("bad", "process.exec", inputs, 1),
                ExecutionContext(tmp_path, {"decision": "allowed"}),
                CancellationToken(),
            )

    cleanup_failure = _Runner(
        [
            *_attestation_results(),
            _completed(b"partial output"),
            _completed(),
            _completed(b"sova-runsc-still-present"),
        ]
    )
    partial_executor = GVisorOciExecutor(_docker(tmp_path), IMAGE, runner=cleanup_failure)
    partial = partial_executor.execute(
        ActionRequest("partial", "process.exec", {"argv": ["/bin/true"]}, 1),
        ExecutionContext(tmp_path, {"decision": "allowed"}),
        CancellationToken(),
    )
    assert partial.status == OutcomeStatus.PARTIAL
    assert partial.output["cleanupVerified"] is False

    daemon_outage = _Runner(
        [
            *_attestation_results(),
            _completed(b"observed"),
            _completed(code=1),
            _completed(code=1),
        ]
    )
    outage_executor = GVisorOciExecutor(_docker(tmp_path), IMAGE, runner=daemon_outage)
    outage = outage_executor.execute(
        ActionRequest("daemon-outage", "process.exec", {"argv": ["/bin/true"]}, 1),
        ExecutionContext(tmp_path, {"decision": "allowed"}),
        CancellationToken(),
    )
    assert outage.status == OutcomeStatus.PARTIAL
    assert outage.output["cleanupVerified"] is False


@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("SOVA_RUN_REAL_GVISOR") != "1",
    reason="set SOVA_RUN_REAL_GVISOR=1 with a cached digest-pinned test image",
)
def test_optional_real_gvisor_user_kernel_boundary(tmp_path: Path) -> None:
    docker = shutil.which("docker")
    image = os.environ.get("SOVA_GVISOR_TEST_IMAGE")
    if docker is None or image is None:
        pytest.skip("container engine and exact cached gVisor test image are required")
    executor = GVisorOciExecutor(Path(docker), image)
    assert executor.attestation.ready
    outcome = executor.execute(
        ActionRequest("real-runsc", "process.exec", {"argv": ["/bin/true"]}, 30),
        ExecutionContext(tmp_path, {"decision": "allowed"}),
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.SUCCEEDED
    assert outcome.output["runtime"] == "runsc"
    assert outcome.output["cleanupVerified"] is True
