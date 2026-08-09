# SPDX-License-Identifier: Apache-2.0
"""Conformance and hostile-input tests for the VM-hosted OCI executor."""

from __future__ import annotations

import json
import os
import shutil
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

from sova.executors import (
    ActionRequest,
    BoundedDockerCommandRunner,
    CancellationToken,
    DockerCommandResult,
    DockerDesktopIsolationPolicy,
    DockerDesktopOciExecutor,
    ExecutionContext,
    OutcomeStatus,
    attest_docker_desktop,
    docker_desktop_backend_descriptor,
)
from sova.formats.errors import FormatError
from sova.safety import ContainmentGate, ContainmentRequirements, IsolationKind

IMAGE = "example.invalid/sova/fixture@sha256:" + "a" * 64


class _Runner:
    def __init__(self, results: list[DockerCommandResult]) -> None:
        self.results = list(results)
        self.calls: list[tuple[str, ...]] = []

    def run(
        self,
        argv: tuple[str, ...],
        *,
        timeout_seconds: float,
        cancellation: CancellationToken,
        max_output_bytes: int,
    ) -> DockerCommandResult:
        assert timeout_seconds > 0
        assert max_output_bytes >= 1024
        assert not cancellation.cancelled
        self.calls.append(argv)
        return self.results.pop(0)


def _completed(stdout: bytes = b"", stderr: bytes = b"", code: int = 0) -> DockerCommandResult:
    return DockerCommandResult("completed", code, stdout, stderr)


def _attestation_results(*, image_cached: bool = True) -> list[DockerCommandResult]:
    version = {
        "Client": {"Version": "29.4.2", "Os": "windows"},
        "Server": {
            "Version": "29.4.2",
            "Os": "linux",
            "Platform": {"Name": "Docker Desktop 4.72.0"},
        },
    }
    info = {
        "OperatingSystem": "Docker Desktop",
        "KernelVersion": "6.6.87.2-microsoft-standard-WSL2",
        "CgroupVersion": "2",
        "SecurityOptions": ["name=seccomp,profile=builtin", "name=cgroupns"],
        "MemoryLimit": True,
        "CpuCfsQuota": True,
        "PidsLimit": True,
    }
    digests = [IMAGE] if image_cached else []
    return [
        _completed(json.dumps(version).encode()),
        _completed(json.dumps(info).encode()),
        _completed(json.dumps(digests).encode()),
    ]


def _docker(tmp_path: Path) -> Path:
    value = tmp_path / "docker.exe"
    value.write_bytes(b"deterministic fixture")
    return value


def test_attestation_requires_cached_digest_vm_and_enforcement(tmp_path: Path) -> None:
    runner = _Runner(_attestation_results())
    attestation = attest_docker_desktop(_docker(tmp_path), IMAGE, runner=runner)
    assert attestation.ready
    assert attestation.docker_desktop_vm
    assert attestation.seccomp
    assert attestation.memory_limit
    assert attestation.cpu_limit
    assert attestation.pids_limit
    assert len(attestation.digest) == 71
    assert runner.calls[2][1:3] == ("image", "inspect")
    descriptor = docker_desktop_backend_descriptor(attestation)
    decision = ContainmentGate().assess(
        descriptor,
        ContainmentRequirements(minimum_isolation=IsolationKind.CONTAINER),
    )
    assert decision.allowed
    assert descriptor.isolation == IsolationKind.CONTAINER

    missing = _Runner(_attestation_results(image_cached=False))
    degraded = attest_docker_desktop(_docker(tmp_path), IMAGE, runner=missing)
    assert degraded.readiness == "degraded"
    assert "exact-image-digest-not-confirmed" in degraded.reasons


def test_attestation_refuses_tags_missing_daemon_and_malformed_json(tmp_path: Path) -> None:
    docker = _docker(tmp_path)
    with pytest.raises(FormatError, match="repository@sha256"):
        attest_docker_desktop(docker, "example.invalid/sova:latest", runner=_Runner([]))

    unavailable_runner = _Runner(
        [
            DockerCommandResult("start-failed", None, b"", b""),
            _completed(code=1),
            _completed(code=1),
        ]
    )
    unavailable = attest_docker_desktop(docker, IMAGE, runner=unavailable_runner)
    assert unavailable.readiness == "unavailable"
    assert "docker-daemon-unavailable" in unavailable.reasons

    malformed = _Runner([_completed(b"{"), *_attestation_results()[1:]])
    with pytest.raises(FormatError, match="malformed JSON"):
        attest_docker_desktop(docker, IMAGE, runner=malformed)

    bad_image_json = _Runner([*_attestation_results()[:2], _completed(b"{")])
    with pytest.raises(FormatError, match="malformed image JSON"):
        attest_docker_desktop(docker, IMAGE, runner=bad_image_json)


def test_bounded_command_runner_normalizes_process_edges() -> None:
    runner = BoundedDockerCommandRunner()
    token = CancellationToken()
    completed = runner.run(
        (sys.executable, "-c", "print('bounded')"),
        timeout_seconds=5,
        cancellation=token,
        max_output_bytes=1024,
    )
    assert completed.state == "completed"
    assert completed.returncode == 0
    assert completed.stdout.strip() == b"bounded"

    missing = runner.run(
        (str(Path(sys.executable).with_name("sova-definitely-missing.exe")),),
        timeout_seconds=1,
        cancellation=CancellationToken(),
        max_output_bytes=1024,
    )
    assert missing.state == "start-failed"

    cancelled_before_start = CancellationToken()
    cancelled_before_start.cancel()
    assert (
        runner.run(
            (sys.executable, "-c", "raise SystemExit(99)"),
            timeout_seconds=1,
            cancellation=cancelled_before_start,
            max_output_bytes=1024,
        ).state
        == "cancelled"
    )

    timeout = runner.run(
        (sys.executable, "-c", "import time; time.sleep(2)"),
        timeout_seconds=0.05,
        cancellation=CancellationToken(),
        max_output_bytes=1024,
    )
    assert timeout.state == "timeout"

    output_limit = runner.run(
        (
            sys.executable,
            "-c",
            "import sys,time; sys.stdout.write('x'*4096); sys.stdout.flush(); time.sleep(2)",
        ),
        timeout_seconds=5,
        cancellation=CancellationToken(),
        max_output_bytes=1024,
    )
    assert output_limit.state == "output-limit"
    assert len(output_limit.stdout) == 1024

    cancellation = CancellationToken()
    timer = threading.Timer(0.05, cancellation.cancel)
    timer.start()
    try:
        interrupted = runner.run(
            (sys.executable, "-c", "import time; time.sleep(2)"),
            timeout_seconds=5,
            cancellation=cancellation,
            max_output_bytes=1024,
        )
    finally:
        timer.cancel()
    assert interrupted.state == "cancelled"


def test_executor_emits_exact_hardened_argv_and_verifies_cleanup(tmp_path: Path) -> None:
    runner = _Runner(
        [
            *_attestation_results(),
            _completed(b"observed\n"),
            _completed(code=1),
            _completed(code=1),
        ]
    )
    executor = DockerDesktopOciExecutor(_docker(tmp_path), IMAGE, runner=runner)
    assert executor.capabilities()[0].identifier == "process.exec/0.1"
    outcome = executor.execute(
        ActionRequest("step-1", "process.exec", {"argv": ["/bin/echo", "safe"]}, 10),
        ExecutionContext(tmp_path, {"decision": "allowed"}),
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.SUCCEEDED
    assert outcome.output["stdout"] == "observed\n"
    assert outcome.output["cleanupVerified"] is True
    command = runner.calls[3]
    for required in (
        "--pull",
        "never",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "no-new-privileges:true",
        "--pids-limit",
        "--memory",
        "--cpus",
        "--user",
        "65534:65534",
        "--log-driver",
        "none",
    ):
        assert required in command
    for forbidden in ("--mount", "--volume", "--privileged", "--network=host"):
        assert forbidden not in command
    assert IMAGE in command
    entrypoint_index = command.index("--entrypoint")
    assert command[entrypoint_index + 1] == "/bin/echo"
    assert command[-2:] == (IMAGE, "safe")
    assert runner.calls[-1][1] == "inspect"


def test_executor_fails_closed_on_cleanup_input_and_cancellation(tmp_path: Path) -> None:
    cleanup_failure = _Runner(
        [
            *_attestation_results(),
            DockerCommandResult("timeout", None, b"partial", b""),
            _completed(),
            _completed(b"still-present"),
        ]
    )
    executor = DockerDesktopOciExecutor(_docker(tmp_path), IMAGE, runner=cleanup_failure)
    outcome = executor.execute(
        ActionRequest("step-1", "process.exec", {"argv": ["/bin/sleep", "60"]}, 1),
        ExecutionContext(tmp_path, {"decision": "allowed"}),
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.PARTIAL
    assert outcome.error_code == "SOVA-OCI-CLEANUP-UNVERIFIED"

    invalid_inputs: tuple[dict[str, Any], ...] = (
        {"argv": ["relative"]},
        {"argv": ["C:\\Windows\\cmd.exe"]},
        {"argv": ["/bin/true"], "env": {"SECRET": "no"}},
        {"argv": []},
    )
    for inputs in invalid_inputs:
        fresh = _Runner(_attestation_results())
        invalid = DockerDesktopOciExecutor(_docker(tmp_path), IMAGE, runner=fresh)
        with pytest.raises(FormatError):
            invalid.execute(
                ActionRequest("bad", "process.exec", inputs, 1),
                ExecutionContext(tmp_path, {"decision": "allowed"}),
                CancellationToken(),
            )

    token = CancellationToken()
    token.cancel()
    cancelled = DockerDesktopOciExecutor(
        _docker(tmp_path), IMAGE, runner=_Runner(_attestation_results())
    ).execute(
        ActionRequest("cancelled", "process.exec", {"argv": ["/bin/true"]}, 1),
        ExecutionContext(tmp_path, {"decision": "allowed"}),
        token,
    )
    assert cancelled.status == OutcomeStatus.CANCELLED


def test_executor_refuses_unattested_and_unsupported_backends(tmp_path: Path) -> None:
    unavailable_runner = _Runner(
        [
            _completed(code=1),
            _completed(code=1),
            _completed(code=1),
        ]
    )
    unavailable = DockerDesktopOciExecutor(_docker(tmp_path), IMAGE, runner=unavailable_runner)
    assert unavailable.capabilities() == ()
    denied = unavailable.execute(
        ActionRequest("denied", "process.exec", {"argv": ["/bin/true"]}, 1),
        ExecutionContext(tmp_path, {"decision": "allowed"}),
        CancellationToken(),
    )
    assert denied.status == OutcomeStatus.DENIED
    assert denied.error_code == "SOVA-OCI-NOT-ATTESTED"

    ready_runner = _Runner(_attestation_results())
    ready = DockerDesktopOciExecutor(_docker(tmp_path), IMAGE, runner=ready_runner)
    unsupported = ready.execute(
        ActionRequest("unsupported", "browser.navigate", {}, 1),
        ExecutionContext(tmp_path, {"decision": "allowed"}),
        CancellationToken(),
    )
    assert unsupported.status == OutcomeStatus.UNSUPPORTED


def test_policy_bounds_are_explicit() -> None:
    with pytest.raises(FormatError, match="memory"):
        DockerDesktopIsolationPolicy(memory_bytes=1024)
    with pytest.raises(FormatError, match="CPU"):
        DockerDesktopIsolationPolicy(cpus="0")
    with pytest.raises(FormatError, match="PID"):
        DockerDesktopIsolationPolicy(pids_limit=1)
    with pytest.raises(FormatError, match="tmpfs"):
        DockerDesktopIsolationPolicy(tmpfs_bytes=1)
    with pytest.raises(FormatError, match="output"):
        DockerDesktopIsolationPolicy(max_output_bytes=1)
    with pytest.raises(FormatError, match="runtime"):
        DockerDesktopIsolationPolicy(max_runtime_seconds=0)


@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("SOVA_RUN_REAL_DOCKER") != "1",
    reason="set SOVA_RUN_REAL_DOCKER=1 with a cached SOVA_DOCKER_TEST_IMAGE digest",
)
def test_optional_real_docker_desktop_isolation(tmp_path: Path) -> None:
    docker_value = shutil.which("docker")
    image = os.environ.get("SOVA_DOCKER_TEST_IMAGE")
    if docker_value is None or image is None:
        pytest.skip("Docker executable and exact cached test image are required")
    executor = DockerDesktopOciExecutor(Path(docker_value), image)
    assert executor.attestation.ready
    outcome = executor.execute(
        ActionRequest(
            "real-boundary",
            "process.exec",
            {
                "argv": [
                    "/bin/sh",
                    "-c",
                    "id -u; grep CapEff /proc/self/status; grep NoNewPrivs /proc/self/status",
                ]
            },
            30,
        ),
        ExecutionContext(tmp_path, {"decision": "allowed"}),
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.SUCCEEDED
    assert "65534" in outcome.output["stdout"]
    assert "0000000000000000" in outcome.output["stdout"]
    assert outcome.output["cleanupVerified"] is True
