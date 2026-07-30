# SPDX-License-Identifier: Apache-2.0
"""Executor contract and restricted-local conformance tests."""

from __future__ import annotations

import sys
import threading
from pathlib import Path

import pytest

from sova.executors import (
    ActionRequest,
    CancellationToken,
    Capability,
    ExecutionContext,
    OutcomeStatus,
    RestrictedLocalExecutor,
    ScriptedAction,
    ScriptedExecutor,
    SideEffect,
    negotiate,
)
from sova.formats import sha256_digest
from sova.formats.errors import FormatError


@pytest.fixture
def context(tmp_path: Path) -> ExecutionContext:
    return ExecutionContext(
        workspace=tmp_path,
        authorization={"decision": "allowed"},
        artifacts={sha256_digest(b"portable fixture"): b"portable fixture"},
    )


def _request(
    action: str,
    inputs: dict[str, object],
    *,
    timeout: float = 2,
) -> ActionRequest:
    return ActionRequest("action-1", action, inputs, timeout)


def _local(*, max_output_bytes: int = 1024 * 1024) -> RestrictedLocalExecutor:
    return RestrictedLocalExecutor(
        executable_allowlist=(Path(sys.executable),),
        max_output_bytes=max_output_bytes,
    )


def test_contract_rejects_invalid_requests_and_workspace(tmp_path: Path) -> None:
    for request_id, action in (("", "read"), ("id", "")):
        with pytest.raises(FormatError, match="non-empty"):
            ActionRequest(request_id, action, {}, 1)
    for timeout in (0, -1, 3601):
        with pytest.raises(FormatError, match="at most one hour"):
            ActionRequest("id", "read", {}, timeout)
    with pytest.raises(FormatError, match="cannot be negative"):
        ActionRequest("id", "read", {}, 1, retry_attempt=-1)
    with pytest.raises(FormatError, match="existing directory"):
        ExecutionContext(tmp_path / "missing", {"decision": "allowed"})


def test_exact_capability_negotiation_does_not_substitute_versions() -> None:
    capabilities = (
        Capability(
            name="artifact.read",
            version="0.1",
            side_effect=SideEffect.READ,
            idempotent=True,
            evidence=("digest",),
        ),
    )
    report = negotiate(
        capabilities,
        ["artifact.read/0.1", "artifact.read/0.2", "browser.click/0.1"],
    )
    assert report.supported == ("artifact.read/0.1",)
    assert report.missing == ("artifact.read/0.2", "browser.click/0.1")
    assert not report.compatible
    assert negotiate(capabilities, ["artifact.read/0.1"]).compatible


@pytest.mark.parametrize("status", list(OutcomeStatus))
def test_scripted_executor_preserves_normalized_statuses(
    tmp_path: Path,
    status: OutcomeStatus,
) -> None:
    executor = ScriptedExecutor(
        [
            ScriptedAction(
                "fixture.read",
                {"name": "safe"},
                status,
                {"value": "observed"},
                evidence=(("result", "text/plain", b"observed"),),
                retryable=status in {OutcomeStatus.TIMEOUT, OutcomeStatus.FAILED},
                error_code=None if status == OutcomeStatus.SUCCEEDED else "SYNTHETIC",
            )
        ]
    )
    outcome = executor.execute(
        _request("fixture.read", {"name": "safe"}),
        ExecutionContext(tmp_path, {"decision": "allowed"}),
        CancellationToken(),
    )
    assert outcome.status == status
    assert outcome.side_effect == SideEffect.READ
    assert outcome.evidence[0].digest == sha256_digest(b"observed")
    assert outcome.verification == "scripted-observation"
    assert executor.complete


def test_scripted_executor_cancellation_unsupported_mismatch_and_exhaustion(
    context: ExecutionContext,
) -> None:
    advertised = (
        Capability(
            name="fixture.read",
            version="0.1",
            side_effect=SideEffect.READ,
            idempotent=True,
            evidence=("result",),
        ),
    )
    executor = ScriptedExecutor(
        [
            ScriptedAction(
                "fixture.read",
                {"name": "expected"},
                OutcomeStatus.SUCCEEDED,
                {},
            )
        ],
        advertised=advertised,
    )
    token = CancellationToken()
    token.cancel()
    cancelled = executor.execute(
        _request("fixture.read", {"name": "expected"}),
        context,
        token,
    )
    assert cancelled.status == OutcomeStatus.CANCELLED
    unsupported = executor.execute(
        _request("browser.click", {"target": "none"}),
        context,
        CancellationToken(),
    )
    assert unsupported.status == OutcomeStatus.UNSUPPORTED
    with pytest.raises(FormatError, match="differs"):
        executor.execute(
            _request("fixture.read", {"name": "wrong"}),
            context,
            CancellationToken(),
        )
    assert executor.complete
    with pytest.raises(FormatError, match="more actions"):
        executor.execute(
            _request("fixture.read", {"name": "expected"}),
            context,
            CancellationToken(),
        )


def test_scripted_executor_supports_fixture_evidence_retry_and_effect_classes(
    context: ExecutionContext,
) -> None:
    screenshot = b"\x89PNG\r\n\x1a\nsynthetic"
    executor = ScriptedExecutor(
        [
            ScriptedAction(
                "browser.screenshot",
                {"tab": "fixture"},
                OutcomeStatus.PARTIAL,
                {"captured": True},
                side_effect=SideEffect.READ,
                evidence=(("screenshot", "image/png", screenshot),),
                verification="fixture-pixels-only",
                retryable=True,
            ),
            ScriptedAction(
                "process.delete",
                {"path": "synthetic"},
                OutcomeStatus.DENIED,
                {},
                side_effect=SideEffect.DESTRUCTIVE,
                error_code="SYNTHETIC-DENIAL",
            ),
        ]
    )
    capabilities = {item.name: item for item in executor.capabilities()}
    assert capabilities["browser.screenshot"].side_effect == SideEffect.READ
    assert capabilities["process.delete"].side_effect == SideEffect.DESTRUCTIVE
    screenshot_outcome = executor.execute(
        ActionRequest(
            "retry-2",
            "browser.screenshot",
            {"tab": "fixture"},
            1,
            retry_attempt=2,
        ),
        context,
        CancellationToken(),
    )
    assert screenshot_outcome.status == OutcomeStatus.PARTIAL
    assert screenshot_outcome.retryable
    assert screenshot_outcome.evidence[0].digest == sha256_digest(screenshot)
    denied = executor.execute(
        _request("process.delete", {"path": "synthetic"}),
        context,
        CancellationToken(),
    )
    assert denied.status == OutcomeStatus.DENIED
    assert denied.side_effect == SideEffect.DESTRUCTIVE


def test_local_artifact_read_is_content_addressed_and_never_opens_host_path(
    context: ExecutionContext,
) -> None:
    digest = sha256_digest(b"portable fixture")
    executor = RestrictedLocalExecutor()
    outcome = executor.execute(
        _request("artifact.read", {"digest": digest, "mediaType": "text/plain"}),
        context,
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.SUCCEEDED
    assert outcome.output == {
        "digest": digest,
        "size": 16,
        "mediaType": "text/plain",
        "text": "portable fixture",
    }
    assert outcome.evidence[0].digest == digest
    assert "no host path" in outcome.limitations[0]
    missing = executor.execute(
        _request("artifact.read", {"digest": "sha256:" + ("0" * 64)}),
        context,
        CancellationToken(),
    )
    assert missing.status == OutcomeStatus.FAILED
    assert missing.error_code == "SOVA-LOCAL-ARTIFACT-MISSING"


def test_local_cancellation_and_unsupported_capability(
    context: ExecutionContext,
) -> None:
    token = CancellationToken()
    token.cancel()
    cancelled = RestrictedLocalExecutor().execute(
        _request("artifact.read", {"digest": next(iter(context.artifacts))}),
        context,
        token,
    )
    assert cancelled.status == OutcomeStatus.CANCELLED
    unsupported = RestrictedLocalExecutor().execute(
        _request("browser.click", {}),
        context,
        CancellationToken(),
    )
    assert unsupported.status == OutcomeStatus.UNSUPPORTED
    assert "security sandbox" in unsupported.limitations[1]


@pytest.mark.parametrize(
    ("code", "expected_status", "expected_returncode"),
    [
        ("print('ok')", OutcomeStatus.SUCCEEDED, 0),
        ("import sys; sys.exit(3)", OutcomeStatus.FAILED, 3),
    ],
)
def test_local_process_normalizes_success_and_failure(
    context: ExecutionContext,
    code: str,
    expected_status: OutcomeStatus,
    expected_returncode: int,
) -> None:
    outcome = _local().execute(
        _request("process.exec", {"argv": [sys.executable, "-c", code]}),
        context,
        CancellationToken(),
    )
    assert outcome.status == expected_status
    assert outcome.output["returncode"] == expected_returncode
    assert outcome.verification == "process-exit-and-bounded-output-observed"
    assert len(outcome.evidence) == 2
    assert "not a security sandbox" in outcome.limitations[0]


def test_local_process_timeout_cancellation_and_output_limit(
    context: ExecutionContext,
) -> None:
    timeout = _local().execute(
        _request(
            "process.exec",
            {"argv": [sys.executable, "-c", "import time; time.sleep(2)"]},
            timeout=0.05,
        ),
        context,
        CancellationToken(),
    )
    assert timeout.status == OutcomeStatus.TIMEOUT

    token = CancellationToken()
    timer = threading.Timer(0.05, token.cancel)
    timer.start()
    try:
        cancelled = _local().execute(
            _request(
                "process.exec",
                {"argv": [sys.executable, "-c", "import time; time.sleep(2)"]},
            ),
            context,
            token,
        )
    finally:
        timer.cancel()
    assert cancelled.status == OutcomeStatus.CANCELLED

    partial = _local(max_output_bytes=1024).execute(
        _request(
            "process.exec",
            {"argv": [sys.executable, "-c", "print('x' * 4096)"]},
        ),
        context,
        CancellationToken(),
    )
    assert partial.status == OutcomeStatus.PARTIAL
    assert len(partial.output["stdout"].encode()) == 1024


def test_local_process_denies_untrusted_paths_and_environment(
    context: ExecutionContext,
    tmp_path: Path,
) -> None:
    executor = _local()
    not_absolute = executor.execute(
        _request("process.exec", {"argv": ["python", "-c", "print('no')"]}),
        context,
        CancellationToken(),
    )
    assert not_absolute.error_code == "SOVA-LOCAL-EXECUTABLE-NOT-ABSOLUTE"

    denied = RestrictedLocalExecutor(
        executable_allowlist=(tmp_path / "not-python",)
    ).execute(
        _request("process.exec", {"argv": [sys.executable, "-c", "print('no')"]}),
        context,
        CancellationToken(),
    )
    assert denied.error_code == "SOVA-LOCAL-EXECUTABLE-DENIED"

    escape = executor.execute(
        _request(
            "process.exec",
            {"argv": [sys.executable, str(tmp_path.parent / "outside.txt")]},
        ),
        context,
        CancellationToken(),
    )
    assert escape.error_code == "SOVA-LOCAL-ARGUMENT-ESCAPE"

    cwd_escape = executor.execute(
        _request(
            "process.exec",
            {"argv": [sys.executable, "-c", "print('no')"], "cwd": ".."},
        ),
        context,
        CancellationToken(),
    )
    assert cwd_escape.error_code == "SOVA-LOCAL-WORKSPACE-ESCAPE"

    missing_cwd = executor.execute(
        _request(
            "process.exec",
            {
                "argv": [sys.executable, "-c", "print('no')"],
                "cwd": "does-not-exist",
            },
        ),
        context,
        CancellationToken(),
    )
    assert missing_cwd.error_code == "SOVA-LOCAL-CWD-MISSING"

    with pytest.raises(FormatError, match="not allowlisted"):
        executor.execute(
            _request(
                "process.exec",
                {
                    "argv": [sys.executable, "-c", "print('no')"],
                    "env": {"API_TOKEN": "do-not-pass"},
                },
            ),
            context,
            CancellationToken(),
        )


def test_local_process_rejects_malformed_inputs_and_limits(
    context: ExecutionContext,
) -> None:
    with pytest.raises(FormatError, match="argv"):
        _local().execute(
            _request("process.exec", {"argv": []}),
            context,
            CancellationToken(),
        )
    with pytest.raises(FormatError, match="relative string"):
        _local().execute(
            _request(
                "process.exec",
                {"argv": [sys.executable, "-c", "print('no')"], "cwd": 1},
            ),
            context,
            CancellationToken(),
        )
    with pytest.raises(FormatError, match="string mapping"):
        _local().execute(
            _request(
                "process.exec",
                {"argv": [sys.executable, "-c", "print('no')"], "env": []},
            ),
            context,
            CancellationToken(),
        )
    for value in (1023, 64 * 1024 * 1024 + 1):
        with pytest.raises(FormatError, match="between"):
            RestrictedLocalExecutor(max_output_bytes=value)
