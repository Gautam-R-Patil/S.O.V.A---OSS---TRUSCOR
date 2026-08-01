# SPDX-License-Identifier: Apache-2.0
"""Executor contract and restricted-local conformance tests."""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from typing import Any, cast

import pytest

from sova.executors import (
    ActionOutcome,
    ActionRequest,
    CancellationToken,
    Capability,
    ExecutionContext,
    FailureCause,
    OutcomeStatus,
    RestrictedLocalExecutor,
    ScriptedAction,
    ScriptedExecutor,
    SideEffect,
    negotiate,
)
from sova.executors.local import _cleanup_temporary
from sova.executors.runner import _expanded_steps
from sova.formats import sha256_digest
from sova.formats.errors import FormatError


class _SecretProvider:
    def __init__(self, value: str) -> None:
        self.value = value
        self.references: list[str] = []

    def resolve(self, reference: str) -> str:
        self.references.append(reference)
        return self.value


class _RaisingSecretProvider:
    def resolve(self, reference: str) -> str:
        del reference
        raise RuntimeError


class _NonStringSecretProvider:
    def resolve(self, reference: str) -> str:
        del reference
        return cast("str", 42)


class _FlakyCleanup:
    def __init__(self, failures: int) -> None:
        self.failures = failures
        self.attempts = 0

    def cleanup(self) -> None:
        self.attempts += 1
        if self.attempts <= self.failures:
            raise PermissionError


def test_background_cleanup_retries_transient_windows_handle_race() -> None:
    resource = _FlakyCleanup(2)
    _cleanup_temporary(resource, attempts=3, retry_seconds=0)
    assert resource.attempts == 3


def test_background_cleanup_preserves_persistent_failure() -> None:
    resource = _FlakyCleanup(3)
    with pytest.raises(PermissionError):
        _cleanup_temporary(resource, attempts=3, retry_seconds=0)
    assert resource.attempts == 3


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

    denied = RestrictedLocalExecutor(executable_allowlist=(tmp_path / "not-python",)).execute(
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


def test_local_process_resolves_only_opaque_ephemeral_secret_references(
    tmp_path: Path,
) -> None:
    provider = _SecretProvider("private-value")
    context = ExecutionContext(
        workspace=tmp_path,
        authorization={"decision": "allowed"},
        secret_provider=provider,
    )
    executor = RestrictedLocalExecutor(
        executable_allowlist=(Path(sys.executable),),
        environment_allowlist=frozenset({"SOVA_TEST_SECRET"}),
    )
    outcome = executor.execute(
        _request(
            "process.exec",
            {
                "argv": [
                    sys.executable,
                    "-c",
                    "import os; print(len(os.environ['SOVA_TEST_SECRET']))",
                ],
                "secretEnv": {"SOVA_TEST_SECRET": "sova-secret:opaque-test-reference"},
            },
        ),
        context,
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.SUCCEEDED
    assert outcome.output["stdout"].strip() == str(len(provider.value))
    assert provider.value not in repr(outcome)
    assert provider.references == ["sova-secret:opaque-test-reference"]

    denied = executor.execute(
        _request(
            "process.exec",
            {
                "argv": [sys.executable, "-c", "print('not-started')"],
                "secretEnv": {"SOVA_TEST_SECRET": "sova-secret:missing-provider"},
            },
        ),
        ExecutionContext(tmp_path, {"decision": "allowed"}),
        CancellationToken(),
    )
    assert denied.status == OutcomeStatus.DENIED
    assert denied.error_code == "SOVA-LOCAL-SECRET-PROVIDER"

    malformed = executor.execute(
        _request(
            "process.exec",
            {
                "argv": [sys.executable, "-c", "print('not-started')"],
                "secretEnv": {"SOVA_TEST_SECRET": "plaintext-secret"},
            },
        ),
        context,
        CancellationToken(),
    )
    assert malformed.status == OutcomeStatus.DENIED
    assert malformed.error_code == "SOVA-LOCAL-SECRET-REFERENCE"


@pytest.mark.parametrize(
    ("provider", "expected_code"),
    [
        (_RaisingSecretProvider(), "SOVA-LOCAL-SECRET-RESOLUTION"),
        (_NonStringSecretProvider(), "SOVA-LOCAL-SECRET-RESOLUTION"),
    ],
)
def test_local_secret_provider_failures_are_normalized_without_details(
    tmp_path: Path,
    provider: object,
    expected_code: str,
) -> None:
    executor = RestrictedLocalExecutor(
        executable_allowlist=(Path(sys.executable),),
        environment_allowlist=frozenset({"SOVA_TEST_SECRET"}),
    )
    context = ExecutionContext(
        tmp_path,
        {"decision": "allowed"},
        secret_provider=cast("Any", provider),
    )
    outcome = executor.execute(
        _request(
            "process.exec",
            {
                "argv": [sys.executable, "-c", "print('not-started')"],
                "secretEnv": {"SOVA_TEST_SECRET": "sova-secret:failure-fixture"},
            },
        ),
        context,
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.DENIED
    assert outcome.error_code == expected_code
    assert "RuntimeError" not in repr(outcome)


def test_local_secret_reference_conflict_and_nonallowlisted_key_fail(
    tmp_path: Path,
) -> None:
    executor = RestrictedLocalExecutor(
        executable_allowlist=(Path(sys.executable),),
        environment_allowlist=frozenset({"APP_MODE"}),
    )
    context = ExecutionContext(
        tmp_path,
        {"decision": "allowed"},
        secret_provider=_SecretProvider("value"),
    )
    conflict = executor.execute(
        _request(
            "process.exec",
            {
                "argv": [sys.executable, "-c", "print('not-started')"],
                "env": {"APP_MODE": "plain"},
                "secretEnv": {"APP_MODE": "sova-secret:conflict"},
            },
        ),
        context,
        CancellationToken(),
    )
    assert conflict.error_code == "SOVA-LOCAL-SECRET-CONFLICT"

    with pytest.raises(FormatError) as denied:
        executor.execute(
            _request(
                "process.exec",
                {
                    "argv": [sys.executable, "-c", "print('not-started')"],
                    "secretEnv": {"NOT_ALLOWED": "sova-secret:denied"},
                },
            ),
            context,
            CancellationToken(),
        )
    assert denied.value.issue.code == "SOVA-LOCAL-ENVIRONMENT-DENIED"


@pytest.mark.parametrize(
    "resources",
    [
        [],
        {"unknown": 1},
        {"maxCpuSeconds": True},
        {"maxOutputBytes": True},
    ],
)
def test_local_process_rejects_malformed_resource_objects(
    context: ExecutionContext,
    resources: object,
) -> None:
    with pytest.raises(FormatError) as error:
        _local().execute(
            _request(
                "process.exec",
                {
                    "argv": [sys.executable, "-c", "print('not-started')"],
                    "resources": resources,
                },
            ),
            context,
            CancellationToken(),
        )
    assert error.value.issue.code == "SOVA-LOCAL-RESOURCE-LIMIT"


@pytest.mark.parametrize(
    ("resource", "value"),
    [
        ("maxCpuSeconds", 1),
        ("maxMemoryBytes", 16 * 1024 * 1024),
        ("maxProcesses", 1),
    ],
)
def test_local_process_rejects_unenforceable_resource_limits_before_start(
    context: ExecutionContext,
    resource: str,
    value: int,
) -> None:
    marker = context.workspace / f"should-not-exist-{resource}"
    outcome = _local().execute(
        _request(
            "process.exec",
            {
                "argv": [
                    sys.executable,
                    "-c",
                    (
                        "from pathlib import Path; "
                        f"Path('should-not-exist-{resource}').write_text('bad')"
                    ),
                ],
                "resources": {resource: value},
            },
        ),
        context,
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.UNSUPPORTED
    assert outcome.error_code == "SOVA-LOCAL-RESOURCE-LIMIT-UNSUPPORTED"
    assert "rejected before process creation" in outcome.limitations[1]
    assert not marker.exists()


def test_supervised_background_process_lifecycle_and_cleanup(
    context: ExecutionContext,
) -> None:
    executor = _local()
    capabilities = {capability.identifier for capability in executor.capabilities()}
    assert {
        "process.spawn/0.1",
        "process.status/0.1",
        "process.stop/0.1",
    } <= capabilities
    spawned = executor.execute(
        _request(
            "process.spawn",
            {
                "argv": [
                    sys.executable,
                    "-c",
                    "import time; print('ready', flush=True); time.sleep(30)",
                ]
            },
            timeout=5,
        ),
        context,
        CancellationToken(),
    )
    assert spawned.status == OutcomeStatus.SUCCEEDED
    handle = spawned.output["handle"]
    status = executor.execute(
        _request("process.status", {"handle": handle}),
        context,
        CancellationToken(),
    )
    assert status.status == OutcomeStatus.SUCCEEDED
    assert status.output["state"] in {"running", "terminal"}
    stopped = executor.execute(
        _request("process.stop", {"handle": handle}),
        context,
        CancellationToken(),
    )
    assert stopped.status == OutcomeStatus.SUCCEEDED
    assert stopped.output["state"] == "terminal"
    assert stopped.output["childStatus"] in {"cancelled", "succeeded"}
    missing = executor.execute(
        _request("process.status", {"handle": handle}),
        context,
        CancellationToken(),
    )
    assert missing.error_code == "SOVA-LOCAL-PROCESS-HANDLE-MISSING"
    executor.close()
    closed = executor.execute(
        _request("artifact.read", {"digest": next(iter(context.artifacts))}),
        context,
        CancellationToken(),
    )
    assert closed.error_code == "SOVA-LOCAL-CLOSED"


def test_supervisor_enforces_background_timeout(
    context: ExecutionContext,
) -> None:
    with _local() as executor:
        spawned = executor.execute(
            _request(
                "process.spawn",
                {"argv": [sys.executable, "-c", "import time; time.sleep(30)"]},
                timeout=0.05,
            ),
            context,
            CancellationToken(),
        )
        handle = spawned.output["handle"]
        deadline = time.monotonic() + 5
        child_status = None
        while time.monotonic() < deadline:
            status = executor.execute(
                _request("process.status", {"handle": handle}),
                context,
                CancellationToken(),
            )
            child_status = status.output.get("childStatus")
            if child_status is not None:
                break
            time.sleep(0.01)
        assert child_status == "timeout"
        collected = executor.execute(
            _request("process.stop", {"handle": handle}),
            context,
            CancellationToken(),
        )
        assert collected.output["childStatus"] == "timeout"


def test_supervisor_enforces_background_cancellation(
    context: ExecutionContext,
) -> None:
    token = CancellationToken()
    with _local() as executor:
        spawned = executor.execute(
            _request(
                "process.spawn",
                {"argv": [sys.executable, "-c", "import time; time.sleep(30)"]},
                timeout=5,
            ),
            context,
            token,
        )
        handle = spawned.output["handle"]
        token.cancel()
        cancelled_at = time.monotonic()
        deadline = cancelled_at + 5
        child_status = None
        while time.monotonic() < deadline:
            status = executor.execute(
                _request("process.status", {"handle": handle}),
                context,
                CancellationToken(),
            )
            child_status = status.output.get("childStatus")
            if child_status is not None:
                break
            time.sleep(0.01)
        assert child_status == "cancelled"
        assert time.monotonic() - cancelled_at < 5
        collected = executor.execute(
            _request("process.stop", {"handle": handle}),
            context,
            CancellationToken(),
        )
        assert collected.output["childStatus"] == "cancelled"


def test_reusable_sequence_expansion_and_fail_closed_cycles() -> None:
    nested = {
        "sequences": [
            {
                "id": "inner",
                "steps": [
                    {
                        "id": "read",
                        "action": "artifact.read",
                        "inputs": {},
                    }
                ],
            },
            {
                "id": "outer",
                "steps": [
                    {
                        "id": "call-inner",
                        "action": "sova.sequence.call",
                        "inputs": {"sequence": "inner"},
                    }
                ],
            },
        ],
        "procedure": {
            "steps": [
                {
                    "id": "call-outer",
                    "action": "sova.sequence.call",
                    "inputs": {"sequence": "outer"},
                }
            ]
        },
    }
    assert [step["id"] for step in _expanded_steps(nested)] == ["read"]

    missing = {
        "sequences": [],
        "procedure": {
            "steps": [
                {
                    "id": "missing",
                    "action": "sova.sequence.call",
                    "inputs": {"sequence": "absent"},
                }
            ]
        },
    }
    with pytest.raises(FormatError) as unknown:
        _expanded_steps(missing)
    assert unknown.value.issue.code == "SOVA-RUN-SEQUENCE"

    cycle = {
        "sequences": [
            {
                "id": "loop",
                "steps": [
                    {
                        "id": "again",
                        "action": "sova.sequence.call",
                        "inputs": {"sequence": "loop"},
                    }
                ],
            }
        ],
        "procedure": {
            "steps": [
                {
                    "id": "start",
                    "action": "sova.sequence.call",
                    "inputs": {"sequence": "loop"},
                }
            ]
        },
    }
    with pytest.raises(FormatError) as recursive:
        _expanded_steps(cycle)
    assert recursive.value.issue.code == "SOVA-RUN-SEQUENCE-CYCLE"


@pytest.mark.parametrize(
    ("status", "cause"),
    [
        (OutcomeStatus.SUCCEEDED, FailureCause.NONE),
        (OutcomeStatus.FAILED, FailureCause.UNKNOWN),
        (OutcomeStatus.TIMEOUT, FailureCause.TIMEOUT),
        (OutcomeStatus.CANCELLED, FailureCause.CANCELLATION),
        (OutcomeStatus.DENIED, FailureCause.POLICY),
        (OutcomeStatus.UNSUPPORTED, FailureCause.UNSUPPORTED),
        (OutcomeStatus.PARTIAL, FailureCause.EVIDENCE),
    ],
)
def test_outcome_failure_cause_is_explicit_and_conservative(
    status: OutcomeStatus,
    cause: FailureCause,
) -> None:
    outcome = ActionOutcome("request", status, SideEffect.READ, {})
    assert outcome.failure_cause == cause

    if status == OutcomeStatus.SUCCEEDED:
        with pytest.raises(FormatError) as error:
            ActionOutcome(
                "request",
                status,
                SideEffect.READ,
                {},
                failure_cause=FailureCause.EXECUTOR,
            )
        assert error.value.issue.code == "SOVA-EXECUTOR-FAILURE-CAUSE"
