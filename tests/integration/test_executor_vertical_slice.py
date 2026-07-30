# SPDX-License-Identifier: Apache-2.0
"""No-Atlas capsule-to-trace executor vertical slice."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from sova.capsule import build_capsule, capsule_manifest_template
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
    run_capsule,
)
from sova.formats import sha256_digest, strict_json_loads
from sova.formats.errors import FormatError
from sova.trace import TraceReader

_FIXTURE = b"portable fixture"
_DIGEST = sha256_digest(_FIXTURE)


def _scenario() -> dict[str, Any]:
    document = strict_json_loads(
        (
            Path(__file__).parents[2] / "examples" / "scenarios" / "portable-artifact-read.json"
        ).read_bytes()
    )
    assert isinstance(document, dict)
    return document


def _capsule(tmp_path: Path) -> Path:
    manifest = capsule_manifest_template(
        title="Portable artifact behavior",
        summary="Same safe read reproduced through independent executor backends.",
        author="SOVA tests",
    )
    manifest["license"] = "Apache-2.0"
    manifest["safety"]["impact"] = "none"
    manifest["requiredFeatures"] = ["scenario.core/0.1"]
    path = tmp_path / "portable.sova"
    build_capsule(
        path,
        manifest,
        scenario=_scenario(),
        attachments={"portable.txt": _FIXTURE},
    )
    return path


def _scripted() -> ScriptedExecutor:
    return ScriptedExecutor(
        [
            ScriptedAction(
                action="artifact.read",
                expected_inputs={"digest": _DIGEST, "mediaType": "text/plain"},
                status=OutcomeStatus.SUCCEEDED,
                side_effect=SideEffect.READ,
                output={
                    "digest": _DIGEST,
                    "size": len(_FIXTURE),
                    "mediaType": "text/plain",
                    "text": _FIXTURE.decode(),
                },
                evidence=(("artifact", "text/plain", _FIXTURE),),
                verification="digest-and-size-checked",
            )
        ]
    )


def _outcome(trace_path: Path) -> dict[str, Any]:
    reader = TraceReader(trace_path)
    report = reader.verify()
    assert report.package_integrity
    assert report.event_chain_integrity
    events = list(reader.query(kind_prefix="tool.completed"))
    assert len(events) == 1
    outcome = events[0]["payload"]["outcome"]
    assert isinstance(outcome, dict)
    return outcome


def _assert_oracle_is_identified_observer(trace_path: Path) -> None:
    oracle = next(TraceReader(trace_path).query(kind_prefix="oracle.completed"))
    assert oracle["producer"] == {
        "id": "sova:actor:oracle",
        "kind": "observer",
        "name": "SOVA deterministic oracle",
    }


class _CrashingExecutor:
    name = "synthetic-crashing-executor"

    def capabilities(self) -> tuple[Capability, ...]:
        return (
            Capability(
                name="artifact.read",
                version="0.1",
                side_effect=SideEffect.READ,
                idempotent=True,
                evidence=("artifact-digest",),
            ),
        )

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> Any:
        del request, context, cancellation
        raise RuntimeError("synthetic-sensitive-provider-message")


class _SecretProvider:
    def resolve(self, reference: str) -> str:
        assert reference == "sova-secret:integration-fixture"
        return "integration-private-value"


def test_same_capsule_reproduces_same_observation_on_two_backends(
    tmp_path: Path,
) -> None:
    capsule = _capsule(tmp_path)
    authorization = {
        "decision": "allowed",
        "scopeDigest": "sha256:" + ("0" * 64),
        "decidedBy": "test-fixture",
    }
    scripted_path = tmp_path / "scripted.sova-trace"
    local_path = tmp_path / "local.sova-trace"
    scripted = _scripted()

    scripted_result = run_capsule(
        capsule,
        scripted_path,
        executor=scripted,
        workspace=tmp_path,
        authorization=authorization,
    )
    local_result = run_capsule(
        capsule,
        local_path,
        executor=RestrictedLocalExecutor(),
        workspace=tmp_path,
        authorization=authorization,
    )

    assert scripted_result.completion == local_result.completion == "completed"
    assert scripted_result.steps_attempted == local_result.steps_attempted == 1
    assert scripted_result.steps_succeeded == local_result.steps_succeeded == 1
    assert scripted.complete
    scripted_outcome = _outcome(scripted_path)
    local_outcome = _outcome(local_path)
    assert scripted_outcome["status"] == local_outcome["status"] == "succeeded"
    assert scripted_outcome["output"] == local_outcome["output"]
    assert scripted_outcome["verification"] == local_outcome["verification"]
    assert (
        scripted_outcome["evidence"][0]["digest"]
        == local_outcome["evidence"][0]["digest"]
        == _DIGEST
    )
    _assert_oracle_is_identified_observer(scripted_path)
    _assert_oracle_is_identified_observer(local_path)
    assert TraceReader(scripted_path).playback()
    assert TraceReader(local_path).playback()


def test_runner_blocks_unsupported_capability_and_denied_authorization(
    tmp_path: Path,
) -> None:
    capsule = _capsule(tmp_path)
    authorization = {
        "decision": "allowed",
        "scopeDigest": "sha256:" + ("0" * 64),
        "decidedBy": "test-fixture",
    }
    unsupported_path = tmp_path / "unsupported.sova-trace"
    result = run_capsule(
        capsule,
        unsupported_path,
        executor=ScriptedExecutor([], advertised=()),
        workspace=tmp_path,
        authorization=authorization,
    )
    assert result.completion == "failed"
    assert result.steps_attempted == 0
    assert TraceReader(unsupported_path).verify().completion == "failed"
    assert list(TraceReader(unsupported_path).query(kind_prefix="blocked.unsupported-capability"))

    with pytest.raises(FormatError, match="fresh allowed"):
        run_capsule(
            capsule,
            tmp_path / "denied.sova-trace",
            executor=_scripted(),
            workspace=tmp_path,
            authorization={"decision": "denied"},
        )


def test_executor_output_is_redacted_by_trace_layer_not_adapter(
    tmp_path: Path,
) -> None:
    capsule = _capsule(tmp_path)
    trace_path = tmp_path / "redacted.sova-trace"
    executor = ScriptedExecutor(
        [
            ScriptedAction(
                action="artifact.read",
                expected_inputs={"digest": _DIGEST, "mediaType": "text/plain"},
                status=OutcomeStatus.SUCCEEDED,
                side_effect=SideEffect.READ,
                output={
                    "digest": _DIGEST,
                    "size": len(_FIXTURE),
                    "mediaType": "text/plain",
                    "password": "synthetic-must-not-persist",
                },
            )
        ]
    )
    run_capsule(
        capsule,
        trace_path,
        executor=executor,
        workspace=tmp_path,
        authorization={
            "decision": "allowed",
            "scopeDigest": "sha256:" + ("0" * 64),
            "decidedBy": "test-fixture",
        },
    )
    assert b"synthetic-must-not-persist" not in trace_path.read_bytes()
    event = next(TraceReader(trace_path).query(kind_prefix="tool.completed"))
    placeholder = event["payload"]["outcome"]["output"]["password"]["$redacted"]
    assert placeholder["class"] == "credential"
    assert placeholder["method"] == "omitted"


def test_runner_enforces_expanded_step_budget_before_execution(
    tmp_path: Path,
) -> None:
    scenario = _scenario()
    scenario["procedure"]["steps"].append(
        {
            "id": "read-fixture-again",
            "action": "artifact.read",
            "inputs": {"digest": _DIGEST, "mediaType": "text/plain"},
            "onFailure": "stop",
            "requires": ["artifact.read/0.1"],
        }
    )
    manifest = capsule_manifest_template(
        title="Over-budget fixture",
        summary="Runner must block before the first action.",
        author="SOVA tests",
    )
    capsule = tmp_path / "over-budget.sova"
    build_capsule(
        capsule,
        manifest,
        scenario=scenario,
        attachments={"portable.txt": _FIXTURE},
    )
    trace_path = tmp_path / "over-budget.sova-trace"
    executor = _scripted()
    result = run_capsule(
        capsule,
        trace_path,
        executor=executor,
        workspace=tmp_path,
        authorization={
            "decision": "allowed",
            "scopeDigest": "sha256:" + ("0" * 64),
            "decidedBy": "test-fixture",
        },
    )
    assert result.completion == "failed"
    assert result.steps_attempted == 0
    assert not executor.complete
    assert list(TraceReader(trace_path).query(kind_prefix="blocked.execution-budget"))


def test_runner_rejects_invalid_step_budget_before_trace_creation(
    tmp_path: Path,
) -> None:
    scenario = _scenario()
    scenario["safety"]["budgets"]["maxSteps"] = 0
    manifest = capsule_manifest_template(
        title="Invalid budget fixture",
        summary="Invalid safety budget must fail closed.",
        author="SOVA tests",
    )
    capsule = tmp_path / "invalid-budget.sova"
    build_capsule(
        capsule,
        manifest,
        scenario=scenario,
        attachments={"portable.txt": _FIXTURE},
    )
    destination = tmp_path / "invalid-budget.sova-trace"
    with pytest.raises(FormatError, match="positive integer"):
        run_capsule(
            capsule,
            destination,
            executor=_scripted(),
            workspace=tmp_path,
            authorization={
                "decision": "allowed",
                "scopeDigest": "sha256:" + ("0" * 64),
                "decidedBy": "test-fixture",
            },
        )
    assert not destination.exists()


def test_runner_records_provider_exception_as_crash_without_message(
    tmp_path: Path,
) -> None:
    trace = tmp_path / "provider-crash.sova-trace"
    result = run_capsule(
        _capsule(tmp_path),
        trace,
        executor=_CrashingExecutor(),
        workspace=tmp_path,
        authorization={
            "decision": "allowed",
            "scopeDigest": "sha256:" + ("0" * 64),
            "decidedBy": "test-fixture",
        },
    )

    assert result.completion == "crashed"
    report = TraceReader(trace).verify()
    assert report.completion == "crashed"
    failed = next(TraceReader(trace).query(kind_prefix="tool.failed"))
    assert failed["payload"]["outcome"]["error_code"] == "SOVA-EXECUTOR-EXCEPTION"
    assert failed["payload"]["outcome"]["output"]["exceptionType"] == "RuntimeError"
    assert failed["payload"]["outcome"]["failure_cause"] == "executor"
    assert b"synthetic-sensitive-provider-message" not in trace.read_bytes()


def test_runner_never_persists_resolved_secret_value(tmp_path: Path) -> None:
    scenario = _scenario()
    scenario["procedure"]["steps"] = [
        {
            "id": "secret-length",
            "action": "process.exec",
            "inputs": {
                "argv": [
                    str(Path(sys.executable).resolve()),
                    "-c",
                    "import os; print(len(os.environ['SOVA_TEST_SECRET']))",
                ],
                "secretEnv": {"SOVA_TEST_SECRET": "sova-secret:integration-fixture"},
            },
            "onFailure": "stop",
            "requires": ["process.exec/0.1"],
        }
    ]
    scenario["oracles"] = [
        {
            "kind": "field-contains",
            "path": "$.stdout",
            "contains": str(len("integration-private-value")),
        }
    ]
    manifest = capsule_manifest_template(
        title="Opaque secret fixture",
        summary="A secret-reference persistence boundary test.",
        author="SOVA tests",
    )
    manifest["license"] = "Apache-2.0"
    manifest["safety"]["impact"] = "none"
    manifest["requiredFeatures"] = ["scenario.core/0.1"]
    capsule = tmp_path / "secret.sova"
    build_capsule(capsule, manifest, scenario=scenario)
    trace = tmp_path / "secret.sova-trace"
    executable = Path(sys.executable).resolve()
    with RestrictedLocalExecutor(
        executable_allowlist=(executable,),
        environment_allowlist=frozenset({"SOVA_TEST_SECRET"}),
    ) as executor:
        result = run_capsule(
            capsule,
            trace,
            executor=executor,
            workspace=tmp_path,
            authorization={
                "decision": "allowed",
                "scopeDigest": "sha256:" + ("0" * 64),
                "decidedBy": "test-fixture",
            },
            secret_provider=_SecretProvider(),
        )
    assert result.completion == "completed"
    assert b"integration-private-value" not in capsule.read_bytes()
    assert b"integration-private-value" not in trace.read_bytes()
    assert TraceReader(trace).verify().event_chain_integrity


@pytest.mark.parametrize(
    ("status", "completion"),
    [
        (OutcomeStatus.FAILED, "failed"),
        (OutcomeStatus.TIMEOUT, "timeout"),
        (OutcomeStatus.CANCELLED, "cancelled"),
    ],
)
def test_runner_preserves_failure_state_when_later_step_continues(
    tmp_path: Path,
    status: OutcomeStatus,
    completion: str,
) -> None:
    scenario = _scenario()
    original = scenario["procedure"]["steps"][0]
    first = {**original, "id": "first", "onFailure": "continue"}
    second = {**original, "id": "second", "onFailure": "stop"}
    scenario["procedure"]["steps"] = [first, second]
    scenario["safety"]["budgets"]["maxSteps"] = 2
    manifest = capsule_manifest_template(
        title="Continuation fixture",
        summary="Normalized terminal-state continuation test.",
        author="SOVA tests",
    )
    manifest["license"] = "Apache-2.0"
    manifest["safety"]["impact"] = "none"
    manifest["requiredFeatures"] = ["scenario.core/0.1"]
    capsule = tmp_path / f"{completion}.sova"
    build_capsule(
        capsule,
        manifest,
        scenario=scenario,
        attachments={"portable.txt": _FIXTURE},
    )
    executor = ScriptedExecutor(
        [
            ScriptedAction(
                action="artifact.read",
                expected_inputs=first["inputs"],
                status=status,
                output={},
                side_effect=SideEffect.READ,
                error_code=f"SYNTHETIC-{status.value.upper()}",
            ),
            ScriptedAction(
                action="artifact.read",
                expected_inputs=second["inputs"],
                status=OutcomeStatus.SUCCEEDED,
                side_effect=SideEffect.READ,
                output={
                    "digest": _DIGEST,
                    "size": len(_FIXTURE),
                    "mediaType": "text/plain",
                    "text": _FIXTURE.decode(),
                },
            ),
        ]
    )
    trace = tmp_path / f"{completion}.sova-trace"
    result = run_capsule(
        capsule,
        trace,
        executor=executor,
        workspace=tmp_path,
        authorization={
            "decision": "allowed",
            "scopeDigest": "sha256:" + ("0" * 64),
            "decidedBy": "test-fixture",
        },
    )
    assert result.completion == completion
    assert result.steps_attempted == 2
    assert result.steps_succeeded == 1
    assert TraceReader(trace).verify().completion == completion


def test_runner_refuses_capsule_without_scenario(tmp_path: Path) -> None:
    capsule = tmp_path / "no-scenario.sova"
    build_capsule(
        capsule,
        capsule_manifest_template(
            title="No scenario",
            summary="No executable object.",
            author="SOVA tests",
        ),
    )
    with pytest.raises(FormatError) as error:
        run_capsule(
            capsule,
            tmp_path / "must-not-exist.sova-trace",
            executor=ScriptedExecutor([]),
            workspace=tmp_path,
            authorization={"decision": "allowed"},
        )
    assert error.value.issue.code == "SOVA-RUN-NO-SCENARIO"
