# SPDX-License-Identifier: Apache-2.0
"""Strict container-local codec and attested gVisor surface tests."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, cast

import pytest

from sova.community.executor_chamber import ChamberObservation
from sova.community.executor_surfaces import (
    ExactOciProcessSurfaceSpec,
    gvisor_process_surface_generation,
    oci_process_codec_factory,
)
from sova.executors import (
    CancellationToken,
    DockerCommandResult,
    ExecutionContext,
    GVisorOciExecutor,
    OutcomeStatus,
)
from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError
from sova.runtime.action_codecs import OciProcessActionCodec
from sova.runtime.environment_builder import capability_contract_digest
from sova.runtime.managed_surfaces import PolicyEvidenceVerifier
from sova.runtime.target_environment import (
    BackendGeneration,
    CapabilityGeneration,
    SessionEnvelope,
    TargetInstance,
)
from sova.runtime.unified_execution import CapabilityBinding, ObservationVersion

if TYPE_CHECKING:
    from pathlib import Path

    from sova.community.executor_engine import EngineSurfaceGeneration

IMAGE = "example.invalid/sova/oci-fixture@sha256:" + "d" * 64


def _digest(label: str) -> str:
    return sha256_digest(label.encode())


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
        _completed(json.dumps({"runsc": {"path": "/usr/local/bin/runsc"}}).encode()),
        _completed(json.dumps("29.4.2").encode()),
        _completed(json.dumps([IMAGE]).encode()),
    ]


def _docker(tmp_path: Path) -> Path:
    executable = tmp_path / "docker"
    executable.write_bytes(b"fixture")
    return executable


def _target_and_session(
    surface: EngineSurfaceGeneration,
) -> tuple[TargetInstance, SessionEnvelope]:
    target = TargetInstance(
        instance_id="target:gvisor-oci-fixture",
        target_manifest_digest=_digest("manifest"),
        environment_digest=_digest("environment"),
        containment_digest=_digest("gvisor-containment"),
        generation=1,
        clock_domain="clock:gvisor-fixture",
    )
    backend = BackendGeneration(
        backend_id=surface.backend.backend_id,
        generation=surface.backend.generation,
        target_instance_digest=target.digest,
        environment_digest=target.environment_digest,
        capabilities=tuple(
            CapabilityGeneration(
                capability.identifier,
                surface.backend.capability_generation,
                capability_contract_digest(capability),
            )
            for capability in surface.backend.executor.capabilities()
        ),
    )
    session = SessionEnvelope(
        session_id="session:gvisor-oci-fixture",
        run_id="run:gvisor-oci-fixture",
        generation=1,
        target_instance_digest=target.digest,
        environment_digest=target.environment_digest,
        containment_digest=target.containment_digest,
        identity_digest=_digest("identity"),
        clock_domain=target.clock_domain,
        backend_generations=(backend,),
        affinity_resources=tuple(
            sorted({"target:gvisor-oci-fixture", *surface.backend.affinity_resources})
        ),
    )
    return target, session


def _binding(
    surface: EngineSurfaceGeneration,
    session: SessionEnvelope,
    target: TargetInstance,
) -> CapabilityBinding:
    capability = surface.backend.executor.capabilities()[0]
    backend = session.backend(surface.backend.backend_id)
    generation = backend.capability(capability.identifier)
    return CapabilityBinding(
        binding_id="binding:gvisor-oci-process",
        backend_id=backend.backend_id,
        backend_generation=backend.generation,
        backend_generation_digest=backend.digest,
        capability_name=capability.name,
        capability_version=capability.version,
        capability_generation=generation.generation,
        capability_contract_digest=generation.contract_digest,
        session_digest=session.digest,
        target_instance_digest=target.digest,
        environment_digest=target.environment_digest,
        side_effect=capability.side_effect,
        idempotent=capability.idempotent,
        expected_evidence=tuple(sorted(capability.evidence)),
        verifier_id=surface.backend.verifier_id,
        affinity_resources=tuple(
            sorted({"target:gvisor-oci-fixture", *surface.backend.affinity_resources})
        ),
        effect_resources=surface.backend.effect_resources[capability.name],
    )


def test_oci_codec_builds_exact_shell_free_argv_and_optional_bounded_stdin() -> None:
    codec = OciProcessActionCodec(
        "/opt/sova/agent",
        ("scan", "--config=/etc/sova/config.json"),
    )
    request = codec.decode(
        {
            "action": "process.exec",
            "arguments": {
                "args": [
                    "--input",
                    "/var/lib/sova/case.json",
                    "literal;$(not-a-shell)",
                ],
                "stdin": '{"case":"bounded"}',
            },
        },
        request_id="oci-safe",
        timeout_seconds=10,
    )
    assert codec.codec_id == "sova.action-codec.oci-process/0.1.0"
    assert request.inputs == {
        "argv": [
            "/opt/sova/agent",
            "scan",
            "--config=/etc/sova/config.json",
            "--input",
            "/var/lib/sova/case.json",
            "literal;$(not-a-shell)",
        ],
        "stdin": '{"case":"bounded"}',
    }
    no_stdin = codec.decode(
        {"action": "process.exec", "arguments": {"args": []}},
        request_id="oci-no-stdin",
        timeout_seconds=1,
    )
    assert "stdin" not in no_stdin.inputs


@pytest.mark.parametrize(
    ("executable", "prefix"),
    [
        ("relative/tool", ()),
        ("/bin/sh", ()),
        ("//bin/tool", ()),
        ("/bin/../tool", ()),
        (r"/bin\tool", ()),
        ("/root/.ssh/tool", ()),
        ("/opt/sova/tool", ("relative/path",)),
        ("/opt/sova/tool", ("--config=relative/path",)),
    ],
)
def test_oci_codec_rejects_non_posix_shell_sensitive_and_relative_templates(
    executable: str,
    prefix: tuple[str, ...],
) -> None:
    with pytest.raises(FormatError):
        OciProcessActionCodec(executable, prefix)


@pytest.mark.parametrize(
    "document",
    [
        {"action": "process.exec", "arguments": {"args": "--help"}},
        {"action": "process.exec", "arguments": {"args": [], "cwd": "/var/empty"}},
        {"action": "process.exec", "arguments": {"args": [], "env": {}}},
        {"action": "process.exec", "arguments": {"args": ["../escape"]}},
        {"action": "process.exec", "arguments": {"args": ["relative/path"]}},
        {"action": "process.exec", "arguments": {"args": [r"C:\host"]}},
        {"action": "process.exec", "arguments": {"args": ["/root/.ssh/id_rsa"]}},
        {"action": "process.exec", "arguments": {"args": ["bad\x00arg"]}},
        {"action": "filesystem.read", "arguments": {"args": []}},
        {"action": "process.exec", "arguments": {"args": []}, "extra": True},
    ],
)
def test_oci_codec_rejects_hostile_or_ambient_model_authority(
    document: dict[str, Any],
) -> None:
    codec = OciProcessActionCodec("/opt/sova/agent")
    with pytest.raises(FormatError):
        codec.decode(document, request_id="hostile", timeout_seconds=1)


def test_oci_codec_rejects_substitution_secrets_and_all_encoded_limits() -> None:
    with pytest.raises(FormatError, match=r"immutable|invalid"):
        OciProcessActionCodec(
            "/opt/sova/agent",
            cast("Any", ["scan"]),
        )
    count_limited = OciProcessActionCodec("/opt/sova/agent", max_args=2)
    with pytest.raises(FormatError, match="count or encoded byte limit"):
        count_limited.decode(
            {"action": "process.exec", "arguments": {"args": ["one", "two"]}},
            request_id="too-many",
            timeout_seconds=1,
        )
    bytes_limited = OciProcessActionCodec("/x", max_arg_bytes=4)
    with pytest.raises(FormatError, match="count or encoded byte limit"):
        bytes_limited.decode(
            {"action": "process.exec", "arguments": {"args": ["long"]}},
            request_id="too-large",
            timeout_seconds=1,
        )
    stdin_limited = OciProcessActionCodec("/opt/sova/agent", max_stdin_bytes=4)
    with pytest.raises(FormatError, match="stdin exceeds"):
        stdin_limited.decode(
            {
                "action": "process.exec",
                "arguments": {"args": [], "stdin": "12345"},
            },
            request_id="stdin-limit",
            timeout_seconds=1,
        )
    with pytest.raises(FormatError, match="secret"):
        OciProcessActionCodec("/opt/sova/agent").decode(
            {
                "action": "process.exec",
                "arguments": {
                    "args": [],
                    "stdin": "Bearer synthetic-credential-value",
                },
            },
            request_id="secret-stdin",
            timeout_seconds=1,
        )


def test_gvisor_surface_binds_exact_contract_and_rejects_unready_or_substituted(
    tmp_path: Path,
) -> None:
    spec = ExactOciProcessSurfaceSpec("agent", "/opt/sova/agent", ("scan",))
    ready = GVisorOciExecutor(
        _docker(tmp_path),
        IMAGE,
        runner=_Runner(_attestation_results()),
    )
    surface = gvisor_process_surface_generation(spec, ready)
    contract = surface.contract_mapping()
    resources = set(contract["affinityResources"])
    assert f"oci-attestation:{ready.attestation.digest}" in resources
    assert f"oci-image-binding:{sha256_digest(IMAGE.encode())}" in resources
    assert "oci-runtime:runsc" in resources
    assert {"oci-network:none", "oci-host-mounts:none", "oci-rootfs:read-only"} <= resources
    assert contract["executorName"].endswith(ready.attestation.digest)
    with pytest.raises(FormatError, match="not an open session-bound"):
        surface.observe()

    target, session = _target_and_session(surface)
    surface.bind(session, target, tmp_path)
    observed = surface.observe()
    assert observed == {
        "attestationDigest": ready.attestation.digest,
        "engineServerVersion": "29.4.2",
        "executed": False,
        "hostWorkspaceMounted": False,
        "image": IMAGE,
        "networkMode": "none",
        "rootFilesystemReadOnly": True,
        "runtime": "runsc",
        "sessionDigest": session.digest,
        "targetInstanceDigest": target.digest,
        "templateId": "agent",
    }
    with pytest.raises(FormatError, match="closed or already bound"):
        surface.bind(session, target, tmp_path)
    surface.close()
    with pytest.raises(FormatError, match="not an open session-bound"):
        surface.observe()

    unavailable = GVisorOciExecutor(
        _docker(tmp_path),
        IMAGE,
        runner=_Runner([_completed(code=1), _completed(code=1), _completed(code=1)]),
    )
    with pytest.raises(FormatError, match="already-ready"):
        gvisor_process_surface_generation(spec, unavailable)
    with pytest.raises(FormatError, match="exact already-ready"):
        gvisor_process_surface_generation(spec, cast("Any", object()))


def test_gvisor_surface_executes_with_no_network_or_mount_and_verifies_policy(
    tmp_path: Path,
) -> None:
    runner = _Runner(
        [
            *_attestation_results(),
            _completed(b"verified\n"),
            _completed(code=1),
            _completed(),
        ]
    )
    executor = GVisorOciExecutor(_docker(tmp_path), IMAGE, runner=runner)
    spec = ExactOciProcessSurfaceSpec("agent", "/opt/sova/agent", ("scan",))
    surface = gvisor_process_surface_generation(spec, executor)
    target, session = _target_and_session(surface)
    surface.bind(session, target, tmp_path)
    before = ChamberObservation.capture(
        session,
        target,
        0,
        {surface.sensor_name: surface.observe()},
    )
    codec = oci_process_codec_factory(spec, executor)(before)
    request = codec.decode(
        {
            "action": "process.exec",
            "arguments": {
                "args": ["--case", "/var/lib/sova/case.json"],
                "stdin": "fixture",
            },
        },
        request_id="attested-run",
        timeout_seconds=10,
    )
    outcome = surface.backend.executor.execute(
        request,
        ExecutionContext(tmp_path, {"decision": "allowed"}),
        CancellationToken(),
    )
    after = ChamberObservation.capture(
        session,
        target,
        1,
        {surface.sensor_name: surface.observe()},
    )
    verification = PolicyEvidenceVerifier(surface.evidence_policies)(
        request,
        outcome,
        _binding(surface, session, target),
        before,
        after,
    )
    assert outcome.status == OutcomeStatus.SUCCEEDED
    assert verification.verified
    assert verification.satisfied_evidence == (
        "gvisor-attestation",
        "returncode",
        "stderr",
        "stdout",
    )
    assert after.projection[surface.sensor_name]["image"] == IMAGE
    assert after.projection[surface.sensor_name]["attestationDigest"] == (
        executor.attestation.digest
    )
    command = runner.calls[3]
    assert command[command.index("--runtime") + 1] == "runsc"
    assert command[command.index("--network") + 1] == "none"
    assert not {"--mount", "--volume", "--privileged"} & set(command)
    assert command[command.index("--entrypoint") + 1] == "/opt/sova/agent"
    assert runner.stdin[3] == b"fixture"
    surface.close()


def test_oci_codec_factory_rejects_observation_attestation_or_session_substitution(
    tmp_path: Path,
) -> None:
    executor = GVisorOciExecutor(
        _docker(tmp_path),
        IMAGE,
        runner=_Runner(_attestation_results()),
    )
    spec = ExactOciProcessSurfaceSpec("agent", "/opt/sova/agent")
    surface = gvisor_process_surface_generation(spec, executor)
    target, session = _target_and_session(surface)
    surface.bind(session, target, tmp_path)
    projection = {surface.sensor_name: surface.observe()}
    valid = ChamberObservation.capture(session, target, 0, projection)
    assert oci_process_codec_factory(spec, executor)(valid).codec_id.endswith("/0.1.0")

    detached = strict_json_loads(canonical_json_bytes(projection))
    assert isinstance(detached, dict)
    detached[surface.sensor_name]["image"] = "example.invalid/substituted@sha256:" + "e" * 64
    substituted = ChamberObservation(
        ObservationVersion(
            session.digest,
            target.digest,
            0,
            sha256_digest(canonical_json_bytes(detached)),
        ),
        detached,
    )
    with pytest.raises(FormatError, match="does not match"):
        oci_process_codec_factory(spec, executor)(substituted)

    session_substitution = strict_json_loads(canonical_json_bytes(projection))
    assert isinstance(session_substitution, dict)
    session_substitution[surface.sensor_name]["sessionDigest"] = _digest("other-session")
    wrong_session = ChamberObservation(
        ObservationVersion(
            session.digest,
            target.digest,
            0,
            sha256_digest(canonical_json_bytes(session_substitution)),
        ),
        session_substitution,
    )
    with pytest.raises(FormatError, match="does not match"):
        oci_process_codec_factory(spec, executor)(wrong_session)
    surface.close()
