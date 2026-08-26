# SPDX-License-Identifier: Apache-2.0
"""`RegistryClient` against a real loopback `CommunityHTTPService`."""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

import pytest

from sova.capsule import CaptureProfile, DomainProfile, build_capsule, capsule_manifest_template
from sova.formats.errors import FormatError
from sova.registry.client import RegistryClient, RegistryEndpoint
from sova.registry.service import CommunityHTTPService, CommunityServiceConfig
from sova.trace import TraceWriter

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

_TOKEN = "x" * 32
_TRUSTED_KEY_ID = "sha256:" + "1" * 64


@pytest.fixture
def running_service(tmp_path: Path) -> Iterator[CommunityHTTPService]:
    config = CommunityServiceConfig(
        tmp_path / "service-root",
        _TOKEN,
        frozenset({_TRUSTED_KEY_ID}),
        "sova-methodology/0.1.0",
    )
    service = CommunityHTTPService(config)
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    service._serving.wait(timeout=5)
    try:
        yield service
    finally:
        service.close()
        thread.join(timeout=10)


def _endpoint(service: CommunityHTTPService, *, token: str = _TOKEN) -> RegistryEndpoint:
    host, port = service.address
    return RegistryEndpoint(f"http://{host}:{port}", token)


def _fixture_trace(path: Path) -> Path:
    writer = TraceWriter(path)
    writer.append("run.started", {"note": "fixture"}, phase="fixture")
    writer.append("run.completed", {"completion": "completed"}, phase="fixture")
    writer.finalize(completion="completed")
    return path


def _fixture_capsule(path: Path) -> Path:
    manifest = capsule_manifest_template(
        title="Registry client fixture capsule",
        summary="Minimal capsule used to exercise the registry client.",
        author="test",
        domain_profile=DomainProfile.EVALUATION,
        capture_profile=CaptureProfile.LITE,
    )
    build_capsule(path, manifest)
    return path


def test_health_returns_a_verified_ready_response(running_service: CommunityHTTPService) -> None:
    client = RegistryClient(_endpoint(running_service))
    verified = client.health()
    assert verified["status"] == "ready"
    assert verified["loopbackVerified"] is True


def test_limits_matches_the_service_configured_limits(
    running_service: CommunityHTTPService,
) -> None:
    client = RegistryClient(_endpoint(running_service))
    limits = client.limits()
    assert limits.to_mapping() == running_service.config.limits.to_mapping()


def test_submit_round_trips_and_can_be_polled_by_status(
    tmp_path: Path, running_service: CommunityHTTPService
) -> None:
    client = RegistryClient(_endpoint(running_service))
    capsule = _fixture_capsule(tmp_path / "fixture.sova")
    trace = _fixture_trace(tmp_path / "fixture.sova-trace")

    submitted = client.submit_capsule_and_trace(
        kind="registry",
        metadata={"requiredKeyId": _TRUSTED_KEY_ID},
        capsule=capsule,
        trace=trace,
    )
    assert submitted["artifactType"] == "sova.community-submission-status"
    assert submitted["status"] in {"queued", "verifying", "accepted", "rejected"}
    submission_id = submitted["id"]
    assert submission_id.startswith("sova-sub-")

    fetched = client.submission_status(submission_id)
    assert fetched["id"] == submission_id


def test_submit_requires_a_valid_bearer_token(
    tmp_path: Path, running_service: CommunityHTTPService
) -> None:
    client = RegistryClient(_endpoint(running_service, token="y" * 32))
    capsule = _fixture_capsule(tmp_path / "fixture.sova")
    trace = _fixture_trace(tmp_path / "fixture.sova-trace")
    with pytest.raises(FormatError):
        client.submit_capsule_and_trace(
            kind="registry",
            metadata={"requiredKeyId": _TRUSTED_KEY_ID},
            capsule=capsule,
            trace=trace,
        )


def test_status_for_an_unknown_submission_id_fails(
    running_service: CommunityHTTPService,
) -> None:
    client = RegistryClient(_endpoint(running_service))
    with pytest.raises(FormatError):
        client.submission_status("sova-sub-doesnotexist000000")


def test_wait_until_terminal_stops_at_the_deadline_when_status_never_advances() -> None:
    client = RegistryClient.__new__(RegistryClient)  # bypass __init__: this test fakes I/O
    calls: list[float] = []
    statuses = iter(["queued", "queued", "queued"])
    client.submission_status = lambda _submission_id: {"status": next(statuses, "queued")}  # type: ignore[assignment]

    clock_value = [0.0]

    def fake_clock() -> float:
        return clock_value[0]

    def fake_sleep(seconds: float) -> None:
        calls.append(seconds)
        clock_value[0] += seconds

    result = client.wait_until_terminal(
        "sova-sub-x",
        poll_interval_s=1.0,
        timeout_s=2.5,
        sleep=fake_sleep,
        clock=fake_clock,
    )
    assert result["status"] == "queued"
    assert len(calls) <= 3  # bounded by the deadline, never spins unboundedly


def test_endpoint_rejects_a_non_loopback_url() -> None:
    with pytest.raises(FormatError, match="loopback"):
        RegistryEndpoint("http://example.invalid", "x" * 32)


def test_endpoint_rejects_a_short_token() -> None:
    with pytest.raises(FormatError, match="24 characters"):
        RegistryEndpoint("http://127.0.0.1:9999", "short")
