# SPDX-License-Identifier: Apache-2.0
"""Default-on, opt-out-able auto-contribution after a run."""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

import pytest

from sova.capsule import CaptureProfile, DomainProfile, build_capsule, capsule_manifest_template
from sova.formats.errors import FormatError
from sova.registry.auto_contribute import auto_contribute_after_run
from sova.registry.client import RegistryClient, RegistryEndpoint
from sova.registry.contribution import preview_contribution
from sova.registry.service import CommunityHTTPService, CommunityServiceConfig
from sova.trace import TraceWriter

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

_TOKEN = "x" * 32
_TRUSTED_KEY_ID = "sha256:" + "1" * 64
_CONTRIBUTOR = {"name": "Test Contributor", "identity": "test@example.invalid"}


def _fixture_trace(path: Path) -> Path:
    writer = TraceWriter(path)
    writer.append("run.started", {"note": "fixture"}, phase="fixture")
    writer.append("run.completed", {"completion": "completed"}, phase="fixture")
    writer.finalize(completion="completed")
    return path


def _fixture_capsule(path: Path) -> Path:
    manifest = capsule_manifest_template(
        title="Auto-contribute fixture capsule",
        summary="Minimal capsule for auto-contribution tests.",
        author="test",
        domain_profile=DomainProfile.EVALUATION,
        capture_profile=CaptureProfile.LITE,
    )
    build_capsule(path, manifest)
    return path


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


def test_disabled_short_circuits_before_touching_disk_or_network(tmp_path: Path) -> None:
    capsule = _fixture_capsule(tmp_path / "run.sova")
    trace = _fixture_trace(tmp_path / "run.sova-trace")
    result = auto_contribute_after_run(
        capsule=capsule,
        trace=trace,
        staging_destination=tmp_path / "staged",
        contributor=_CONTRIBUTOR,
        enabled=False,
    )
    assert result["contributed"] is False
    assert result["reason"] == "operator-opted-out"
    assert not (tmp_path / "staged").exists()


def test_default_enabled_stages_and_falls_back_to_local_pr_instructions(
    tmp_path: Path,
) -> None:
    capsule = _fixture_capsule(tmp_path / "run.sova")
    trace = _fixture_trace(tmp_path / "run.sova-trace")
    result = auto_contribute_after_run(
        capsule=capsule,
        trace=trace,
        staging_destination=tmp_path / "staged",
        contributor=_CONTRIBUTOR,
        # enabled defaults to True: no explicit opt-in required.
    )
    assert result["contributed"] is True
    assert result["transport"] == "git-pr-local-only"
    assert result["pushed"] is False
    assert result["uploadPerformed"] is False
    assert (tmp_path / "staged" / "contribution.json").is_file()
    assert (tmp_path / "staged" / "PR_INSTRUCTIONS.md").is_file()


def test_service_client_uploads_instead_of_the_pr_fallback(
    tmp_path: Path, running_service: CommunityHTTPService
) -> None:
    capsule = _fixture_capsule(tmp_path / "run.sova")
    trace = _fixture_trace(tmp_path / "run.sova-trace")
    host, port = running_service.address
    client = RegistryClient(RegistryEndpoint(f"http://{host}:{port}", _TOKEN))

    result = auto_contribute_after_run(
        capsule=capsule,
        trace=trace,
        staging_destination=tmp_path / "staged",
        contributor=_CONTRIBUTOR,
        registry_client=client,
        submission_metadata={"requiredKeyId": _TRUSTED_KEY_ID},
    )
    assert result["contributed"] is True
    assert result["transport"] == "service"
    assert result["uploadPerformed"] is True
    assert result["upload"]["status"] in {"queued", "verifying", "accepted", "rejected"}
    assert result["upload"]["id"].startswith("sova-sub-")


def test_secret_shaped_capsule_content_hard_fails_before_any_upload(tmp_path: Path) -> None:
    """`_review_item` fails closed (raises) on credential-shaped content; a
    caller must not silently swallow this into a soft "not contributed"
    result, since that could hide a real secret-leak from the operator."""
    manifest = capsule_manifest_template(
        title="Secret fixture capsule",
        summary="password=hunter2hunter2hunter2",
        author="test",
        domain_profile=DomainProfile.EVALUATION,
        capture_profile=CaptureProfile.LITE,
    )
    capsule = tmp_path / "secret.sova"
    build_capsule(capsule, manifest)
    trace = _fixture_trace(tmp_path / "run.sova-trace")

    with pytest.raises(FormatError, match="credential-shaped"):
        auto_contribute_after_run(
            capsule=capsule,
            trace=trace,
            staging_destination=tmp_path / "staged",
            contributor=_CONTRIBUTOR,
        )
    assert not (tmp_path / "staged").exists()


def test_disallowed_gate_fails_soft_without_raising(tmp_path: Path) -> None:
    """An ungranted contribution gate (e.g. the operator declined disclosure)
    is a normal, expected outcome and must return a soft rejection, not raise."""
    capsule = _fixture_capsule(tmp_path / "run.sova")
    trace = _fixture_trace(tmp_path / "run.sova-trace")
    specification_override = {
        "items": [str(capsule), str(trace)],
        "contributor": _CONTRIBUTOR,
        "license": "Apache-2.0",
        "gates": {
            "humanReviewed": False,
            "publicDisclosureAllowed": True,
            "authorizationRedacted": True,
            "provenanceComplete": True,
            "separateCorpusReuseConsent": True,
        },
    }
    preview = preview_contribution(specification_override)
    assert preview["acceptedForLocalStaging"] is False
