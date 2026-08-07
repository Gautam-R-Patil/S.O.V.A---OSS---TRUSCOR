# SPDX-License-Identifier: Apache-2.0
"""Offline case-workspace integration and hostile-boundary tests."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

import sova.workflows.case as case_module
from sova.capsule import build_capsule, capsule_manifest_template, scenario_template
from sova.cli import main
from sova.formats import sha256_digest, strict_json_loads
from sova.formats.errors import FormatError
from sova.trace import TraceWriter, generate_ed25519_keypair
from sova.workflows import build_case_workspace

if TYPE_CHECKING:
    from pathlib import Path

_RENDERER_FAILURE = "injected renderer failure"


def _fingerprints() -> dict[str, dict[str, str | None]]:
    return {
        name: {
            "value": None,
            "status": "not-applicable",
            "method": "case-test-fixture",
            "source": "case-test-fixture",
            "version": "0.1.0",
        }
        for name in ("environment", "target", "code", "dependencies", "registry", "model")
    }


def _linked_artifacts(  # noqa: PLR0913 - test fixture exposes independent trust dimensions
    root: Path,
    *,
    stem: str = "observed",
    reviewed_for_export: bool = False,
    signed: bool = True,
    pinned_capsule: bool = True,
    extra_events: int = 0,
    include_events: bool = True,
    completion: str = "completed",
) -> tuple[Path, Path]:
    trace = root / f"{stem}.sova-trace"
    writer = TraceWriter(
        trace,
        signing_key=generate_ed25519_keypair() if signed else None,
        fingerprints=_fingerprints(),
        reviewed_for_export=reviewed_for_export,
        authorization={
            "decision": "allowed",
            "scopeDigest": sha256_digest(b"owned-case-fixture"),
            "decidedBy": "test-operator",
        },
    )
    if include_events:
        started = writer.append("run.started", {"mode": "owned-case-fixture"})
        prompt = writer.append(
            "prompt.sent",
            {"message": "observe fixture", "password": "never-emit-this-secret"},
            parents=[started] if started else [],
        )
        writer.append(
            "oracle.completed",
            {"status": "pass", "expected": "FIXTURE_OBSERVED"},
            parents=[prompt] if prompt else [],
        )
        for index in range(extra_events):
            writer.append("prompt.sent", {"message": f"fixture event {index}"})
        writer.append("run.completed", {"status": completion})
    writer.finalize(completion=completion)

    scenario = scenario_template(title="Case fixture", purpose="Index one inert observation")
    manifest = capsule_manifest_template(
        title="Linked case fixture",
        summary="Safe capsule and signed trace for offline case construction.",
        author="SOVA tests",
    )
    manifest["license"] = "Apache-2.0"
    manifest["safety"]["impact"] = "none"
    manifest["requiredFeatures"] = ["trace.core/0.1"]
    if pinned_capsule:
        manifest["methodology"] = {
            "id": "SOVA-CASE-TEST",
            "version": "0.1.0",
            "digest": sha256_digest(b"case-test-methodology"),
        }
        manifest["taxonomy"] = {
            "id": "sova.case-test",
            "version": "0.1.0",
            "digest": sha256_digest(b"case-test-taxonomy"),
        }
    capsule = root / f"{stem}.sova"
    build_capsule(capsule, manifest, scenario=scenario, traces=[trace])
    return trace, capsule


def _load(path: Path) -> dict[str, Any]:
    document = strict_json_loads(path.read_bytes())
    assert isinstance(document, dict)
    return document


@pytest.mark.integration
def test_case_workspace_connects_verification_forensics_replay_evidence_and_registry(
    tmp_path: Path,
) -> None:
    trace, capsule = _linked_artifacts(tmp_path)
    result = build_case_workspace(
        trace,
        capsule,
        tmp_path / "case",
        title="Owned fixture behavior",
    )

    assert result.event_count == 4
    case = _load(result.index)
    assert case["source"]["exactTraceEmbeddedInCapsule"] is True
    assert case["operations"] == {
        "tracePlayback": True,
        "controlledReexecution": False,
        "semanticReproduction": False,
        "targetExecuted": False,
        "networkUsed": False,
        "uploadPerformed": False,
    }
    assert len(case["artifacts"]) == 17
    assert _load(result.reconstruction)["source"]["integrityState"] == (
        "verified-within-declared-trust-policy"
    )
    assert _load(result.evidence)["assuranceBoundary"]["independentAttestation"] is False
    assert _load(result.snapshot)["axes"]["observedEffects"]["eventCount"] == 4
    preview = _load(result.contribution_preview)
    assert preview["acceptedForLocalStaging"] is False
    assert preview["uploadPerformed"] is False
    assert result.timeline.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert result.replay_clip.read_bytes().startswith(b"YUV4MPEG2")
    assert b"never-emit-this-secret" not in result.replay_clip.read_bytes()
    assert b"never-emit-this-secret" not in result.replay_clip.with_suffix(".y4m.json").read_bytes()
    disclosure = _load(result.root / "artifacts" / "selective-disclosure.json")
    assert all("payload" not in event for event in disclosure["events"])


@pytest.mark.integration
def test_case_workspace_refuses_unlinked_or_not_export_reviewed_evidence(tmp_path: Path) -> None:
    trace, capsule = _linked_artifacts(tmp_path, stem="first")
    other_trace, _other_capsule = _linked_artifacts(tmp_path, stem="other")

    with pytest.raises(FormatError) as unlinked:
        build_case_workspace(other_trace, capsule, tmp_path / "unlinked-case")
    assert unlinked.value.issue.code == "SOVA-CASE-TRACE-LINK"

    with pytest.raises(FormatError) as disclosure:
        build_case_workspace(
            trace,
            capsule,
            tmp_path / "disclosed-case",
            classification="real-disclosed-finding",
            disclosure_cleared=True,
            reviewed_for_export=True,
        )
    assert disclosure.value.issue.code == "SOVA-CASE-DISCLOSURE"
    assert not (tmp_path / "unlinked-case").exists()
    assert not (tmp_path / "disclosed-case").exists()


@pytest.mark.integration
def test_case_build_cli_is_complete_and_still_local_only(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    trace, capsule = _linked_artifacts(tmp_path)
    destination = tmp_path / "cli-case"
    assert (
        main(
            [
                "case",
                "build",
                str(trace),
                str(capsule),
                str(destination),
                "--title",
                "CLI owned fixture behavior",
            ]
        )
        == 0
    )
    output = strict_json_loads(capfd.readouterr().out.encode())
    assert isinstance(output, dict)
    assert output["status"] == "built"
    assert output["targetExecuted"] is False
    assert output["networkUsed"] is False
    assert output["publicationPerformed"] is False
    assert (destination / "case.json").is_file()


@pytest.mark.integration
def test_case_workspace_requires_regular_verified_inputs_and_new_destination(
    tmp_path: Path,
) -> None:
    with pytest.raises(FormatError) as missing:
        build_case_workspace(
            tmp_path / "missing.sova-trace",
            tmp_path / "missing.sova",
            tmp_path / "case",
        )
    assert missing.value.issue.code == "SOVA-CASE-INPUT"

    unsigned_trace, unsigned_capsule = _linked_artifacts(
        tmp_path,
        stem="unsigned",
        signed=False,
    )
    with pytest.raises(FormatError) as unsigned:
        build_case_workspace(unsigned_trace, unsigned_capsule, tmp_path / "unsigned-case")
    assert unsigned.value.issue.code == "SOVA-CASE-TRACE-VERIFY"

    trace, partial_capsule = _linked_artifacts(
        tmp_path,
        stem="partial-capsule",
        pinned_capsule=False,
    )
    with pytest.raises(FormatError) as partial:
        build_case_workspace(trace, partial_capsule, tmp_path / "partial-case")
    assert partial.value.issue.code == "SOVA-CASE-CAPSULE-VERIFY"

    verified_trace, verified_capsule = _linked_artifacts(tmp_path, stem="destination")
    destination = tmp_path / "already-there"
    destination.mkdir()
    with pytest.raises(FormatError) as existing:
        build_case_workspace(verified_trace, verified_capsule, destination)
    assert existing.value.issue.code == "SOVA-CASE-DESTINATION"


@pytest.mark.integration
@pytest.mark.parametrize(
    "overrides",
    [
        {"title": ""},
        {"title": "x" * 241},
        {"classification": "unknown"},
        {"component": ""},
        {"component_version": ""},
    ],
)
def test_case_workspace_rejects_invalid_review_metadata(
    tmp_path: Path,
    overrides: dict[str, Any],
) -> None:
    trace, capsule = _linked_artifacts(tmp_path, stem="metadata")
    with pytest.raises(FormatError):
        build_case_workspace(trace, capsule, tmp_path / "metadata-case", **overrides)


@pytest.mark.integration
def test_case_workspace_samples_long_trace_and_allows_fully_reviewed_disclosed_case(
    tmp_path: Path,
) -> None:
    trace, capsule = _linked_artifacts(
        tmp_path,
        stem="reviewed",
        reviewed_for_export=True,
        extra_events=20,
    )
    result = build_case_workspace(
        trace,
        capsule,
        tmp_path / "reviewed-case",
        classification="real-disclosed-finding",
        component="owned fixture",
        disclosure_cleared=True,
        reviewed_for_export=True,
    )
    sidecar = _load(result.replay_clip.with_suffix(".y4m.json"))
    assert sidecar["durationSeconds"] == "12"
    assert sidecar["component"] == "owned fixture"
    assert sidecar["disclosureCleared"] is True


@pytest.mark.integration
def test_case_workspace_removes_partial_output_after_renderer_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trace, capsule = _linked_artifacts(tmp_path, stem="renderer-failure")

    def fail_renderer(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(_RENDERER_FAILURE)

    monkeypatch.setattr(case_module, "render_timeline_html", fail_renderer)
    with pytest.raises(RuntimeError, match="injected"):
        build_case_workspace(trace, capsule, tmp_path / "failed-case")
    assert not (tmp_path / "failed-case").exists()
    assert not list(tmp_path.glob(".sova-case-*"))


@pytest.mark.integration
def test_case_workspace_rejects_failed_and_empty_completed_traces(tmp_path: Path) -> None:
    failed_trace, failed_capsule = _linked_artifacts(
        tmp_path,
        stem="failed",
        completion="failed",
    )
    with pytest.raises(FormatError) as incomplete:
        build_case_workspace(failed_trace, failed_capsule, tmp_path / "failed-trace-case")
    assert incomplete.value.issue.code == "SOVA-CASE-INCOMPLETE"

    empty_trace, empty_capsule = _linked_artifacts(
        tmp_path,
        stem="empty",
        include_events=False,
    )
    with pytest.raises(FormatError) as empty:
        build_case_workspace(empty_trace, empty_capsule, tmp_path / "empty-case")
    assert empty.value.issue.code == "SOVA-CASE-EMPTY"


def test_case_internal_assertions_fail_closed(tmp_path: Path) -> None:
    source = tmp_path / "copy.bin"
    source.write_bytes(b"source")
    with pytest.raises(FormatError) as copy:
        case_module._require_verified_copy(source, sha256_digest(b"different"))
    assert copy.value.issue.code == "SOVA-CASE-COPY"
    with pytest.raises(FormatError) as preview:
        case_module._require_blocked_preview(
            {"acceptedForLocalStaging": True, "uploadPerformed": False}
        )
    assert preview.value.issue.code == "SOVA-CASE-CONTRIBUTE"
