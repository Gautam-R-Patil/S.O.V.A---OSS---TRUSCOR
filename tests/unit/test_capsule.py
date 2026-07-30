# SPDX-License-Identifier: Apache-2.0
"""`.sova` capsule authoring, package, and lifecycle contracts."""

from __future__ import annotations

import zipfile
from typing import TYPE_CHECKING

import pytest

from sova.capsule import (
    CapsuleLifecycle,
    build_capsule,
    can_transition,
    capsule_manifest_template,
    lint_capsule,
    render_capsule,
    scenario_template,
)
from sova.formats import PackageReader, PackageWriter, canonical_json_bytes
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from pathlib import Path


def _capsule(tmp_path: Path) -> Path:
    path = tmp_path / "behavior.sova"
    manifest = capsule_manifest_template(
        title="Conditional behavior",
        summary="A deterministic synthetic behavior fixture.",
        author="Test author",
    )
    scenario = scenario_template(title="Synthetic scenario", purpose="Test package semantics")
    build_capsule(path, manifest, scenario=scenario, attachments={"fixture.txt": b"fixture"})
    return path


def test_capsule_round_trip_is_deterministic_and_inert(tmp_path: Path) -> None:
    first = _capsule(tmp_path)
    second = tmp_path / "same.sova"
    reader = PackageReader(first)
    manifest = reader.manifest("sova.capsule")
    scenario_descriptor = next(item for item in reader.verify() if item.role == "scenario")
    scenario = reader.read_object(scenario_descriptor)

    writer_manifest = dict(manifest)
    writer_manifest.pop("objects")
    writer = PackageWriter(writer_manifest)
    for descriptor in reader.verify():
        writer.add_bytes(
            role=descriptor.role,
            path=descriptor.path,
            media_type=descriptor.mediaType,
            data=reader.read_object(descriptor),
        )
    writer.write(second)

    assert first.read_bytes() == second.read_bytes()
    assert b"sova.observe.fixture" in scenario
    assert "Rendering is inert" in render_capsule(first)
    issues = lint_capsule(first)
    assert {issue.code for issue in issues} == {
        "SOVA-LINT-NO-LICENSE",
        "SOVA-LINT-UNKNOWN-IMPACT",
    }


def test_capsule_can_exist_without_scenario_for_incident_or_research(tmp_path: Path) -> None:
    path = tmp_path / "observation-only.sova"
    manifest = capsule_manifest_template(
        title="Unexpected output",
        summary="An observation awaiting a reproduction recipe.",
        author="Observer",
    )
    build_capsule(path, manifest)
    assert "SOVA-LINT-NO-SCENARIO" in {issue.code for issue in lint_capsule(path)}


def test_capsule_lifecycle_is_explicit_and_terminal_states_do_not_reopen() -> None:
    assert can_transition(CapsuleLifecycle.DRAFT, CapsuleLifecycle.EMBARGOED)
    assert can_transition(CapsuleLifecycle.DISCLOSED, CapsuleLifecycle.CORRECTED)
    assert can_transition(CapsuleLifecycle.VERIFIED, CapsuleLifecycle.REVOKED)
    assert not can_transition(CapsuleLifecycle.WITHDRAWN, CapsuleLifecycle.DRAFT)
    assert not can_transition(CapsuleLifecycle.REVOKED, CapsuleLifecycle.DRAFT)
    assert not can_transition(CapsuleLifecycle.SUPERSEDED, CapsuleLifecycle.VERIFIED)


def test_archive_path_traversal_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "traversal.sova"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("manifest.json", b"{}")
        archive.writestr("../escape", b"bad")
    with pytest.raises(FormatError) as error:
        PackageReader(path).raw_manifest()
    assert error.value.issue.code == "SOVA-PACKAGE-PATH"


def test_undeclared_member_is_rejected(tmp_path: Path) -> None:
    original = _capsule(tmp_path)
    changed = tmp_path / "undeclared.sova"
    with zipfile.ZipFile(original) as source, zipfile.ZipFile(changed, "w") as destination:
        for item in source.infolist():
            destination.writestr(item, source.read(item.filename))
        destination.writestr("objects/undeclared.txt", b"surprise")
    with pytest.raises(FormatError) as error:
        PackageReader(changed).verify("sova.capsule")
    assert error.value.issue.code == "SOVA-PACKAGE-INDEX-MISMATCH"


def test_manifest_bytes_are_canonical(tmp_path: Path) -> None:
    path = _capsule(tmp_path)
    with zipfile.ZipFile(path) as archive:
        manifest_bytes = archive.read("manifest.json")
    assert canonical_json_bytes(PackageReader(path).manifest()) == manifest_bytes
    assert PackageReader(path).content_digest("sova.capsule").startswith("sha256:")


def test_attachments_are_content_addressed_and_deduplicated(tmp_path: Path) -> None:
    path = tmp_path / "attachments.sova"
    manifest = capsule_manifest_template(
        title="Attachments",
        summary="Content-addressed attachment fixture.",
        author="Test author",
    )
    build_capsule(
        path,
        manifest,
        attachments={"first.txt": b"same", "renamed.txt": b"same"},
    )
    attachments = [
        item for item in PackageReader(path).verify("sova.capsule") if item.role == "attachment"
    ]
    assert len(attachments) == 1
    assert attachments[0].path == f"blobs/sha256/{attachments[0].digest[7:]}"


def test_secret_shaped_scenario_content_is_rejected_before_packaging(tmp_path: Path) -> None:
    manifest = capsule_manifest_template(
        title="Unsafe authoring",
        summary="Must fail before persistence.",
        author="Test author",
    )
    scenario = scenario_template(title="Unsafe", purpose="Verify secret gate")
    scenario["parameters"] = {"api_key": "sk-never-package-this-value"}
    with pytest.raises(FormatError) as error:
        build_capsule(tmp_path / "unsafe.sova", manifest, scenario=scenario)
    assert error.value.issue.code == "SOVA-CAPSULE-SECRET-MATERIAL"
