# SPDX-License-Identifier: Apache-2.0
"""Universal target profile and fail-closed intake contract tests."""

from __future__ import annotations

import json
import zipfile
from dataclasses import replace
from typing import TYPE_CHECKING

import pytest

from sova.cli import main
from sova.formats import canonical_json_bytes, validate_document
from sova.formats.errors import FormatError
from sova.intake import (
    CredentialReference,
    EntryPoint,
    EntryPointKind,
    InputKind,
    ProfileTargetKind,
    SourceClass,
    TargetProfile,
    describe_material,
    read_intake_report,
    run_universal_intake,
    target_profile_from_mapping,
    target_profile_template,
    validate_intake_report,
    validate_target_profile,
)

if TYPE_CHECKING:
    from pathlib import Path


def test_target_profile_round_trip_is_composite_and_content_addressed(tmp_path: Path) -> None:
    openapi = tmp_path / "openapi.json"
    openapi.write_text('{"openapi":"3.1.0","paths":{}}', encoding="utf-8")
    descriptor = describe_material(
        openapi,
        identifier="api-spec",
        kind=InputKind.OPENAPI,
        source_class=SourceClass.SUPPLIED,
    )
    profile = TargetProfile(
        identifier="owned-composite",
        version="0.1.0",
        title="Owned composite",
        target_kinds=(ProfileTargetKind.WEB, ProfileTargetKind.API),
        authorization_scope="owned deterministic fixture only",
        entrypoints=(
            EntryPoint(
                "owned-api",
                EntryPointKind.API,
                "https://owned.example/api",
                (ProfileTargetKind.WEB, ProfileTargetKind.API),
            ),
        ),
        inputs=(descriptor,),
        credential_references=(
            CredentialReference(
                "sova-secret:owned-api",
                "runtime API authority",
                ("api.read",),
            ),
        ),
    )

    mapping = profile.to_mapping()
    validate_document(mapping, "sova.target-profile")
    restored = target_profile_from_mapping(mapping)
    report = validate_target_profile(restored)

    assert restored.digest == profile.digest
    assert report["accepted"] is True
    assert report["secretMaterialEmbedded"] is False
    assert report["executorMechanicsEmbedded"] is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("authorization_scope", "Bearer definitely-secret-token"),
        ("title", "Basic ZGVmaW5pdGVseS1zZWNyZXQ="),
    ],
)
def test_target_profile_rejects_secret_shaped_values(field: str, value: str) -> None:
    options = {
        "identifier": "owned",
        "version": "0.1.0",
        "title": "Owned",
        "target_kinds": (ProfileTargetKind.WEB,),
        "authorization_scope": "owned fixture only",
    }
    options[field] = value
    with pytest.raises(FormatError, match="secret-shaped"):
        TargetProfile(**options)  # type: ignore[arg-type]


def test_active_observation_import_is_blocked_without_explicit_authorization(
    tmp_path: Path,
) -> None:
    observations = tmp_path / "observations.json"
    observations.write_text(
        '{"workflow":{"nodes":[],"edges":[]},"attackSurface":{"nodes":[],"edges":[]}}',
        encoding="utf-8",
    )
    descriptor = describe_material(
        observations,
        identifier="runtime",
        kind=InputKind.RUNTIME_OBSERVATIONS,
        source_class=SourceClass.ACTIVE,
    )
    base = target_profile_template(
        identifier="owned",
        title="Owned",
        target_kinds=(ProfileTargetKind.AGENT,),
        authorization_scope="owned fixture only",
    )
    profile = replace(base, inputs=(descriptor,))

    artifacts = run_universal_intake(
        profile,
        {"runtime": observations},
        tmp_path / "blocked-intake",
    )
    report = read_intake_report(artifacts.report)

    assert artifacts.status == "inconclusive"
    assert report["inputs"][0]["status"] == "blocked"
    assert report["claims"]["targetCodeExecuted"] is False
    assert report["coverage"]["safeOrClean"] is False


def test_material_drift_and_report_tampering_fail_closed(tmp_path: Path) -> None:
    html = tmp_path / "page.html"
    html.write_text("<main>owned</main>", encoding="utf-8")
    descriptor = describe_material(html, identifier="page", kind=InputKind.HTML)
    base = target_profile_template(
        identifier="owned",
        title="Owned",
        target_kinds=(ProfileTargetKind.WEB,),
        authorization_scope="owned fixture only",
    )
    profile = replace(base, inputs=(descriptor,))
    html.write_text("<main>changed</main>", encoding="utf-8")

    artifacts = run_universal_intake(
        profile,
        {"page": html},
        tmp_path / "drift-intake",
    )
    report = read_intake_report(artifacts.report)
    assert report["status"] == "inconclusive"
    assert report["generation"]["state"] == "drift"

    tampered = dict(report)
    tampered["status"] = "complete"
    with pytest.raises(FormatError, match="digest"):
        validate_intake_report(tampered)

    assert b"<main>changed</main>" not in canonical_json_bytes(report)


def test_malformed_required_material_is_inconclusive_not_clean(tmp_path: Path) -> None:
    malformed = tmp_path / "openapi.json"
    malformed.write_text('{"paths":{}}', encoding="utf-8")
    descriptor = describe_material(
        malformed,
        identifier="api",
        kind=InputKind.OPENAPI,
    )
    base = target_profile_template(
        identifier="owned",
        title="Owned",
        target_kinds=(ProfileTargetKind.API,),
        authorization_scope="owned fixture only",
    )
    artifacts = run_universal_intake(
        replace(base, inputs=(descriptor,)),
        {"api": malformed},
        tmp_path / "malformed-intake",
    )
    report = read_intake_report(artifacts.report)

    assert report["status"] == "inconclusive"
    assert report["inputs"][0]["status"] == "parse-error"
    assert report["coverage"]["safeOrClean"] is False


def test_authorized_runtime_import_redacts_arbitrary_labels_and_values(tmp_path: Path) -> None:
    observations = tmp_path / "observations.json"
    observations.write_text(
        json.dumps(
            {
                "workflow": {
                    "nodes": [
                        {
                            "key": "Basic cHJpdmF0ZS1ydW50aW1lLXZhbHVl",
                            "kind": "agent-state",
                            "name": "Bearer private-runtime-value",
                            "attributes": {
                                "note": "private free form value",
                                "authorization": "Bearer private-runtime-value",
                            },
                        }
                    ],
                    "edges": [],
                },
                "attackSurface": {"nodes": [], "edges": []},
            }
        ),
        encoding="utf-8",
    )
    descriptor = describe_material(
        observations,
        identifier="runtime",
        kind=InputKind.RUNTIME_OBSERVATIONS,
        source_class=SourceClass.ACTIVE,
    )
    base = target_profile_template(
        identifier="owned",
        title="Owned",
        target_kinds=(ProfileTargetKind.AGENT,),
        authorization_scope="owned fixture only",
    )
    artifacts = run_universal_intake(
        replace(base, inputs=(descriptor,)),
        {"runtime": observations},
        tmp_path / "authorized-intake",
        active_observations_authorized=True,
    )
    report_bytes = canonical_json_bytes(read_intake_report(artifacts.report))

    assert b"private-runtime-value" not in report_bytes
    assert b"private free form value" not in report_bytes
    assert b"cHJpdmF0ZS1ydW50aW1lLXZhbHVl" not in report_bytes


def test_cli_creates_validates_and_runs_profile(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    html = tmp_path / "index.html"
    html.write_text('<a href="/orders">orders</a>', encoding="utf-8")
    profile = tmp_path / "profile.json"

    assert (
        main(
            [
                "target",
                "profile-create",
                "owned-web",
                str(profile),
                "--kind",
                "web",
                "--authorization-scope",
                "owned fixture only",
                "--material",
                f"html=html=supplied={html}",
                "--entrypoint",
                "web=url=web=https://owned.example/app",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["accepted"] is True
    assert main(["target", "profile-validate", str(profile)]) == 0
    assert json.loads(capsys.readouterr().out)["accepted"] is True
    assert main(["target", "intake", str(profile), str(tmp_path / "cli-intake")]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["artifactType"] == "sova.intake-artifacts"
    assert output["status"] == "complete"


def test_archive_traversal_is_reported_without_extraction(tmp_path: Path) -> None:
    archive = tmp_path / "source.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("../outside.txt", "must never be extracted")
    descriptor = describe_material(
        archive,
        identifier="source",
        kind=InputKind.ARCHIVE,
    )
    base = target_profile_template(
        identifier="owned",
        title="Owned",
        target_kinds=(ProfileTargetKind.SOURCE,),
        authorization_scope="owned fixture only",
    )

    artifacts = run_universal_intake(
        replace(base, inputs=(descriptor,)),
        {"source": archive},
        tmp_path / "archive-intake",
    )
    report = read_intake_report(artifacts.report)

    assert report["status"] == "inconclusive"
    assert report["errors"][0]["code"] == "SOVA-INTAKE-ARCHIVE-PATH"
    assert not (tmp_path / "outside.txt").exists()
