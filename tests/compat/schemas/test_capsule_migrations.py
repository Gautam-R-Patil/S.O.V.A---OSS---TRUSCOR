# SPDX-License-Identifier: Apache-2.0
"""Experimental chained `.sova` migration contracts."""

from __future__ import annotations

import zipfile
from copy import deepcopy
from typing import TYPE_CHECKING

import pytest

from sova.capsule import migrate as migrate_module
from sova.capsule.migrate import analyze_migration, migrate_capsule, migrate_manifest
from sova.formats import PackageReader, canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from pathlib import Path


def _legacy() -> dict[str, object]:
    return {
        "artifactType": "sova.capsule",
        "schemaVersion": "0.0.1",
        "id": "sova:capsule:018f7f8a-6d1e-7b2a-8d0f-8f0f0f0f0f0f",
        "title": "Legacy behavior",
        "description": "Same information, newer structure.",
        "useCase": "attack",
        "createdAt": "2026-07-30T00:00:00Z",
        "authors": ["Gautam R. Patil"],
        "objects": [],
        "customMetadata": {"preserve": True},
    }


@pytest.mark.compat
def test_chained_migration_preserves_source_and_unknown_optional_data() -> None:
    source = _legacy()
    migrated = migrate_manifest(deepcopy(source))
    assert source == _legacy()
    assert migrated["schemaVersion"] == "0.1.0"
    assert migrated["summary"] == source["description"]
    assert migrated["domainProfile"] == "security"
    assert migrated["authors"] == [{"name": "Gautam R. Patil"}]
    assert migrated["extensions"]["x-sova-legacy"] == {"customMetadata": {"preserve": True}}
    assert migrated["migration"]["path"] == ["0.0.1->0.0.2", "0.0.2->0.1.0"]
    assert migrated["authorization"]["reexecutionRequiresFreshAuthorization"] is True


@pytest.mark.compat
def test_same_version_migration_is_idempotent() -> None:
    current = migrate_manifest(_legacy())
    assert migrate_manifest(current) == current


@pytest.mark.compat
def test_unknown_required_behavior_fails_closed() -> None:
    source = _legacy()
    source["requiredFeatures"] = ["vendor.magic/9"]
    with pytest.raises(FormatError) as error:
        migrate_manifest(source)
    assert error.value.issue.code == "SOVA-MIGRATE-UNKNOWN-REQUIRED-FEATURE"
    details = error.value.issue.details
    assert details is not None
    assert details["features"] == ["vendor.magic/9"]


@pytest.mark.compat
def test_migration_does_not_promise_unavailable_historical_information() -> None:
    migrated = migrate_manifest(_legacy())
    assert migrated["compatibility"]["runtime"] == "unknown-after-migration"
    assert migrated["safety"]["impact"] == "unknown"
    assert any("historical context may be unknown" in item for item in migrated["limitations"])


@pytest.mark.compat
def test_package_migration_never_overwrites_source(tmp_path: Path) -> None:
    source = tmp_path / "legacy.sova"
    destination = tmp_path / "current.sova"
    source_bytes = canonical_json_bytes(_legacy())
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("manifest.json", source_bytes)
    original_package = source.read_bytes()

    digest = migrate_capsule(source, destination)

    assert digest.startswith("sha256:")
    assert source.read_bytes() == original_package
    migrated = PackageReader(destination).manifest("sova.capsule")
    assert migrated["schemaVersion"] == "0.1.0"
    assert migrated["migration"]["classification"] == "lossless-forward"
    assert migrated["migration"]["sourcePackageDigest"].startswith("sha256:")
    with pytest.raises(FormatError) as error:
        migrate_capsule(source, source)
    assert error.value.issue.code == "SOVA-MIGRATE-NO-OVERWRITE"


@pytest.mark.compat
def test_migration_preflight_explains_every_incompatibility() -> None:
    source = {
        "artifactType": "wrong",
        "requiredFeatures": "not-an-array",
    }
    analysis = analyze_migration(source)
    assert analysis.classification == "unsupported"
    assert analysis.source_version == "<missing>"
    assert "unsupported artifactType" in analysis.blockers
    assert "requiredFeatures is not a string array" in analysis.blockers
    assert any("no deterministic migration path" in blocker for blocker in analysis.blockers)

    unknown_use_case = _legacy()
    unknown_use_case["useCase"] = "unmappable"
    analysis = analyze_migration(unknown_use_case)
    assert not analysis.lossless
    assert "legacy useCase cannot be mapped without inventing meaning" in analysis.blockers


@pytest.mark.compat
def test_cycle_in_internal_migration_graph_fails_visibly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unchanged(value: dict[str, object]) -> dict[str, object]:
        return value

    monkeypatch.setattr(
        migrate_module,
        "_MIGRATIONS",
        {("x", "y"): unchanged, ("y", "x"): unchanged},
    )
    analysis = analyze_migration(
        {"artifactType": "sova.capsule", "schemaVersion": "x"},
        destination_version="z",
    )
    assert analysis.classification == "unsupported"
    assert any("no deterministic migration path" in blocker for blocker in analysis.blockers)


@pytest.mark.compat
def test_package_migration_preserves_objects_and_refuses_existing_destination(
    tmp_path: Path,
) -> None:
    source = tmp_path / "legacy-with-object.sova"
    destination = tmp_path / "current.sova"
    data = b"portable fixture"
    legacy = _legacy()
    legacy["objects"] = [
        {
            "role": "fixture",
            "path": "fixtures/value.txt",
            "mediaType": "text/plain",
            "digest": sha256_digest(data),
            "size": len(data),
        }
    ]
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("manifest.json", canonical_json_bytes(legacy))
        archive.writestr("fixtures/value.txt", data)

    migrate_capsule(source, destination)
    descriptors = PackageReader(destination).verify("sova.capsule")
    assert {descriptor.role for descriptor in descriptors} == {
        "fixture",
        "migration-source-manifest",
    }
    with pytest.raises(FormatError) as exists:
        migrate_capsule(source, destination)
    assert exists.value.issue.code == "SOVA-MIGRATE-DESTINATION-EXISTS"
