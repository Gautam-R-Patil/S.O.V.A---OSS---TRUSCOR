# SPDX-License-Identifier: Apache-2.0
"""Topic 27 neutral conformance-kit contracts."""

from __future__ import annotations

import json
import stat
import zipfile
from typing import TYPE_CHECKING

import pytest

import sova.conformance as conformance_module
from sova.cli import main
from sova.conformance import export_conformance_kit, verify_conformance_kit
from sova.formats import canonical_json_bytes
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from pathlib import Path


def test_conformance_kit_is_byte_reproducible_and_self_verifying(tmp_path: Path) -> None:
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    one = export_conformance_kit(first)
    two = export_conformance_kit(second)
    assert first.read_bytes() == second.read_bytes()
    assert one["archiveDigest"] == two["archiveDigest"]
    assert verify_conformance_kit(first)["accepted"] is True
    with zipfile.ZipFile(first) as archive:
        names = archive.namelist()
        assert "manifest.json" in names
        assert any(name.startswith("schemas/") for name in names)
        assert any(name.startswith("vectors/") for name in names)


def test_conformance_verifier_detects_undeclared_entry(tmp_path: Path) -> None:
    path = tmp_path / "kit.zip"
    export_conformance_kit(path)
    with zipfile.ZipFile(path, "a") as archive:
        archive.writestr("undeclared.txt", "unexpected")
    report = verify_conformance_kit(path)
    assert report["accepted"] is False
    assert report["undeclared"] == ["undeclared.txt"]


def test_conformance_verifier_rejects_traversal_links_and_case_collisions(
    tmp_path: Path,
) -> None:
    traversal = tmp_path / "traversal.zip"
    with zipfile.ZipFile(traversal, "w") as archive:
        archive.writestr("../escape", "bad")
    with pytest.raises(FormatError, match="unsafe"):
        verify_conformance_kit(traversal)

    linked = tmp_path / "link.zip"
    link = zipfile.ZipInfo("linked-schema")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(linked, "w") as archive:
        archive.writestr(link, "target")
    with pytest.raises(FormatError, match="links"):
        verify_conformance_kit(linked)

    collision = tmp_path / "collision.zip"
    with zipfile.ZipFile(collision, "w") as archive:
        archive.writestr("Vector.json", "one")
        archive.writestr("vector.json", "two")
    with pytest.raises(FormatError, match="duplicated"):
        verify_conformance_kit(collision)


def test_conformance_verifier_rejects_invalid_empty_missing_and_bad_manifests(
    tmp_path: Path,
) -> None:
    invalid = tmp_path / "invalid.zip"
    invalid.write_bytes(b"not a zip")
    with pytest.raises(FormatError, match="valid ZIP"):
        verify_conformance_kit(invalid)

    empty = tmp_path / "empty.zip"
    with zipfile.ZipFile(empty, "w"):
        pass
    with pytest.raises(FormatError, match="entry count"):
        verify_conformance_kit(empty)

    missing = tmp_path / "missing.zip"
    with zipfile.ZipFile(missing, "w") as archive:
        archive.writestr("vector.json", "{}")
    with pytest.raises(FormatError, match="manifest is missing"):
        verify_conformance_kit(missing)

    cases: tuple[tuple[object, str], ...] = (
        ([], "malformed"),
        ({}, "malformed"),
        ({"entries": ["bad"]}, "entry is malformed"),
        (
            {"entries": [{"path": "Vector.json"}, {"path": "vector.json"}]},
            "duplicated",
        ),
    )
    for index, (manifest, message) in enumerate(cases):
        path = tmp_path / f"manifest-{index}.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("manifest.json", canonical_json_bytes(manifest))
        with pytest.raises(FormatError, match=message):
            verify_conformance_kit(path)


def test_conformance_verifier_detects_content_mismatch_and_resource_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.zip"
    export_conformance_kit(source)
    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(source) as original, zipfile.ZipFile(tampered, "w") as output:
        for info in original.infolist():
            data = original.read(info.filename)
            output.writestr(info, b"changed" if info.filename == "README.md" else data)
    report = verify_conformance_kit(tampered)
    assert report["mismatched"] == ["README.md"]

    oversized = tmp_path / "oversized.zip"
    with zipfile.ZipFile(oversized, "w") as archive:
        archive.writestr("manifest.json", canonical_json_bytes({"entries": []}))
    monkeypatch.setattr(conformance_module, "_MAX_UNCOMPRESSED", 1)
    with pytest.raises(FormatError, match="too large"):
        verify_conformance_kit(oversized)

    info = zipfile.ZipInfo("payload")
    info.file_size = 1
    info.compress_size = 0
    with pytest.raises(FormatError, match="invalid compression"):
        conformance_module._validated_members([info])


def test_conformance_cli_round_trip(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "kit.zip"
    assert main(["conformance", "export", str(path)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["verification"]["accepted"] is True
    assert main(["conformance", "verify", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "pass"
