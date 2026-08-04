# SPDX-License-Identifier: Apache-2.0
"""Topic 26 deterministic release artifact contracts."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

import sova.release as release_module
from sova.cli import main
from sova.formats.errors import FormatError
from sova.release import (
    generate_cyclonedx_sbom,
    verify_checksums,
    write_checksums,
    write_cyclonedx_sbom,
)

if TYPE_CHECKING:
    from pathlib import Path


def _lock(path: Path) -> Path:
    path.write_text(
        """version = 1
[[package]]
name = "alpha"
version = "1.2.3"
source = { registry = "https://pypi.org/simple" }
sdist = { hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
dependencies = [{ name = "beta" }]
[[package]]
name = "beta"
version = "2.0"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "dev-only"
version = "9"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "sova-oss"
version = "0.1.0a0"
source = { editable = "." }
dependencies = [{ name = "alpha" }]
""",
        encoding="utf-8",
    )
    return path


def test_runtime_sbom_is_deterministic_and_transitive(tmp_path: Path) -> None:
    lock = _lock(tmp_path / "uv.lock")
    first = generate_cyclonedx_sbom(lock)
    second = generate_cyclonedx_sbom(lock)
    assert first == second
    assert first["bomFormat"] == "CycloneDX"
    assert [item["name"] for item in first["components"]] == ["alpha", "beta"]
    assert "timestamp" not in first["metadata"]
    all_components = generate_cyclonedx_sbom(lock, scope="all")["components"]
    assert [item["name"] for item in all_components] == ["alpha", "beta", "dev-only"]


def test_sbom_writer_uses_canonical_json(tmp_path: Path) -> None:
    lock = _lock(tmp_path / "uv.lock")
    destination = tmp_path / "dist" / "sova.cdx.json"
    report = write_cyclonedx_sbom(lock, destination)
    assert report["componentCount"] == 2
    parsed = json.loads(destination.read_text(encoding="utf-8"))
    assert parsed["specVersion"] == "1.6"


def test_checksums_detect_tampering_missing_and_extra_files(tmp_path: Path) -> None:
    root = tmp_path / "dist"
    root.mkdir()
    (root / "a.whl").write_bytes(b"wheel")
    (root / "b.tar.gz").write_bytes(b"source")
    manifest = root / "SHA256SUMS"
    write_checksums(root, manifest)
    assert verify_checksums(root, manifest)["status"] == "pass"

    (root / "a.whl").write_bytes(b"tampered")
    assert verify_checksums(root, manifest)["mismatched"] == ["a.whl"]
    (root / "a.whl").write_bytes(b"wheel")
    (root / "extra.txt").write_text("extra", encoding="utf-8")
    assert verify_checksums(root, manifest)["undeclared"] == ["extra.txt"]
    (root / "extra.txt").unlink()
    (root / "b.tar.gz").unlink()
    assert verify_checksums(root, manifest)["missing"] == ["b.tar.gz"]


def test_checksum_manifest_refuses_traversal_and_duplicate(tmp_path: Path) -> None:
    root = tmp_path / "dist"
    root.mkdir()
    (root / "artifact").write_text("ok", encoding="utf-8")
    manifest = root / "SHA256SUMS"
    digest = "0" * 64
    manifest.write_text(f"{digest}  ../outside\n", encoding="utf-8")
    with pytest.raises(FormatError, match="leaves"):
        verify_checksums(root, manifest)
    manifest.write_text(f"{digest}  artifact\n{digest}  artifact\n", encoding="utf-8")
    with pytest.raises(FormatError, match="duplicated"):
        verify_checksums(root, manifest)
    manifest.write_text(f"{digest}  artifact\n{digest}  ARTIFACT\n", encoding="utf-8")
    with pytest.raises(FormatError, match="duplicated"):
        verify_checksums(root, manifest)


def test_release_cli_round_trip(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    lock = _lock(tmp_path / "uv.lock")
    root = tmp_path / "dist"
    root.mkdir()
    sbom = root / "sova.cdx.json"
    sums = root / "SHA256SUMS"
    assert main(["release", "sbom", str(lock), str(sbom)]) == 0
    capsys.readouterr()
    assert main(["release", "checksums", str(root), str(sums)]) == 0
    capsys.readouterr()
    assert main(["release", "verify-checksums", str(root), str(sums)]) == 0
    assert json.loads(capsys.readouterr().out)["accepted"] is True


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("not = [toml", "could not be parsed"),
        ("version = 1", "package list is missing"),
        ("version = 1\npackage = [1]", "entry is malformed"),
        (
            'version = 1\n[[package]]\nname = "sova-oss"\nversion = "0.1"\n'
            'dependencies = [{ name = "missing" }]',
            "dependency is missing",
        ),
        (
            'version = 1\n[[package]]\nname = "alpha"\n[[package]]\n'
            'name = "sova-oss"\nversion = "0.1"\ndependencies = [{ name = "alpha" }]',
            "has no version",
        ),
    ],
)
def test_sbom_rejects_hostile_or_incomplete_locks(
    tmp_path: Path,
    content: str,
    message: str,
) -> None:
    lock = tmp_path / "uv.lock"
    lock.write_text(content, encoding="utf-8")
    with pytest.raises(FormatError, match=message):
        generate_cyclonedx_sbom(lock)


def test_sbom_rejects_scope_missing_root_and_missing_file(tmp_path: Path) -> None:
    lock = _lock(tmp_path / "uv.lock")
    with pytest.raises(FormatError, match="scope"):
        generate_cyclonedx_sbom(lock, scope="unknown")
    lock.write_text('version = 1\n[[package]]\nname = "alpha"\nversion = "1"', encoding="utf-8")
    with pytest.raises(FormatError, match="sova-oss"):
        generate_cyclonedx_sbom(lock)
    with pytest.raises(FormatError, match="could not be parsed"):
        generate_cyclonedx_sbom(tmp_path / "missing.lock")


def test_checksums_reject_invalid_roots_empty_trees_links_and_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(FormatError, match="directory"):
        write_checksums(tmp_path / "missing", tmp_path / "SHA256SUMS")
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(FormatError, match="no candidate"):
        write_checksums(empty, empty / "SHA256SUMS")

    root = tmp_path / "dist"
    root.mkdir()
    artifact = root / "artifact"
    artifact.write_text("payload", encoding="utf-8")
    original = type(artifact).is_symlink
    monkeypatch.setattr(
        type(artifact),
        "is_symlink",
        lambda path: path.name == "artifact" or original(path),
    )
    with pytest.raises(FormatError, match="symlinks"):
        write_checksums(root, root / "SHA256SUMS")
    monkeypatch.setattr(type(artifact), "is_symlink", original)
    monkeypatch.setattr(release_module, "_MAX_RELEASE_BYTES", 1)
    with pytest.raises(FormatError, match="limits"):
        write_checksums(root, root / "SHA256SUMS")


def test_checksum_verifier_rejects_malformed_manifest(tmp_path: Path) -> None:
    root = tmp_path / "dist"
    root.mkdir()
    (root / "artifact").write_text("ok", encoding="utf-8")
    manifest = root / "SHA256SUMS"
    manifest.write_text("not-a-checksum\n", encoding="utf-8")
    with pytest.raises(FormatError, match="malformed"):
        verify_checksums(root, manifest)
