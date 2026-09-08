# SPDX-License-Identifier: Apache-2.0
"""Registry snapshot and empty-root restore tests."""

from __future__ import annotations

import zipfile
from io import BytesIO
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from sova.formats import FormatError, canonical_json_bytes, sha256_digest
from sova.registry import backup as backup_module
from sova.registry.backup import (
    RegistryBackupLimits,
    create_registry_backup,
    restore_registry_backup,
    verify_registry_backup,
)


def _source(root: Path) -> Path:
    source = root / "source"
    (source / "cas").mkdir(parents=True)
    (source / "index.json").write_text("{}", encoding="utf-8")
    (source / "cas" / "object").write_bytes(b"content")
    return source


def _write_manifest_archive(path: Path, manifest: object, files: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("registry-backup-manifest.json", canonical_json_bytes(manifest))
        for name, raw in files.items():
            archive.writestr(name, raw)


def test_registry_backup_is_deterministic_verified_and_restorable(tmp_path: Path) -> None:
    source = _source(tmp_path)
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    receipt = create_registry_backup(source, first)
    create_registry_backup(source, second)
    assert first.read_bytes() == second.read_bytes()
    assert receipt["productionBackupReceipt"] is False
    assert verify_registry_backup(first)["status"] == "pass"
    destination = tmp_path / "restore"
    destination.mkdir()
    restored = restore_registry_backup(first, destination)
    assert restored["restoredFiles"] == 2
    assert (destination / "cas" / "object").read_bytes() == b"content"


def test_registry_backup_rejects_existing_inside_empty_and_oversize_destinations(
    tmp_path: Path,
) -> None:
    source = _source(tmp_path)
    existing = tmp_path / "existing.zip"
    existing.write_bytes(b"exists")
    with pytest.raises(FormatError, match="already exists"):
        create_registry_backup(source, existing)
    with pytest.raises(FormatError, match="outside"):
        create_registry_backup(source, source / "backup.zip")
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(FormatError, match="empty"):
        create_registry_backup(empty, tmp_path / "empty.zip")
    with pytest.raises(FormatError, match="byte limit"):
        create_registry_backup(
            source,
            tmp_path / "small.zip",
            limits=RegistryBackupLimits(10, 1, 10),
        )
    with pytest.raises(FormatError, match="positive"):
        RegistryBackupLimits(0, 1, 1)
    with pytest.raises(FormatError, match="real directory"):
        create_registry_backup(tmp_path / "missing", tmp_path / "missing-source.zip")
    with pytest.raises(FormatError, match="aggregate"):
        create_registry_backup(
            source,
            tmp_path / "few.zip",
            limits=RegistryBackupLimits(1, 100, 100),
        )


def test_registry_restore_rejects_nonempty_destination_and_invalid_archive(tmp_path: Path) -> None:
    source = _source(tmp_path)
    archive = tmp_path / "backup.zip"
    create_registry_backup(source, archive)
    destination = tmp_path / "restore"
    destination.mkdir()
    (destination / "occupied").write_text("x", encoding="utf-8")
    with pytest.raises(FormatError, match="real and empty"):
        restore_registry_backup(archive, destination)
    invalid = tmp_path / "invalid.zip"
    invalid.write_bytes(b"not-a-zip")
    with pytest.raises(FormatError, match="valid ZIP"):
        verify_registry_backup(invalid)


def test_registry_backup_rejects_path_traversal_missing_manifest_and_digest_tamper(
    tmp_path: Path,
) -> None:
    traversal = tmp_path / "traversal.zip"
    with zipfile.ZipFile(traversal, "w") as archive:
        archive.writestr("../escape", b"x")
    with pytest.raises(FormatError, match="unsafe"):
        verify_registry_backup(traversal)

    missing = tmp_path / "missing.zip"
    with zipfile.ZipFile(missing, "w") as archive:
        archive.writestr("data/value", b"x")
    with pytest.raises(FormatError, match="manifest"):
        verify_registry_backup(missing)

    source = _source(tmp_path)
    original = tmp_path / "original.zip"
    create_registry_backup(source, original)
    tampered_stream = BytesIO()
    with zipfile.ZipFile(original, "r") as reader, zipfile.ZipFile(tampered_stream, "w") as writer:
        for info in reader.infolist():
            raw = reader.read(info)
            if info.filename == "data/index.json":
                raw = b"xx"
            writer.writestr(info, raw)
    tampered = tmp_path / "tampered.zip"
    tampered.write_bytes(tampered_stream.getvalue())
    with pytest.raises(FormatError, match="digest"):
        verify_registry_backup(tampered)


def test_registry_backup_rejects_manifest_shape_declarations_and_extra_content(
    tmp_path: Path,
) -> None:
    invalid_manifests: tuple[object, ...] = (
        [],
        {"artifactType": "wrong"},
        {
            "artifactType": "wrong",
            "schemaVersion": "0.1.0",
            "files": [],
            "encryptionAppliedByThisTool": False,
            "operatorEncryptionRequired": True,
        },
        {
            "artifactType": "sova.registry-backup-manifest",
            "schemaVersion": "0.1.0",
            "files": "bad",
            "encryptionAppliedByThisTool": False,
            "operatorEncryptionRequired": True,
        },
        {
            "artifactType": "sova.registry-backup-manifest",
            "schemaVersion": "wrong",
            "files": [],
            "encryptionAppliedByThisTool": False,
            "operatorEncryptionRequired": True,
        },
        {
            "artifactType": "sova.registry-backup-manifest",
            "schemaVersion": "0.1.0",
            "files": [],
            "encryptionAppliedByThisTool": True,
            "operatorEncryptionRequired": False,
        },
    )
    for index, manifest in enumerate(invalid_manifests):
        path = tmp_path / f"invalid-manifest-{index}.zip"
        _write_manifest_archive(path, manifest, {})
        with pytest.raises(FormatError):
            verify_registry_backup(path)

    base = {
        "artifactType": "sova.registry-backup-manifest",
        "schemaVersion": "0.1.0",
        "files": [],
        "encryptionAppliedByThisTool": False,
        "operatorEncryptionRequired": True,
    }
    bad_entry = dict(base)
    bad_entry["files"] = [{"path": "value", "size": 1}]
    bad_type = dict(base)
    bad_type["files"] = [{"path": "value", "size": True, "digest": sha256_digest(b"x")}]
    negative_size = dict(base)
    negative_size["files"] = [{"path": "value", "size": -1, "digest": sha256_digest(b"x")}]
    bad_digest = dict(base)
    bad_digest["files"] = [{"path": "value", "size": 1, "digest": "sha256:" + ("z" * 64)}]
    duplicate = dict(base)
    entry = {"path": "value", "size": 1, "digest": sha256_digest(b"x")}
    duplicate["files"] = [entry, entry]
    mismatch = dict(base)
    mismatch["files"] = [entry]
    cases: tuple[tuple[dict[str, object], dict[str, bytes]], ...] = (
        (bad_entry, {}),
        (bad_type, {}),
        (negative_size, {"data/value": b"x"}),
        (bad_digest, {"data/value": b"x"}),
        (duplicate, {"data/value": b"x"}),
        (mismatch, {"unexpected": b"x"}),
    )
    for index, (manifest, files) in enumerate(cases):
        path = tmp_path / f"bad-declaration-{index}.zip"
        _write_manifest_archive(path, manifest, files)
        with pytest.raises(FormatError):
            verify_registry_backup(path)


def test_registry_backup_rejects_member_limits_duplicates_and_publication_race(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    too_many = tmp_path / "too-many.zip"
    with zipfile.ZipFile(too_many, "w") as archive:
        archive.writestr("registry-backup-manifest.json", b"{}")
        archive.writestr("data/one", b"1")
        archive.writestr("data/two", b"2")
    with pytest.raises(FormatError, match="too many"):
        verify_registry_backup(too_many, limits=RegistryBackupLimits(1, 100, 100))

    duplicate = tmp_path / "duplicate.zip"
    with (
        pytest.warns(UserWarning, match="Duplicate name"),
        zipfile.ZipFile(duplicate, "w") as archive,
    ):
        archive.writestr("same", b"1")
        archive.writestr("same", b"2")
    with pytest.raises(FormatError, match="duplicated"):
        verify_registry_backup(duplicate)

    oversized = tmp_path / "oversized.zip"
    with zipfile.ZipFile(oversized, "w") as archive:
        archive.writestr("registry-backup-manifest.json", b"{}")
    with pytest.raises(FormatError, match="byte limit"):
        verify_registry_backup(oversized, limits=RegistryBackupLimits(10, 1, 100))

    source = _source(tmp_path)

    def collide(_source: object, _destination: object) -> None:
        raise FileExistsError

    monkeypatch.setattr("sova.registry.backup.os.link", collide)
    with pytest.raises(FormatError, match="already exists"):
        create_registry_backup(source, tmp_path / "race.zip")


def test_restore_validates_one_immutable_archive_snapshot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = _source(tmp_path)
    archive = tmp_path / "backup.zip"
    create_registry_backup(source, archive)
    destination = tmp_path / "restore"
    destination.mkdir()
    original = backup_module._read_backup
    calls = 0

    def counted_read(
        archive_path: Path, limits: RegistryBackupLimits
    ) -> tuple[dict[str, object], dict[str, bytes], str]:
        nonlocal calls
        calls += 1
        return original(archive_path, limits)

    monkeypatch.setattr(backup_module, "_read_backup", counted_read)
    restore_registry_backup(archive, destination)
    assert calls == 1


def test_backup_read_is_bounded_by_file_size_not_the_configured_ceiling(
    tmp_path: Path,
) -> None:
    """A large declared ceiling must not force a large allocation for a small archive.

    ``_read_backup`` previously issued ``read(maximum_total_bytes + overhead + 1)``.
    A bounded read preallocates its full request, so a kilobyte archive demanded
    gigabytes and raised an untyped ``MemoryError`` out of the restore path on any
    memory-constrained host. A one-terabyte ceiling makes that regression fail
    deterministically regardless of how much memory the running machine has.
    """
    source = _source(tmp_path)
    archive = tmp_path / "backup.zip"
    create_registry_backup(source, archive)
    assert archive.stat().st_size < 64 * 1024

    terabyte_ceiling = RegistryBackupLimits(
        maximum_files=100_000,
        maximum_file_bytes=256 * 1024 * 1024,
        maximum_total_bytes=1024**4,
    )
    assert verify_registry_backup(archive, limits=terabyte_ceiling)["status"] == "pass"

    destination = tmp_path / "restore"
    destination.mkdir()
    restored = restore_registry_backup(archive, destination, limits=terabyte_ceiling)
    assert restored["restoredFiles"] == 2


def test_backup_rejects_an_oversized_archive_before_reading_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An archive larger than the ceiling fails closed with a typed limit error."""
    source = _source(tmp_path)
    archive = tmp_path / "backup.zip"
    create_registry_backup(source, archive)

    monkeypatch.setattr(backup_module, "_MAX_ARCHIVE_OVERHEAD_BYTES", 0)
    tiny_ceiling = RegistryBackupLimits(
        maximum_files=100_000,
        maximum_file_bytes=256 * 1024 * 1024,
        maximum_total_bytes=8,
    )
    with pytest.raises(FormatError) as rejection:
        verify_registry_backup(archive, limits=tiny_ceiling)
    assert rejection.value.issue.code == "SOVA-REGISTRY-BACKUP-LIMIT"
