# SPDX-License-Identifier: Apache-2.0
"""Deterministic, bounded Registry snapshots and fail-closed empty-root restore."""

from __future__ import annotations

import io
import os
import stat
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError

_MANIFEST = "registry-backup-manifest.json"
_FIXED_TIME = (1980, 1, 1, 0, 0, 0)
_MAX_ARCHIVE_OVERHEAD_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class RegistryBackupLimits:
    maximum_files: int = 100_000
    maximum_file_bytes: int = 256 * 1024 * 1024
    maximum_total_bytes: int = 4 * 1024 * 1024 * 1024

    def __post_init__(self) -> None:
        values = (self.maximum_files, self.maximum_file_bytes, self.maximum_total_bytes)
        if any(isinstance(value, bool) or value <= 0 for value in values):
            raise FormatError("SOVA-REGISTRY-BACKUP-LIMIT", "backup limits must be positive")


_DEFAULT_LIMITS = RegistryBackupLimits()


def _safe_name(name: str) -> str:
    path = PurePosixPath(name)
    if (
        not name
        or "\x00" in name
        or "\\" in name
        or ":" in name
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or str(path) != name
    ):
        raise FormatError("SOVA-REGISTRY-BACKUP-PATH", "backup member path is unsafe")
    return name


def _source_rows(source: Path, limits: RegistryBackupLimits) -> list[tuple[str, bytes]]:
    source = source.resolve()
    if not source.is_dir() or source.is_symlink():
        raise FormatError("SOVA-REGISTRY-BACKUP-SOURCE", "backup source must be a real directory")
    rows: list[tuple[str, bytes]] = []
    total = 0
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise FormatError("SOVA-REGISTRY-BACKUP-SYMLINK", "backup source cannot contain links")
        if not path.is_file():
            continue
        relative = _safe_name(path.relative_to(source).as_posix())
        size = path.stat().st_size
        if size > limits.maximum_file_bytes:
            raise FormatError("SOVA-REGISTRY-BACKUP-LIMIT", "backup member exceeds byte limit")
        total += size
        if len(rows) + 1 > limits.maximum_files or total > limits.maximum_total_bytes:
            raise FormatError("SOVA-REGISTRY-BACKUP-LIMIT", "backup exceeds aggregate limits")
        rows.append((relative, path.read_bytes()))
    if not rows:
        raise FormatError("SOVA-REGISTRY-BACKUP-EMPTY", "Registry backup source is empty")
    return rows


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=_FIXED_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100400 << 16
    return info


def create_registry_backup(
    source: Path,
    destination: Path,
    *,
    limits: RegistryBackupLimits = _DEFAULT_LIMITS,
) -> dict[str, Any]:
    """Create an immutable local snapshot; operators must encrypt it before off-host storage."""
    resolved_source = source.resolve()
    resolved_destination = destination.resolve()
    try:
        resolved_destination.relative_to(resolved_source)
    except ValueError:
        pass
    else:
        raise FormatError("SOVA-REGISTRY-BACKUP-DESTINATION", "backup must stay outside source")
    if resolved_destination.exists():
        raise FormatError("SOVA-REGISTRY-BACKUP-DESTINATION", "backup destination already exists")
    resolved_destination.parent.mkdir(parents=True, exist_ok=True)
    rows = _source_rows(resolved_source, limits)
    manifest = {
        "artifactType": "sova.registry-backup-manifest",
        "schemaVersion": "0.1.0",
        "files": [
            {"path": name, "size": len(raw), "digest": sha256_digest(raw)} for name, raw in rows
        ],
        "encryptionAppliedByThisTool": False,
        "operatorEncryptionRequired": True,
    }
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".sova-registry-backup-", suffix=".tmp", dir=resolved_destination.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with zipfile.ZipFile(temporary, mode="w") as archive:
            archive.writestr(_zip_info(_MANIFEST), canonical_json_bytes(manifest))
            for name, raw in rows:
                archive.writestr(_zip_info(f"data/{name}"), raw)
        with temporary.open("rb+") as stream:
            os.fsync(stream.fileno())
        try:
            os.link(temporary, resolved_destination)
        except FileExistsError as error:
            raise FormatError(
                "SOVA-REGISTRY-BACKUP-DESTINATION", "backup destination already exists"
            ) from error
    finally:
        temporary.unlink(missing_ok=True)
    return {
        "artifactType": "sova.registry-backup-result",
        "schemaVersion": "0.1.0",
        "fileCount": len(rows),
        "archiveDigest": sha256_digest(resolved_destination.read_bytes()),
        "encrypted": False,
        "productionBackupReceipt": False,
    }


def _read_backup(
    archive_path: Path, limits: RegistryBackupLimits
) -> tuple[dict[str, Any], dict[str, bytes], str]:
    maximum_archive_bytes = limits.maximum_total_bytes + _MAX_ARCHIVE_OVERHEAD_BYTES
    try:
        with archive_path.open("rb") as stream:
            # A bounded ``read`` preallocates its full request, so sizing the request
            # from the configured ceiling would demand gigabytes for a kilobyte
            # archive and fail with an untyped MemoryError. Measure the open
            # descriptor instead, reject an oversized archive before allocating, and
            # request only one byte beyond what the file actually holds.
            observed_bytes = os.fstat(stream.fileno()).st_size
            if observed_bytes > maximum_archive_bytes:
                raise FormatError("SOVA-REGISTRY-BACKUP-LIMIT", "backup archive exceeds byte limit")
            archive_bytes = stream.read(min(observed_bytes, maximum_archive_bytes) + 1)
    except OSError as error:
        raise FormatError("SOVA-REGISTRY-BACKUP-ZIP", "backup is not a valid ZIP") from error
    if len(archive_bytes) > maximum_archive_bytes:
        raise FormatError("SOVA-REGISTRY-BACKUP-LIMIT", "backup archive exceeds byte limit")
    try:
        archive = zipfile.ZipFile(io.BytesIO(archive_bytes), mode="r")
    except zipfile.BadZipFile as error:
        raise FormatError("SOVA-REGISTRY-BACKUP-ZIP", "backup is not a valid ZIP") from error
    with archive:
        infos = archive.infolist()
        if len(infos) > limits.maximum_files + 1:
            raise FormatError("SOVA-REGISTRY-BACKUP-LIMIT", "backup has too many members")
        names: set[str] = set()
        total = 0
        files: dict[str, bytes] = {}
        for info in infos:
            name = _safe_name(info.filename)
            if name in names or info.is_dir() or stat.S_ISLNK(info.external_attr >> 16):
                raise FormatError(
                    "SOVA-REGISTRY-BACKUP-MEMBER", "backup member is duplicated or unsafe"
                )
            names.add(name)
            if info.file_size > limits.maximum_file_bytes:
                raise FormatError("SOVA-REGISTRY-BACKUP-LIMIT", "backup member exceeds byte limit")
            total += info.file_size
            if total > limits.maximum_total_bytes:
                raise FormatError(
                    "SOVA-REGISTRY-BACKUP-LIMIT", "backup exceeds aggregate byte limit"
                )
            try:
                files[name] = archive.read(info)
            except (OSError, RuntimeError, zipfile.BadZipFile) as error:
                raise FormatError(
                    "SOVA-REGISTRY-BACKUP-ZIP", "backup member is unreadable"
                ) from error
    try:
        raw_manifest = files.pop(_MANIFEST)
    except KeyError as error:
        raise FormatError("SOVA-REGISTRY-BACKUP-MANIFEST", "backup manifest is missing") from error
    manifest = strict_json_loads(raw_manifest, max_bytes=16 * 1024 * 1024, max_items=1_000_000)
    if not isinstance(manifest, dict):
        raise FormatError("SOVA-REGISTRY-BACKUP-MANIFEST", "backup manifest must be an object")
    return manifest, files, sha256_digest(archive_bytes)


def _validated_backup(
    archive_path: Path, limits: RegistryBackupLimits
) -> tuple[dict[str, Any], dict[str, bytes]]:
    manifest, files, archive_digest = _read_backup(archive_path, limits)
    if set(manifest) != {
        "artifactType",
        "schemaVersion",
        "files",
        "encryptionAppliedByThisTool",
        "operatorEncryptionRequired",
    }:
        raise FormatError("SOVA-REGISTRY-BACKUP-MANIFEST", "backup manifest fields are invalid")
    if (
        manifest.get("artifactType") != "sova.registry-backup-manifest"
        or manifest.get("schemaVersion") != "0.1.0"
        or manifest.get("encryptionAppliedByThisTool") is not False
        or manifest.get("operatorEncryptionRequired") is not True
    ):
        raise FormatError("SOVA-REGISTRY-BACKUP-MANIFEST", "backup manifest type is invalid")
    declared = manifest.get("files")
    if not isinstance(declared, list) or not all(isinstance(item, dict) for item in declared):
        raise FormatError("SOVA-REGISTRY-BACKUP-MANIFEST", "backup file list is invalid")
    expected: dict[str, tuple[int, str]] = {}
    for item in declared:
        if set(item) != {"path", "size", "digest"}:
            raise FormatError("SOVA-REGISTRY-BACKUP-MANIFEST", "backup file entry is invalid")
        path = item["path"]
        size = item["size"]
        digest = item["digest"]
        if (
            not isinstance(path, str)
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or not isinstance(digest, str)
        ):
            raise FormatError(
                "SOVA-REGISTRY-BACKUP-MANIFEST", "backup file entry types are invalid"
            )
        name = _safe_name(path)
        if name in expected:
            raise FormatError("SOVA-REGISTRY-BACKUP-MANIFEST", "backup file is declared twice")
        expected[name] = (size, digest)
    actual = {
        name.removeprefix("data/"): raw for name, raw in files.items() if name.startswith("data/")
    }
    if len(actual) != len(files) or set(actual) != set(expected):
        raise FormatError("SOVA-REGISTRY-BACKUP-CONTENT", "backup content differs from manifest")
    for name, (size, digest) in expected.items():
        raw = actual[name]
        if len(raw) != size or sha256_digest(raw) != digest:
            raise FormatError("SOVA-REGISTRY-BACKUP-DIGEST", "backup content digest is invalid")
    return (
        {
            "artifactType": "sova.registry-backup-verification",
            "schemaVersion": "0.1.0",
            "status": "pass",
            "fileCount": len(expected),
            "archiveDigest": archive_digest,
            "encrypted": False,
            "productionRestoreReceipt": False,
        },
        actual,
    )


def verify_registry_backup(
    archive_path: Path, *, limits: RegistryBackupLimits = _DEFAULT_LIMITS
) -> dict[str, Any]:
    verification, _files = _validated_backup(archive_path, limits)
    return verification


def restore_registry_backup(
    archive_path: Path,
    destination: Path,
    *,
    limits: RegistryBackupLimits = _DEFAULT_LIMITS,
) -> dict[str, Any]:
    """Restore verified content only into an existing, empty, non-symlink directory."""
    root = destination.resolve()
    if not root.is_dir() or root.is_symlink() or any(root.iterdir()):
        raise FormatError(
            "SOVA-REGISTRY-RESTORE-DESTINATION", "restore destination must be real and empty"
        )
    verification, files = _validated_backup(archive_path, limits)
    restored = 0
    for relative, raw in sorted(files.items()):
        safe_relative = _safe_name(relative)
        candidate = (root / safe_relative).resolve()
        try:
            candidate.relative_to(root)
        except ValueError as error:
            raise FormatError(
                "SOVA-REGISTRY-RESTORE-PATH", "restore path leaves destination"
            ) from error
        candidate.parent.mkdir(parents=True, exist_ok=True)
        with candidate.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        restored += 1
    return {
        "artifactType": "sova.registry-restore-result",
        "schemaVersion": "0.1.0",
        "status": "pass",
        "restoredFiles": restored,
        "archiveDigest": verification["archiveDigest"],
        "syntheticOrOperatorEnvironment": True,
        "productionRestoreReceipt": False,
    }


__all__ = [
    "RegistryBackupLimits",
    "create_registry_backup",
    "restore_registry_backup",
    "verify_registry_backup",
]
