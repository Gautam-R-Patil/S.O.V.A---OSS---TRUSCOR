# SPDX-License-Identifier: Apache-2.0
"""Deterministic local file-integrity baselines for SOVA self-checks."""

from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

_MAX_FILES = 8192
_MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024


def _relative_path(value: str) -> Path:
    if "\\" in value or "\x00" in value or value.startswith("/"):
        raise FormatError("SOVA-SELF-CHECK-PATH", "path must be normalized relative POSIX")
    relative = PurePosixPath(value)
    if str(relative) != value or any(part in {"", ".", ".."} for part in relative.parts):
        raise FormatError("SOVA-SELF-CHECK-PATH", "path must be normalized relative POSIX")
    return Path(*relative.parts)


def build_integrity_manifest(root: Path, paths: tuple[str, ...]) -> dict[str, Any]:
    """Create a versionable hash baseline without signing or identity claims."""
    root = root.resolve()
    if not root.is_dir() or not paths:
        raise FormatError("SOVA-SELF-CHECK-INPUT", "root and at least one path are required")
    if len(paths) > _MAX_FILES or len(paths) != len(set(paths)):
        raise FormatError("SOVA-SELF-CHECK-INPUT", "paths exceed limits or contain duplicates")
    files: list[dict[str, Any]] = []
    total = 0
    for value in sorted(paths):
        relative = _relative_path(value)
        target = root / relative
        resolved = target.resolve()
        if root not in resolved.parents or not target.is_file() or target.is_symlink():
            raise FormatError("SOVA-SELF-CHECK-FILE", "baseline path is missing or unsafe")
        data = target.read_bytes()
        total += len(data)
        if total > _MAX_TOTAL_BYTES:
            raise FormatError("SOVA-SELF-CHECK-LIMIT", "baseline exceeds byte limit")
        files.append({"path": value, "size": len(data), "digest": sha256_digest(data)})
    document = {
        "artifactType": "sova.integrity-manifest",
        "schemaVersion": "0.1.0",
        "files": files,
        "rootStored": False,
        "signaturePresent": False,
        "identityClaim": False,
        "limitations": [
            "The baseline must be protected independently; an attacker who can replace it "
            "can hide changes."
        ],
    }
    document["manifestDigest"] = sha256_digest(canonical_json_bytes(document))
    return document


def verify_integrity_manifest(root: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    """Compare current files with one explicit baseline and report every mismatch."""
    root = root.resolve()
    raw_files = manifest.get("files")
    declared_digest = manifest.get("manifestDigest")
    unsigned = dict(manifest)
    unsigned.pop("manifestDigest", None)
    if (
        manifest.get("artifactType") != "sova.integrity-manifest"
        or manifest.get("schemaVersion") != "0.1.0"
        or not isinstance(raw_files, list)
        or not isinstance(declared_digest, str)
        or sha256_digest(canonical_json_bytes(unsigned)) != declared_digest
    ):
        raise FormatError("SOVA-SELF-CHECK-MANIFEST", "integrity manifest is malformed")
    changes: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in raw_files:
        if not isinstance(row, dict):
            raise FormatError("SOVA-SELF-CHECK-MANIFEST", "file entries must be objects")
        value = row.get("path")
        size = row.get("size")
        digest = row.get("digest")
        if (
            not isinstance(value, str)
            or value in seen
            or not isinstance(size, int)
            or isinstance(size, bool)
            or not isinstance(digest, str)
        ):
            raise FormatError("SOVA-SELF-CHECK-MANIFEST", "file entry is malformed")
        seen.add(value)
        relative = _relative_path(value)
        target = root / relative
        if not target.is_file() or target.is_symlink():
            changes.append({"path": value, "state": "missing"})
            continue
        data = target.read_bytes()
        if len(data) != size or sha256_digest(data) != digest:
            changes.append(
                {
                    "path": value,
                    "state": "changed",
                    "currentSize": len(data),
                    "currentDigest": sha256_digest(data),
                }
            )
    return {
        "artifactType": "sova.integrity-report",
        "schemaVersion": "0.1.0",
        "status": "failed" if changes else "passed",
        "checkedFiles": len(raw_files),
        "changes": changes,
        "baselineDigest": declared_digest,
        "signatureVerified": False,
        "identityVerified": False,
        "newSecurityEvidence": False,
    }


__all__ = ["build_integrity_manifest", "verify_integrity_manifest"]
