# SPDX-License-Identifier: Apache-2.0
"""Bounded, non-executing material loading and generation fingerprinting."""

from __future__ import annotations

import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.intake.contracts import InputDescriptor, InputKind, SourceClass, TargetProfile
from sova.intake.model import GenerationState, MaterialFingerprint

if TYPE_CHECKING:
    from collections.abc import Mapping

_MAX_FILE_BYTES = 8 * 1024 * 1024
_MAX_BULK_FILE_BYTES = 64 * 1024 * 1024
_MAX_TREE_FILES = 10_000
_MAX_TREE_BYTES = 64 * 1024 * 1024
_IGNORED_PARTS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "__pycache__",
    "browser-profiles",
    "client-data",
    "confidential",
    "node_modules",
    "private",
    "receipts",
    "traces",
}
_MEDIA_TYPES = {
    InputKind.HTML: "text/html",
    InputKind.WEB_INVENTORY: "application/json",
    InputKind.HAR: "application/json",
    InputKind.OPENAPI: "application/json",
    InputKind.GRAPHQL_SCHEMA: "text/plain",
    InputKind.GRPC_DESCRIPTOR: "application/json",
    InputKind.POSTMAN: "application/json",
    InputKind.SOURCE_TREE: "application/vnd.sova.source-tree",
    InputKind.ARCHIVE: "application/octet-stream",
    InputKind.SBOM: "application/json",
    InputKind.LOCKFILE: "text/plain",
    InputKind.OCI_MANIFEST: "application/json",
    InputKind.OCI_CONFIG: "application/json",
    InputKind.OCI_INVENTORY: "application/json",
    InputKind.NETWORK_INVENTORY: "application/json",
    InputKind.TLS_REPORT: "application/json",
    InputKind.PROCESS_INVENTORY: "application/json",
    InputKind.ACCESSIBILITY_TREE: "application/json",
    InputKind.AGENT_MANIFEST: "application/json",
    InputKind.MCP_MANIFEST: "application/json",
    InputKind.A2A_CARD: "application/json",
    InputKind.RUNTIME_OBSERVATIONS: "application/json",
}


@dataclass(frozen=True, slots=True)
class LoadedMaterial:
    """One input loaded without executing or extracting it to disk."""

    descriptor: InputDescriptor
    path: Path
    start_digest: str
    payload: bytes | None
    files: dict[str, bytes]


@dataclass(frozen=True, slots=True)
class MaterialLoadResult:
    """Loaded materials plus explicit missing/error state."""

    materials: tuple[LoadedMaterial, ...]
    fingerprints: tuple[MaterialFingerprint, ...]
    errors: tuple[dict[str, str], ...]


def describe_material(
    path: Path,
    *,
    identifier: str,
    kind: InputKind,
    source_class: SourceClass = SourceClass.SUPPLIED,
    required: bool = True,
) -> InputDescriptor:
    """Create a content-addressed portable descriptor for one local material."""
    resolved = path.resolve(strict=True)
    digest = fingerprint_material_path(resolved, kind=kind)
    return InputDescriptor(
        id=identifier,
        kind=kind,
        source_class=source_class,
        logical_locator=resolved.name,
        media_type=_MEDIA_TYPES[kind],
        expected_digest=digest,
        required=required,
    )


def fingerprint_material_path(path: Path, *, kind: InputKind) -> str:
    """Fingerprint a file or a bounded source tree without following symlinks."""
    if path.is_symlink():
        raise FormatError("SOVA-INTAKE-MATERIAL-SYMLINK", "material path cannot be a symlink")
    if kind == InputKind.SOURCE_TREE:
        if not path.is_dir():
            raise FormatError(
                "SOVA-INTAKE-MATERIAL-TYPE", "source-tree material must be a directory"
            )
        files = _read_tree(path)
        return sha256_digest(
            canonical_json_bytes(
                [
                    {"path": relative, "digest": sha256_digest(content), "size": len(content)}
                    for relative, content in sorted(files.items())
                ]
            )
        )
    if not path.is_file():
        raise FormatError("SOVA-INTAKE-MATERIAL-TYPE", "material must be one real file")
    maximum = (
        _MAX_BULK_FILE_BYTES if kind in {InputKind.HAR, InputKind.ARCHIVE} else _MAX_FILE_BYTES
    )
    if path.stat().st_size > maximum:
        raise FormatError("SOVA-INTAKE-MATERIAL-SIZE", "material exceeds its byte limit")
    return sha256_digest(path.read_bytes())


def load_profile_materials(
    profile: TargetProfile,
    bindings: Mapping[str, Path],
    *,
    active_observations_authorized: bool = False,
) -> MaterialLoadResult:
    """Load exact profile inputs while preserving missing and mismatch states."""
    declared = {item.id for item in profile.inputs}
    unknown_bindings = sorted(set(bindings) - declared)
    if unknown_bindings:
        raise FormatError(
            "SOVA-INTAKE-MATERIAL-BINDING",
            "material binding references an unknown input",
            details={"inputIds": unknown_bindings},
        )
    materials: list[LoadedMaterial] = []
    fingerprints: list[MaterialFingerprint] = []
    errors: list[dict[str, str]] = []
    for descriptor in profile.inputs:
        if descriptor.source_class == SourceClass.ACTIVE and not active_observations_authorized:
            errors.append(
                {
                    "inputId": descriptor.id,
                    "code": "SOVA-INTAKE-ACTIVE-AUTHORIZATION",
                    "message": "active observation import requires explicit authorization",
                }
            )
            fingerprints.append(
                MaterialFingerprint(
                    descriptor.id,
                    descriptor.expected_digest,
                    None,
                    None,
                    GenerationState.INCOMPLETE,
                    "active-observation-authorization-missing",
                )
            )
            continue
        path = bindings.get(descriptor.id)
        if path is None:
            errors.append(
                {
                    "inputId": descriptor.id,
                    "code": "SOVA-INTAKE-MATERIAL-MISSING",
                    "message": "required material is not bound"
                    if descriptor.required
                    else "optional material is not bound",
                }
            )
            fingerprints.append(
                MaterialFingerprint(
                    descriptor.id,
                    descriptor.expected_digest,
                    None,
                    None,
                    GenerationState.INCOMPLETE,
                    "required-material-missing"
                    if descriptor.required
                    else "optional-material-missing",
                )
            )
            continue
        try:
            resolved = path.resolve(strict=True)
            start_digest = fingerprint_material_path(resolved, kind=descriptor.kind)
            if start_digest != descriptor.expected_digest:
                fingerprints.append(
                    MaterialFingerprint(
                        descriptor.id,
                        descriptor.expected_digest,
                        start_digest,
                        start_digest,
                        GenerationState.DRIFT,
                        "material-does-not-match-profile",
                    )
                )
                errors.append(
                    {
                        "inputId": descriptor.id,
                        "code": "SOVA-INTAKE-MATERIAL-DRIFT",
                        "message": "material does not match the profile digest",
                    }
                )
                continue
            payload: bytes | None = None
            files: dict[str, bytes] = {}
            if descriptor.kind == InputKind.SOURCE_TREE:
                files = _read_tree(resolved)
            else:
                payload = resolved.read_bytes()
                if descriptor.kind == InputKind.ARCHIVE:
                    files = _read_archive(resolved)
            materials.append(
                LoadedMaterial(
                    descriptor=descriptor,
                    path=resolved,
                    start_digest=start_digest,
                    payload=payload,
                    files=files,
                )
            )
        except (FormatError, OSError, tarfile.TarError, zipfile.BadZipFile) as error:
            fingerprints.append(
                MaterialFingerprint(
                    descriptor.id,
                    descriptor.expected_digest,
                    None,
                    None,
                    GenerationState.INCOMPLETE,
                    "material-load-failed",
                )
            )
            errors.append(
                {
                    "inputId": descriptor.id,
                    "code": error.issue.code
                    if isinstance(error, FormatError)
                    else "SOVA-INTAKE-IO",
                    "message": error.issue.message
                    if isinstance(error, FormatError)
                    else type(error).__name__,
                }
            )
    return MaterialLoadResult(tuple(materials), tuple(fingerprints), tuple(errors))


def finalize_material_fingerprints(
    loaded: MaterialLoadResult,
) -> tuple[MaterialFingerprint, ...]:
    """Re-fingerprint loaded inputs after discovery and detect generation drift."""
    completed: list[MaterialFingerprint] = list(loaded.fingerprints)
    for material in loaded.materials:
        try:
            end_digest = fingerprint_material_path(material.path, kind=material.descriptor.kind)
        except (FormatError, OSError):
            completed.append(
                MaterialFingerprint(
                    material.descriptor.id,
                    material.descriptor.expected_digest,
                    material.start_digest,
                    None,
                    GenerationState.DRIFT,
                    "material-unavailable-after-discovery",
                )
            )
            continue
        state = (
            GenerationState.MATCH
            if end_digest == material.start_digest == material.descriptor.expected_digest
            else GenerationState.DRIFT
        )
        completed.append(
            MaterialFingerprint(
                material.descriptor.id,
                material.descriptor.expected_digest,
                material.start_digest,
                end_digest,
                state,
                "stable-generation"
                if state == GenerationState.MATCH
                else "changed-during-discovery",
            )
        )
    return tuple(sorted(completed, key=lambda item: item.input_id))


def _read_tree(root: Path) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    total = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix().casefold()):
        relative = path.relative_to(root)
        if any(part.casefold() in _IGNORED_PARTS for part in relative.parts):
            continue
        if path.is_symlink() or not path.is_file():
            continue
        if len(result) >= _MAX_TREE_FILES:
            raise FormatError("SOVA-INTAKE-TREE-LIMIT", "source tree file limit exceeded")
        size = path.stat().st_size
        if size > _MAX_FILE_BYTES:
            continue
        total += size
        if total > _MAX_TREE_BYTES:
            raise FormatError("SOVA-INTAKE-TREE-LIMIT", "source tree byte limit exceeded")
        content = path.read_bytes()
        result[relative.as_posix()] = content
    return result


def _read_archive(path: Path) -> dict[str, bytes]:
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            result: dict[str, bytes] = {}
            total = 0
            for info in sorted(archive.infolist(), key=lambda item: item.filename.casefold()):
                if info.is_dir():
                    continue
                name = _safe_archive_name(info.filename)
                if info.file_size > _MAX_FILE_BYTES:
                    continue
                total += info.file_size
                if len(result) >= _MAX_TREE_FILES or total > _MAX_TREE_BYTES:
                    raise FormatError("SOVA-INTAKE-ARCHIVE-LIMIT", "archive limit exceeded")
                result[name] = archive.read(info)
            return result
    try:
        with tarfile.open(path, mode="r:*") as archive:
            result = {}
            total = 0
            for member in sorted(archive.getmembers(), key=lambda item: item.name.casefold()):
                if not member.isfile():
                    continue
                name = _safe_archive_name(member.name)
                if member.size > _MAX_FILE_BYTES:
                    continue
                total += member.size
                if len(result) >= _MAX_TREE_FILES or total > _MAX_TREE_BYTES:
                    raise FormatError("SOVA-INTAKE-ARCHIVE-LIMIT", "archive limit exceeded")
                handle = archive.extractfile(member)
                if handle is not None:
                    result[name] = handle.read()
            return result
    except tarfile.ReadError as error:
        raise FormatError("SOVA-INTAKE-ARCHIVE", "unsupported or malformed archive") from error


def _safe_archive_name(raw: str) -> str:
    candidate = PurePosixPath(raw.replace("\\", "/"))
    if candidate.is_absolute() or ".." in candidate.parts or "\x00" in raw:
        raise FormatError("SOVA-INTAKE-ARCHIVE-PATH", "archive member path is unsafe")
    return candidate.as_posix()


__all__ = [
    "LoadedMaterial",
    "MaterialLoadResult",
    "describe_material",
    "finalize_material_fingerprints",
    "fingerprint_material_path",
    "load_profile_materials",
]
