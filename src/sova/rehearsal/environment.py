# SPDX-License-Identifier: Apache-2.0
"""Credential-stripping preparation of disposable rehearsal workspaces."""

from __future__ import annotations

import os
import re
from pathlib import Path

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.rehearsal.model import EnvironmentPreparation

_DENIED_DIRECTORIES = frozenset(
    {".git", ".hg", ".svn", ".venv", "node_modules", "private", "__pycache__"}
)
_SECRET_FILE = re.compile(
    r"(?:^\.env(?:\.|$)|credential|secret|token|cookie|\.pem$|\.key$|id_rsa)",
    re.IGNORECASE,
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?im)(api[_-]?key|authorization|cookie|credential|password|secret|token)"
    r"(\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_MAX_FILES = 4096
_MAX_FILE_BYTES = 8 * 1024 * 1024
_MAX_TOTAL_BYTES = 64 * 1024 * 1024


def _safe_destination(source: Path, destination: Path) -> None:
    if not source.is_dir():
        raise FormatError("SOVA-REHEARSE-SOURCE", "source must be an existing directory")
    if destination.exists():
        raise FormatError("SOVA-REHEARSE-DESTINATION", "destination must not already exist")
    if destination == source or source in destination.parents:
        raise FormatError(
            "SOVA-REHEARSE-DESTINATION",
            "rehearsal workspace must not be inside the source tree",
        )


def _sanitize_text(data: bytes) -> tuple[bytes, bool]:
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise FormatError(
            "SOVA-REHEARSE-BINARY",
            "binary content is not cloned by default",
        ) from error

    def replacement(match: re.Match[str]) -> str:
        label = re.sub(r"[^A-Za-z0-9]", "_", match.group(1)).upper()
        return f'{match.group(1)}{match.group(2)}"<SOVA-REDACTED:{label}>"'

    sanitized = _SECRET_ASSIGNMENT.sub(replacement, text)
    private_key_marker = "-----BEGIN " + "PRIVATE KEY-----"
    sanitized = sanitized.replace(private_key_marker, "<SOVA-REDACTED:PRIVATE_KEY>")
    return sanitized.encode("utf-8"), sanitized != text


def prepare_rehearsal_environment(  # noqa: PLR0915
    source: Path,
    destination: Path,
    *,
    substitutes: tuple[str, ...] = (
        "process",
        "database",
        "api",
        "network",
        "browser",
        "computer",
    ),
) -> EnvironmentPreparation:
    """Create a bounded, secret-stripped clone with inert substitute services."""
    source = source.resolve()
    destination = destination.resolve()
    _safe_destination(source, destination)
    destination.mkdir(parents=True)
    control = destination / ".sova-rehearsal"
    control.mkdir()
    omitted: list[dict[str, str]] = []
    fingerprint_rows: list[dict[str, str | int]] = []
    cloned = 0
    sanitized = 0
    total = 0
    for root, directories, files in os.walk(source, followlinks=False):
        root_path = Path(root)
        directories[:] = sorted(
            item
            for item in directories
            if item not in _DENIED_DIRECTORIES and not (root_path / item).is_symlink()
        )
        relative_root = root_path.relative_to(source)
        for name in sorted(files):
            original = root_path / name
            relative = (relative_root / name).as_posix()
            if original.is_symlink():
                omitted.append({"path": relative, "reason": "symbolic-link-omitted"})
                continue
            if _SECRET_FILE.search(name):
                omitted.append({"path": relative, "reason": "credential-shaped-file-omitted"})
                continue
            if cloned >= _MAX_FILES:
                raise FormatError(
                    "SOVA-REHEARSE-FILE-LIMIT",
                    "source exceeds clone file limit",
                )
            size = original.stat().st_size
            if size > _MAX_FILE_BYTES:
                omitted.append({"path": relative, "reason": "file-size-limit"})
                continue
            data = original.read_bytes()
            try:
                output, changed = _sanitize_text(data)
            except FormatError:
                omitted.append({"path": relative, "reason": "binary-file-omitted"})
                continue
            total += len(output)
            if total > _MAX_TOTAL_BYTES:
                raise FormatError(
                    "SOVA-REHEARSE-TOTAL-LIMIT",
                    "source exceeds clone byte limit",
                )
            target = destination / Path(relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(output)
            cloned += 1
            sanitized += int(changed)
            fingerprint_rows.append(
                {"path": relative, "size": len(data), "digest": sha256_digest(data)}
            )
    service_names = sorted(set(substitutes))
    service_descriptors = [
        {
            "id": name,
            "mode": "inert-ledger",
            "protocol": "sova-rehearsal/0.1",
            "dataPolicy": "empty-structure-synthetic-fixtures-only",
            "productionFallback": False,
        }
        for name in service_names
    ]
    substitute_document = {
        "artifactType": "sova.rehearsal-substitutes",
        "schemaVersion": "0.1.0",
        "services": service_names,
        "serviceDescriptors": service_descriptors,
        "productionReachable": False,
        "networkMode": "sink-only-substitute-ledger",
    }
    (control / "substitutes.json").write_bytes(canonical_json_bytes(substitute_document) + b"\n")
    source_fingerprint = sha256_digest(canonical_json_bytes(fingerprint_rows))
    marker = {
        "artifactType": "sova.rehearsal-workspace",
        "schemaVersion": "0.1.0",
        "sourceFingerprint": source_fingerprint,
        "sourcePathStored": False,
        "disposable": True,
        "clonedFileCount": cloned,
        "sanitizedFileCount": sanitized,
        "omitted": omitted,
        "substitutes": service_names,
        "isolationClaim": "filesystem-scoped-substitute-workspace-not-a-security-sandbox",
    }
    (control / "workspace.json").write_bytes(canonical_json_bytes(marker) + b"\n")
    return EnvironmentPreparation(
        workspace=str(destination),
        source_fingerprint=source_fingerprint,
        cloned_file_count=cloned,
        sanitized_file_count=sanitized,
        omitted=tuple(omitted),
        substitutes=tuple(service_names),
    )


__all__ = ["prepare_rehearsal_environment"]
