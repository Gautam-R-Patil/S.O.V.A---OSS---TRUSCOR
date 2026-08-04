# SPDX-License-Identifier: Apache-2.0
"""Deterministic, independently implementable SOVA compatibility kit."""

from __future__ import annotations

import importlib.resources
import stat
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from sova import __version__
from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError

_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
_MAX_ENTRIES = 256
_MAX_UNCOMPRESSED = 32 * 1024 * 1024
_MAX_RATIO = 1000


def _entry(name: str, data: bytes) -> dict[str, Any]:
    return {
        "path": name,
        "sha256": sha256_digest(data),
        "size": len(data),
    }


def _kit_files() -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    schema_root = importlib.resources.files("sova.schemas")
    for resource in sorted(schema_root.iterdir(), key=lambda item: item.name):
        if resource.name.endswith(".schema.json"):
            parsed = strict_json_loads(resource.read_bytes(), max_bytes=2 * 1024 * 1024)
            files[f"schemas/{resource.name}"] = canonical_json_bytes(parsed) + b"\n"
    canonical_input = {"z": 1, "a": "SOVA", "extensions": {"x-example": [True, None]}}
    canonical = canonical_json_bytes(canonical_input)
    files["vectors/canonical-json.json"] = (
        canonical_json_bytes(
            {
                "artifactType": "sova.conformance-vector",
                "schemaVersion": "0.1.0",
                "operation": "canonical-json",
                "input": canonical_input,
                "expectedUtf8Hex": canonical.hex(),
                "expectedSha256": sha256_digest(canonical),
            }
        )
        + b"\n"
    )
    files["vectors/unknown-extension-roundtrip.json"] = (
        canonical_json_bytes(
            {
                "artifactType": "sova.conformance-vector",
                "schemaVersion": "0.1.0",
                "operation": "preserve-unknown-extension",
                "input": {
                    "schemaVersion": "0.1.0",
                    "extensions": {"org.example/future": {"value": "preserve-exactly"}},
                },
                "expected": {"extensions": {"org.example/future": {"value": "preserve-exactly"}}},
            }
        )
        + b"\n"
    )
    files["README.md"] = (
        b"# SOVA conformance kit\n\n"
        b"This deterministic kit contains the public experimental schemas and portable "
        b"golden vectors required to implement SOVA parsing and canonicalization without "
        b"using the Python package. Passing the kit establishes only the tested format "
        b"contracts; it does not establish behavioral, security, or executor equivalence.\n"
    )
    return files


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, _ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    return info


def export_conformance_kit(destination: Path) -> dict[str, Any]:
    """Export schemas and golden vectors as a byte-reproducible ZIP archive."""
    destination = destination.resolve()
    files = _kit_files()
    manifest = {
        "artifactType": "sova.conformance-kit",
        "schemaVersion": "0.1.0",
        "sovaVersion": __version__,
        "formatStatus": "experimental",
        "compatibilityClaim": "tested-schema-and-vector-conformance-only",
        "entries": [_entry(name, files[name]) for name in sorted(files)],
    }
    payloads = {**files, "manifest.json": canonical_json_bytes(manifest) + b"\n"}
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w") as archive:
        for name in sorted(payloads):
            archive.writestr(_zip_info(name), payloads[name])
    verification = verify_conformance_kit(destination)
    return {
        "artifactType": "sova.conformance-export-result",
        "schemaVersion": "0.1.0",
        "destination": str(destination),
        "entryCount": len(payloads),
        "archiveDigest": sha256_digest(destination.read_bytes()),
        "verification": verification,
        "networkUsed": False,
    }


def _safe_name(name: str) -> str:
    pure = PurePosixPath(name)
    if (
        not name
        or "\\" in name
        or pure.is_absolute()
        or ".." in pure.parts
        or pure.as_posix() != name
    ):
        raise FormatError("SOVA-CONFORMANCE-PATH", "conformance entry path is unsafe")
    return name


def _validated_members(infos: list[zipfile.ZipInfo]) -> set[str]:
    if not infos or len(infos) > _MAX_ENTRIES:
        raise FormatError("SOVA-CONFORMANCE-LIMIT", "conformance entry count is invalid")
    names: set[str] = set()
    folded_names: set[str] = set()
    total = 0
    for info in infos:
        name = _safe_name(info.filename)
        folded = name.casefold()
        if name in names or folded in folded_names or info.is_dir():
            raise FormatError("SOVA-CONFORMANCE-DUPLICATE", "entry is duplicated or a directory")
        names.add(name)
        folded_names.add(folded)
        total += info.file_size
        if total > _MAX_UNCOMPRESSED:
            raise FormatError("SOVA-CONFORMANCE-LIMIT", "conformance kit is too large")
        if info.file_size and info.compress_size == 0:
            raise FormatError("SOVA-CONFORMANCE-RATIO", "conformance entry has invalid compression")
        if info.compress_size and info.file_size / info.compress_size > _MAX_RATIO:
            raise FormatError("SOVA-CONFORMANCE-RATIO", "conformance entry compression is unsafe")
        if stat.S_ISLNK(info.external_attr >> 16):
            raise FormatError("SOVA-CONFORMANCE-SYMLINK", "conformance kit cannot contain links")
    return names


def _expected_members(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    entries = manifest.get("entries")
    if not isinstance(entries, list):
        raise FormatError("SOVA-CONFORMANCE-MANIFEST", "conformance manifest is malformed")
    expected: dict[str, dict[str, Any]] = {}
    folded_names: set[str] = set()
    for item in entries:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise FormatError("SOVA-CONFORMANCE-MANIFEST", "manifest entry is malformed")
        name = _safe_name(item["path"])
        folded = name.casefold()
        if name in expected or folded in folded_names:
            raise FormatError("SOVA-CONFORMANCE-DUPLICATE", "manifest path is duplicated")
        expected[name] = item
        folded_names.add(folded)
    return expected


def verify_conformance_kit(path: Path) -> dict[str, Any]:
    """Verify bounded ZIP structure, exact membership, bytes, and content digests."""
    try:
        archive = zipfile.ZipFile(path, "r")
    except (OSError, zipfile.BadZipFile) as error:
        raise FormatError("SOVA-CONFORMANCE-ZIP", "conformance kit is not a valid ZIP") from error
    with archive:
        names = _validated_members(archive.infolist())
        if "manifest.json" not in names:
            raise FormatError("SOVA-CONFORMANCE-MANIFEST", "conformance manifest is missing")
        manifest = strict_json_loads(archive.read("manifest.json"), max_bytes=2 * 1024 * 1024)
        if not isinstance(manifest, dict):
            raise FormatError("SOVA-CONFORMANCE-MANIFEST", "conformance manifest is malformed")
        expected = _expected_members(manifest)
        actual = names - {"manifest.json"}
        missing = sorted(set(expected) - actual)
        undeclared = sorted(actual - set(expected))
        mismatched: list[str] = []
        for name in sorted(actual & set(expected)):
            data = archive.read(name)
            if expected[name].get("size") != len(data) or expected[name].get(
                "sha256"
            ) != sha256_digest(data):
                mismatched.append(name)
        accepted = not missing and not undeclared and not mismatched
        return {
            "artifactType": "sova.conformance-verification",
            "schemaVersion": "0.1.0",
            "status": "pass" if accepted else "fail",
            "accepted": accepted,
            "entryCount": len(actual),
            "missing": missing,
            "undeclared": undeclared,
            "mismatched": mismatched,
            "compatibilityClaim": manifest.get("compatibilityClaim"),
            "offline": True,
        }


__all__ = ["export_conformance_kit", "verify_conformance_kit"]
