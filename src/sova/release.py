# SPDX-License-Identifier: Apache-2.0
"""Deterministic SBOM and release-checksum generation and verification."""

from __future__ import annotations

import hashlib
import re
import tomllib
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from sova import __version__
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from pathlib import Path

_CHECKSUM = re.compile(r"^(?P<digest>[0-9a-f]{64})  (?P<path>[^\r\n]+)$")
_MAX_RELEASE_FILES = 4096
_MAX_RELEASE_BYTES = 4 * 1024 * 1024 * 1024


def _packages(lock_path: Path) -> dict[str, dict[str, Any]]:
    try:
        document = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise FormatError("SOVA-SBOM-LOCK", "lockfile could not be parsed") from error
    raw = document.get("package")
    if not isinstance(raw, list):
        raise FormatError("SOVA-SBOM-LOCK", "lockfile package list is missing")
    packages: dict[str, dict[str, Any]] = {}
    for item in raw:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise FormatError("SOVA-SBOM-LOCK", "lockfile package entry is malformed")
        packages.setdefault(item["name"], item)
    return packages


def _dependency_names(package: dict[str, Any]) -> tuple[str, ...]:
    raw = package.get("dependencies", [])
    if not isinstance(raw, list):
        return ()
    return tuple(
        sorted(
            str(item["name"])
            for item in raw
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        )
    )


def _runtime_closure(packages: dict[str, dict[str, Any]], root: str) -> set[str]:
    selected: set[str] = set()
    pending = list(_dependency_names(packages[root]))
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        package = packages.get(name)
        if package is None:
            raise FormatError("SOVA-SBOM-LOCK", f"locked dependency is missing: {name}")
        selected.add(name)
        pending.extend(_dependency_names(package))
    return selected


def _component(name: str, package: dict[str, Any]) -> dict[str, Any]:
    version = package.get("version")
    if not isinstance(version, str):
        raise FormatError("SOVA-SBOM-LOCK", f"locked package has no version: {name}")
    result: dict[str, Any] = {
        "type": "library",
        "bom-ref": f"pkg:pypi/{quote(name)}@{quote(version)}",
        "name": name,
        "version": version,
        "purl": f"pkg:pypi/{quote(name)}@{quote(version)}",
    }
    source = package.get("source")
    if isinstance(source, dict) and isinstance(source.get("registry"), str):
        result["externalReferences"] = [{"type": "distribution", "url": str(source["registry"])}]
    archive = package.get("sdist")
    if not isinstance(archive, dict):
        wheels = package.get("wheels")
        archive = wheels[0] if isinstance(wheels, list) and wheels else None
    digest = archive.get("hash") if isinstance(archive, dict) else None
    if isinstance(digest, str) and digest.startswith("sha256:"):
        result["hashes"] = [{"alg": "SHA-256", "content": digest.removeprefix("sha256:")}]
    return result


def generate_cyclonedx_sbom(lock_path: Path, *, scope: str = "runtime") -> dict[str, Any]:
    """Generate a timestamp-free CycloneDX 1.6 SBOM from an exact uv lockfile."""
    if scope not in {"runtime", "all"}:
        raise FormatError("SOVA-SBOM-SCOPE", "SBOM scope must be runtime or all")
    lock_path = lock_path.resolve()
    packages = _packages(lock_path)
    root_name = "sova-oss"
    if root_name not in packages:
        raise FormatError("SOVA-SBOM-ROOT", "sova-oss package is absent from the lockfile")
    selected = (
        _runtime_closure(packages, root_name) if scope == "runtime" else set(packages) - {root_name}
    )
    components = [_component(name, packages[name]) for name in sorted(selected)]
    root_ref = f"pkg:pypi/sova-oss@{quote(__version__)}"
    dependency_rows: list[dict[str, Any]] = [
        {
            "ref": root_ref,
            "dependsOn": sorted(component["bom-ref"] for component in components),
        }
    ]
    selected_refs = {name: _component(name, packages[name])["bom-ref"] for name in selected}
    dependency_rows.extend(
        {
            "ref": selected_refs[name],
            "dependsOn": sorted(
                selected_refs[dependency]
                for dependency in _dependency_names(packages[name])
                if dependency in selected_refs
            ),
        }
        for name in sorted(selected)
    )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": "sova-oss",
                "version": __version__,
                "purl": root_ref,
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            },
            "properties": [
                {"name": "sova:sbom:scope", "value": scope},
                {"name": "sova:lock:sha256", "value": sha256_digest(lock_path.read_bytes())},
                {"name": "sova:network-used", "value": "false"},
            ],
        },
        "components": components,
        "dependencies": dependency_rows,
    }


def write_cyclonedx_sbom(
    lock_path: Path, destination: Path, *, scope: str = "runtime"
) -> dict[str, Any]:
    document = generate_cyclonedx_sbom(lock_path, scope=scope)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(canonical_json_bytes(document) + b"\n")
    return {
        "artifactType": "sova.release-sbom-result",
        "schemaVersion": "0.1.0",
        "format": "CycloneDX-1.6",
        "scope": scope,
        "componentCount": len(document["components"]),
        "digest": sha256_digest(destination.read_bytes()),
        "destination": str(destination),
        "networkUsed": False,
    }


def _release_files(root: Path, output: Path) -> list[Path]:
    root = root.resolve()
    output = output.resolve()
    if not root.is_dir():
        raise FormatError("SOVA-CHECKSUM-ROOT", "release root must be a directory")
    files: list[Path] = []
    folded_names: set[str] = set()
    total = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise FormatError("SOVA-CHECKSUM-SYMLINK", "release trees cannot contain symlinks")
        if not path.is_file() or path.resolve() == output:
            continue
        relative = path.relative_to(root).as_posix()
        if "\n" in relative or "\r" in relative:
            raise FormatError("SOVA-CHECKSUM-NAME", "release filenames cannot contain newlines")
        folded = relative.casefold()
        if folded in folded_names:
            raise FormatError("SOVA-CHECKSUM-NAME", "release filenames collide by case")
        folded_names.add(folded)
        files.append(path)
        total += path.stat().st_size
        if len(files) > _MAX_RELEASE_FILES or total > _MAX_RELEASE_BYTES:
            raise FormatError("SOVA-CHECKSUM-LIMIT", "release tree exceeds checksum limits")
    if not files:
        raise FormatError("SOVA-CHECKSUM-EMPTY", "release tree contains no candidate files")
    return files


def write_checksums(root: Path, destination: Path) -> dict[str, Any]:
    """Write a stable sha256sum-compatible manifest for one release tree."""
    resolved_root = root.resolve()
    files = _release_files(resolved_root, destination)
    rows = []
    for path in files:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        relative = path.relative_to(resolved_root).as_posix()
        rows.append(f"{digest}  {relative}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(rows) + "\n", encoding="utf-8", newline="\n")
    return {
        "artifactType": "sova.release-checksum-result",
        "schemaVersion": "0.1.0",
        "fileCount": len(rows),
        "manifestDigest": sha256_digest(destination.read_bytes()),
        "destination": str(destination),
    }


def verify_checksums(root: Path, manifest: Path) -> dict[str, Any]:
    """Verify manifest syntax, every declared file, and undeclared-file absence."""
    resolved_root = root.resolve()
    manifest = manifest.resolve()
    expected: dict[str, str] = {}
    folded_names: set[str] = set()
    for line in manifest.read_text(encoding="utf-8").splitlines():
        match = _CHECKSUM.fullmatch(line)
        if match is None:
            raise FormatError("SOVA-CHECKSUM-FORMAT", "checksum manifest line is malformed")
        relative = match.group("path")
        folded = relative.casefold()
        if relative in expected or folded in folded_names:
            raise FormatError("SOVA-CHECKSUM-DUPLICATE", "checksum path is duplicated")
        candidate = (resolved_root / relative).resolve()
        try:
            candidate.relative_to(resolved_root)
        except ValueError as error:
            raise FormatError(
                "SOVA-CHECKSUM-TRAVERSAL", "checksum path leaves release root"
            ) from error
        expected[relative] = match.group("digest")
        folded_names.add(folded)
    actual_files = _release_files(resolved_root, manifest)
    actual_names = {path.relative_to(resolved_root).as_posix() for path in actual_files}
    missing = sorted(set(expected) - actual_names)
    undeclared = sorted(actual_names - set(expected))
    mismatched = sorted(
        name
        for name, digest in expected.items()
        if name in actual_names
        and hashlib.sha256((resolved_root / name).read_bytes()).hexdigest() != digest
    )
    accepted = not missing and not undeclared and not mismatched
    return {
        "artifactType": "sova.release-checksum-verification",
        "schemaVersion": "0.1.0",
        "status": "pass" if accepted else "fail",
        "accepted": accepted,
        "declaredFileCount": len(expected),
        "missing": missing,
        "undeclared": undeclared,
        "mismatched": mismatched,
        "offline": True,
    }


__all__ = [
    "generate_cyclonedx_sbom",
    "verify_checksums",
    "write_checksums",
    "write_cyclonedx_sbom",
]
