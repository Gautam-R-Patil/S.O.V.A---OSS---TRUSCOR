# SPDX-License-Identifier: Apache-2.0
"""Deterministic, non-destructive experimental capsule migrations."""

from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

from sova.formats import PackageReader, PackageWriter, canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.formats.schema import validate_document

if TYPE_CHECKING:
    from pathlib import Path

CURRENT_VERSION = "0.1.0"
Migration = Callable[[dict[str, Any]], dict[str, Any]]
SUPPORTED_REQUIRED_FEATURES = frozenset(
    {
        "capsule.core/0.1",
        "scenario.core/0.1",
        "trace.core/0.1",
        "detonation.synthetic/0.1",
    }
)


@dataclass(frozen=True, slots=True)
class MigrationAnalysis:
    """Machine-readable preflight for a deterministic schema conversion."""

    source_version: str
    destination_version: str
    path: tuple[str, ...]
    classification: str
    preserved_unknown: tuple[str, ...]
    assumptions: tuple[str, ...]
    blockers: tuple[str, ...]

    @property
    def lossless(self) -> bool:
        return self.classification == "lossless-forward" and not self.blockers

    def to_mapping(self) -> dict[str, Any]:
        value = asdict(self)
        value["lossless"] = self.lossless
        return value


def _v001_to_v002(source: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(source)
    result["schemaVersion"] = "0.0.2"
    if "description" in result and "summary" not in result:
        result["summary"] = result.pop("description")
    if "useCase" in result and "domainProfile" not in result:
        mapping = {
            "attack": "security",
            "evaluation": "evaluation",
            "interpretability": "behavioral-interpretability",
            "incident": "incident-forensics",
            "research": "research-publication",
        }
        raw = result.pop("useCase")
        if not isinstance(raw, str) or raw not in mapping:
            raise FormatError(
                "SOVA-MIGRATE-SEMANTIC-LOSS",
                "legacy useCase has no semantics-preserving domain-profile mapping",
                path="$.useCase",
                details={"value": raw},
            )
        result["domainProfile"] = mapping[raw]
    authors = result.get("authors", [])
    result["authors"] = [
        {"name": author} if isinstance(author, str) else author for author in authors
    ]
    return result


def _v002_to_v010(source: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(source)
    legacy_unknown = {
        key: result.pop(key)
        for key in list(result)
        if key
        not in {
            "artifactType",
            "schemaVersion",
            "id",
            "version",
            "title",
            "summary",
            "domainProfile",
            "captureProfile",
            "lifecycle",
            "createdAt",
            "authors",
            "citation",
            "provenance",
            "methodology",
            "taxonomy",
            "compatibility",
            "authorization",
            "safety",
            "disclosure",
            "license",
            "limitations",
            "relationships",
            "objects",
            "requiredFeatures",
            "optionalFeatures",
            "extensions",
            "migration",
        }
    }
    result["schemaVersion"] = CURRENT_VERSION
    result.setdefault("version", "0.1.0")
    result.setdefault("captureProfile", "lite")
    result.setdefault("lifecycle", "draft")
    result.setdefault(
        "citation",
        {
            "preferred": (f"{result.get('title', 'Untitled')}. Migrated SOVA behavior capsule."),
            "identifiers": [],
        },
    )
    result.setdefault(
        "provenance",
        {
            "createdBy": "unknown-after-migration",
            "createdWith": "sova-migrate",
            "sourceDigests": [],
            "transformations": [],
        },
    )
    result.setdefault(
        "methodology",
        {"id": "unknown-after-migration", "version": "unknown", "digest": None},
    )
    result.setdefault(
        "taxonomy",
        {"id": "unknown-after-migration", "version": "unknown", "digest": None},
    )
    result.setdefault(
        "compatibility",
        {"runtime": "unknown-after-migration", "models": [], "tools": [], "platforms": []},
    )
    result.setdefault(
        "authorization",
        {
            "reexecutionRequiresFreshAuthorization": True,
            "scopeStatement": (
                "Historical authorization was not recorded; fresh authority is required."
            ),
        },
    )
    result.setdefault(
        "safety",
        {
            "impact": "unknown",
            "forbiddenEffects": ["undeclared external side effects"],
            "cleanupRequired": True,
        },
    )
    result.setdefault(
        "disclosure",
        {"classification": "private", "sharing": "Review migrated content before sharing."},
    )
    result.setdefault("license", "NOASSERTION")
    result.setdefault("limitations", [])
    result.setdefault("relationships", [])
    result["limitations"].append(
        "Migrated from an experimental schema; newly required historical context may be unknown."
    )
    result.setdefault("requiredFeatures", [])
    result.setdefault("optionalFeatures", [])
    extensions = result.setdefault("extensions", {})
    if legacy_unknown:
        extensions["x-sova-legacy"] = legacy_unknown
    return result


_MIGRATIONS: dict[tuple[str, str], Migration] = {
    ("0.0.1", "0.0.2"): _v001_to_v002,
    ("0.0.2", "0.1.0"): _v002_to_v010,
}


def _path(source: str, destination: str) -> list[tuple[str, str]]:
    if source == destination:
        return []
    path: list[tuple[str, str]] = []
    current = source
    visited: set[str] = set()
    while current != destination:
        if current in visited:
            break
        visited.add(current)
        match = next((edge for edge in _MIGRATIONS if edge[0] == current), None)
        if match is None:
            raise FormatError(
                "SOVA-MIGRATE-NO-PATH",
                f"no deterministic migration path from {source} to {destination}",
            )
        path.append(match)
        current = match[1]
    if current != destination:
        raise FormatError(
            "SOVA-MIGRATE-NO-PATH",
            f"no deterministic migration path from {source} to {destination}",
        )
    return path


def analyze_migration(
    source: dict[str, Any],
    *,
    destination_version: str = CURRENT_VERSION,
) -> MigrationAnalysis:
    """Explain compatibility without writing or transforming the source."""
    source_version = source.get("schemaVersion")
    if not isinstance(source_version, str):
        source_version = "<missing>"
    blockers: list[str] = []
    if source.get("artifactType") != "sova.capsule":
        blockers.append("unsupported artifactType")
    raw_features = source.get("requiredFeatures", [])
    if not isinstance(raw_features, list) or not all(
        isinstance(feature, str) for feature in raw_features
    ):
        blockers.append("requiredFeatures is not a string array")
        raw_features = []
    unsupported = sorted(set(raw_features) - SUPPORTED_REQUIRED_FEATURES)
    if unsupported:
        blockers.append(f"unknown required features: {', '.join(unsupported)}")
    if source_version == "0.0.1" and "useCase" in source:
        known_use_cases = {"attack", "evaluation", "interpretability", "incident", "research"}
        if source["useCase"] not in known_use_cases:
            blockers.append("legacy useCase cannot be mapped without inventing meaning")
    try:
        edges = _path(source_version, destination_version)
    except FormatError as error:
        blockers.append(error.issue.message)
        edges = []
    known_v002 = {
        "artifactType",
        "schemaVersion",
        "id",
        "version",
        "title",
        "summary",
        "domainProfile",
        "captureProfile",
        "lifecycle",
        "createdAt",
        "authors",
        "citation",
        "provenance",
        "methodology",
        "taxonomy",
        "compatibility",
        "authorization",
        "safety",
        "disclosure",
        "license",
        "limitations",
        "relationships",
        "objects",
        "requiredFeatures",
        "optionalFeatures",
        "extensions",
        "migration",
    }
    preserved_unknown = tuple(sorted(set(source) - known_v002))
    assumptions = (
        (
            "newly required historical context is recorded as unknown-after-migration",
            "fresh authorization remains required for re-execution",
        )
        if edges
        else ()
    )
    return MigrationAnalysis(
        source_version=source_version,
        destination_version=destination_version,
        path=tuple(f"{left}->{right}" for left, right in edges),
        classification="unsupported" if blockers else "lossless-forward",
        preserved_unknown=preserved_unknown,
        assumptions=assumptions,
        blockers=tuple(blockers),
    )


def migrate_manifest(
    source: dict[str, Any],
    *,
    destination_version: str = CURRENT_VERSION,
) -> dict[str, Any]:
    """Migrate a manifest while preserving source bytes and explicit lineage."""
    analysis = analyze_migration(source, destination_version=destination_version)
    if analysis.blockers:
        unsupported = (
            sorted(set(source.get("requiredFeatures", [])) - SUPPORTED_REQUIRED_FEATURES)
            if isinstance(source.get("requiredFeatures", []), list)
            else []
        )
        if unsupported:
            raise FormatError(
                "SOVA-MIGRATE-UNKNOWN-REQUIRED-FEATURE",
                "migration cannot preserve unknown required behavior",
                details={"features": unsupported, "analysis": analysis.to_mapping()},
            )
        raise FormatError(
            "SOVA-MIGRATE-INCOMPATIBLE",
            "migration preflight found an incompatibility",
            details=analysis.to_mapping(),
        )
    source_version = source.get("schemaVersion")
    if not isinstance(source_version, str):
        raise FormatError("SOVA-MIGRATE-VERSION", "source schemaVersion is required")
    result = copy.deepcopy(source)
    edges = _path(source_version, destination_version)
    for edge in edges:
        result = _MIGRATIONS[edge](result)
    if not edges:
        validate_document(result, "sova.capsule")
        return result
    source_digest = sha256_digest(canonical_json_bytes(source))
    result["migration"] = {
        "sourceDigest": source_digest,
        "sourceVersion": source_version,
        "path": [f"{left}->{right}" for left, right in edges],
        "classification": analysis.classification,
        "preservedUnknown": list(analysis.preserved_unknown),
        "assumptions": list(analysis.assumptions),
    }
    provenance = result["provenance"]
    provenance["sourceDigests"] = [*provenance.get("sourceDigests", []), source_digest]
    provenance["transformations"] = [
        *provenance.get("transformations", []),
        *(f"sova.migrate/{left}-to-{right}" for left, right in edges),
    ]
    validate_document(result, "sova.capsule")
    return result


def migrate_capsule(
    source_path: Path,
    destination_path: Path,
    *,
    destination_version: str = CURRENT_VERSION,
) -> str:
    """Migrate a `.sova` package without overwriting the source."""
    if source_path.resolve() == destination_path.resolve():
        raise FormatError(
            "SOVA-MIGRATE-NO-OVERWRITE",
            "migration never overwrites the source artifact",
        )
    if destination_path.exists():
        raise FormatError(
            "SOVA-MIGRATE-DESTINATION-EXISTS",
            "migration will not overwrite an existing destination",
        )
    reader = PackageReader(source_path)
    source_manifest_bytes = reader.raw_manifest_bytes()
    source_manifest = reader.raw_manifest()
    raw_objects = source_manifest.get("objects", [])
    descriptors = reader.verify_object_index(raw_objects)
    migrated = migrate_manifest(source_manifest, destination_version=destination_version)
    migrated["migration"]["sourcePackageDigest"] = sha256_digest(source_path.read_bytes())
    migrated["migration"]["preservedSourcePath"] = "migration/source-manifest.json"
    migrated.pop("objects", None)
    writer = PackageWriter(migrated)
    for descriptor in descriptors:
        data = reader.read_object(descriptor)
        writer.add_bytes(
            role=descriptor.role,
            path=descriptor.path,
            media_type=descriptor.mediaType,
            data=data,
        )
    writer.add_bytes(
        role="migration-source-manifest",
        path="migration/source-manifest.json",
        media_type="application/json",
        data=source_manifest_bytes,
    )
    return writer.write(destination_path)


__all__ = [
    "CURRENT_VERSION",
    "MigrationAnalysis",
    "analyze_migration",
    "migrate_capsule",
    "migrate_manifest",
]
