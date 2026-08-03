# SPDX-License-Identifier: Apache-2.0
"""Provenance-preserving imports for established external formats."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sova.evidence import import_sarif
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from collections.abc import Mapping


def import_sarif_findings(document: Mapping[str, Any], *, source_uri: str) -> dict[str, Any]:
    findings = import_sarif(document)
    return {
        "artifactType": "sova.external-findings",
        "schemaVersion": "0.1.0",
        "source": {
            "format": "SARIF-2.1.0",
            "uri": source_uri,
            "digest": sha256_digest(canonical_json_bytes(document)),
            "integrity": "caller-supplied-not-independently-verified",
        },
        "findings": [finding.to_mapping() for finding in findings],
        "provenancePreserved": True,
    }


def import_passive_trace(
    events: list[Mapping[str, Any]],
    *,
    source_format: str,
    source_uri: str,
    integrity_state: str,
) -> dict[str, Any]:
    if not source_format or not source_uri or not integrity_state:
        raise FormatError("SOVA-ADAPTER-PROVENANCE", "passive trace provenance is required")
    normalized: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        kind = event.get("kind")
        if not isinstance(kind, str) or not kind:
            raise FormatError("SOVA-ADAPTER-EVENT", "each external event requires a kind")
        normalized.append(
            {
                "id": str(event.get("id", f"external:{index}")),
                "sequence": index,
                "kind": kind,
                "phase": str(event.get("phase", "external")),
                "actor": dict(event.get("actor", {"name": "external"})),
                "target": dict(event.get("target", {"name": "unknown"})),
                "parents": list(event.get("parents", [])),
                "payload": event.get("payload", {}),
                "sourceRecord": dict(event),
            }
        )
    return {
        "artifactType": "sova.external-normalized-events",
        "schemaVersion": "0.1.0",
        "sourceType": source_format,
        "sourceId": source_uri,
        "sourceDigest": sha256_digest(canonical_json_bytes(events)),
        "integrityState": integrity_state,
        "events": normalized,
        "provenancePreserved": True,
        "evidenceUpgraded": False,
    }


def import_benchmark_scenario(
    scenario: Mapping[str, Any],
    *,
    source_name: str,
    source_version: str,
    source_uri: str,
    license_expression: str,
) -> dict[str, Any]:
    if not all((source_name, source_version, source_uri, license_expression)):
        raise FormatError("SOVA-ADAPTER-PROVENANCE", "benchmark provenance is required")
    return {
        "artifactType": "sova.external-scenario-import",
        "schemaVersion": "0.1.0",
        "portableIntent": dict(scenario),
        "source": {
            "name": source_name,
            "version": source_version,
            "uri": source_uri,
            "license": license_expression,
            "digest": sha256_digest(canonical_json_bytes(scenario)),
        },
        "executorMechanicsIncluded": False,
        "provenancePreserved": True,
    }


def map_external_taxonomy(
    external_ids: list[str],
    mapping: Mapping[str, str],
    *,
    mapping_version: str,
) -> dict[str, Any]:
    if not mapping_version:
        raise FormatError("SOVA-ADAPTER-TAXONOMY", "mapping version is required")
    resolved = [
        {
            "externalId": external_id,
            "sovaId": mapping.get(external_id),
            "state": "mapped" if external_id in mapping else "unmapped",
        }
        for external_id in external_ids
    ]
    return {
        "artifactType": "sova.taxonomy-mapping",
        "schemaVersion": "0.1.0",
        "mappingVersion": mapping_version,
        "results": resolved,
        "unmappedIdsInvented": False,
    }


__all__ = [
    "import_benchmark_scenario",
    "import_passive_trace",
    "import_sarif_findings",
    "map_external_taxonomy",
]
