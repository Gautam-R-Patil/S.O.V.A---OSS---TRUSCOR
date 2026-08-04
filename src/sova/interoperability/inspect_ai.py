# SPDX-License-Identifier: Apache-2.0
"""Loss-reporting bridge for Inspect AI Sample JSON/JSONL datasets."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from pathlib import Path

_MAX_DATASET_BYTES = 64 * 1024 * 1024
_MAX_SAMPLES = 100_000
_ALLOWED_FIELDS = {"id", "input", "target", "choices", "metadata", "sandbox", "files", "setup"}


def _sample(value: Any, index: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FormatError("SOVA-INTEROP-INSPECT-SAMPLE", "Inspect sample must be an object")
    if "input" not in value:
        raise FormatError("SOVA-INTEROP-INSPECT-INPUT", "Inspect sample input is required")
    identifier = str(value.get("id", index))
    metadata = value.get("metadata", {})
    if not isinstance(metadata, dict):
        raise FormatError("SOVA-INTEROP-INSPECT-METADATA", "sample metadata must be an object")
    # setup/files are retained as inert source data. Import never executes or materializes them.
    return {
        "originalId": identifier,
        "input": value["input"],
        "target": value.get("target"),
        "choices": value.get("choices"),
        "metadata": metadata,
        "inertSetup": value.get("setup"),
        "inertFiles": value.get("files"),
        "sandboxDeclaration": value.get("sandbox"),
        "unknownFields": {key: child for key, child in value.items() if key not in _ALLOWED_FIELDS},
    }


def _rows(path: Path) -> list[Any]:
    size = path.stat().st_size
    if size > _MAX_DATASET_BYTES:
        raise FormatError("SOVA-INTEROP-DATASET-LIMIT", "external dataset exceeds size limit")
    raw = path.read_bytes()
    if path.suffix.lower() == ".jsonl":
        parsed = [strict_json_loads(line) for line in raw.splitlines() if line.strip()]
    else:
        value = strict_json_loads(raw, max_bytes=_MAX_DATASET_BYTES)
        parsed = value if isinstance(value, list) else [value]
    if len(parsed) > _MAX_SAMPLES:
        raise FormatError("SOVA-INTEROP-SAMPLE-LIMIT", "external dataset has too many samples")
    return parsed


def import_inspect_samples(
    source: Path,
    *,
    license_expression: str,
    source_url: str,
) -> dict[str, Any]:
    """Import Inspect samples without executing dataset-provided setup or files."""
    if not license_expression or not source_url:
        raise FormatError("SOVA-INTEROP-PROVENANCE", "source URL and licence are required")
    samples = [_sample(row, index) for index, row in enumerate(_rows(source))]
    source_digest = sha256_digest(source.read_bytes())
    losses: list[str] = []
    if any(item["sandboxDeclaration"] is not None for item in samples):
        losses.append("inspect-sandbox-declaration-not-executed")
    if any(item["inertSetup"] is not None for item in samples):
        losses.append("inspect-setup-retained-inert-not-executed")
    if any(item["inertFiles"] is not None for item in samples):
        losses.append("inspect-files-retained-inert-not-materialized")
    return {
        "artifactType": "sova.external-scenario-set",
        "schemaVersion": "0.1.0",
        "sourceFormat": "inspect-ai-sample-jsonl",
        "source": {
            "url": source_url,
            "license": license_expression,
            "digest": source_digest,
        },
        "samples": samples,
        "conversion": {
            "lossless": not losses,
            "semanticLoss": sorted(losses),
            "executionPolicy": "inert-import-fresh-authorization-required",
        },
    }


def export_inspect_samples(document: dict[str, Any], destination: Path) -> dict[str, Any]:
    """Export preserved Inspect fields and report SOVA-only fields that cannot transfer."""
    if document.get("artifactType") != "sova.external-scenario-set":
        raise FormatError("SOVA-INTEROP-ARTIFACT", "document is not an external scenario set")
    rows: list[dict[str, Any]] = []
    samples = document.get("samples")
    if not isinstance(samples, list):
        raise FormatError("SOVA-INTEROP-SAMPLES", "samples must be an array")
    for item in samples:
        if not isinstance(item, dict):
            raise FormatError("SOVA-INTEROP-SAMPLE", "sample must be an object")
        row = {
            "id": item.get("originalId"),
            "input": item.get("input"),
            "target": item.get("target"),
            "choices": item.get("choices"),
            "metadata": item.get("metadata", {}),
        }
        for source_key, output_key in (
            ("inertSetup", "setup"),
            ("inertFiles", "files"),
            ("sandboxDeclaration", "sandbox"),
        ):
            if item.get(source_key) is not None:
                row[output_key] = item[source_key]
        unknown = item.get("unknownFields", {})
        if isinstance(unknown, dict):
            row.update(unknown)
        rows.append({key: value for key, value in row.items() if value is not None})
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(b"".join(canonical_json_bytes(row) + b"\n" for row in rows))
    return {
        "artifactType": "sova.interop-export-report",
        "destination": destination.as_posix(),
        "sampleCount": len(rows),
        "semanticLoss": ["sova-provenance-and-conversion-envelope-emitted-as-sidecar-only"],
    }
