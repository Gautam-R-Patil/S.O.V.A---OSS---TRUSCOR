# SPDX-License-Identifier: Apache-2.0
"""Capability map construction, validation, and atomic output."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads, validate_document
from sova.formats.errors import FormatError
from sova.mapping.analysis import analyze_capability_graph, capability_closures
from sova.mapping.discovery import discover_workspace, import_inventory
from sova.mapping.drift import compare_tool_snapshot
from sova.mapping.model import CapabilityMapReport

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path


def build_capability_map(
    root: Path,
    *,
    inventories: Sequence[Path] = (),
    observed_inventories: Sequence[Path] = (),
    runtime_authorized: bool = False,
    baseline: Path | None = None,
) -> CapabilityMapReport:
    """Build a local map without network access or runtime code execution."""
    discovery = discover_workspace(root)
    for inventory in inventories:
        import_inventory(discovery, inventory)
    for inventory in observed_inventories:
        import_inventory(
            discovery,
            inventory,
            observed=True,
            authorized=runtime_authorized,
        )
    drift = compare_tool_snapshot(baseline, discovery.graph) if baseline is not None else ()
    limitations = sorted(set(discovery.limitations))
    if observed_inventories:
        limitations.append(
            "Observed inventory was imported from an authorized external collector; "
            "SOVA did not independently attest collector completeness."
        )
    report = CapabilityMapReport(
        graph=discovery.graph,
        findings=analyze_capability_graph(discovery.graph),
        limitations=tuple(limitations),
        inputs=tuple(item.to_mapping() for item in discovery.inputs),
        closures=capability_closures(discovery.graph),
        tool_drift=drift,
    )
    validate_map_report(report.to_mapping())
    return report


def validate_map_report(document: dict[str, Any]) -> None:
    """Validate structure, content digest, endpoints, and evidence provenance."""
    validate_document(document, "sova.map")
    supplied = document["contentDigest"]
    body = dict(document)
    body.pop("contentDigest")
    expected = sha256_digest(canonical_json_bytes(body))
    if supplied != expected:
        raise FormatError("SOVA-MAP-INTEGRITY", "map report content digest mismatch")
    graph = document["graph"]
    nodes = {node["id"] for node in graph["nodes"]}
    edge_ids = {edge["id"] for edge in graph["edges"]}
    if any(item["nodeId"] not in nodes for item in document["inventory"]):
        raise FormatError("SOVA-MAP-DANGLING-INVENTORY", "inventory references an unknown node")
    for edge in graph["edges"]:
        if edge["source"] not in nodes or edge["target"] not in nodes:
            raise FormatError("SOVA-MAP-DANGLING-EDGE", "map report contains a dangling edge")
    for finding in document["findings"]:
        if not set(finding["nodeIds"]).issubset(nodes):
            raise FormatError(
                "SOVA-MAP-DANGLING-FINDING",
                "map finding references an unknown node",
            )
        if not set(finding["edgeIds"]).issubset(edge_ids):
            raise FormatError(
                "SOVA-MAP-DANGLING-FINDING",
                "map finding references an unknown edge",
            )


def read_capability_map(path: Path) -> dict[str, Any]:
    """Read and validate a capability map without executing embedded content."""
    document = strict_json_loads(path.read_bytes())
    if not isinstance(document, dict):
        raise FormatError("SOVA-MAP-ROOT", "map report root must be an object")
    validate_map_report(document)
    return document


def write_capability_map(path: Path, report: CapabilityMapReport) -> str:
    """Atomically create a report without overwriting an existing artifact."""
    if path.exists():
        raise FormatError("SOVA-MAP-OUTPUT-EXISTS", "map report destination already exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    document = report.to_mapping()
    validate_map_report(document)
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(canonical_json_bytes(document) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return str(document["contentDigest"])


__all__ = [
    "build_capability_map",
    "read_capability_map",
    "validate_map_report",
    "write_capability_map",
]
