# SPDX-License-Identifier: Apache-2.0
"""Versioned tool-description snapshots and conservative drift classification."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError
from sova.mapping.model import CapabilityGraph, NodeKind

if TYPE_CHECKING:
    from pathlib import Path


def tool_snapshot(graph: CapabilityGraph) -> dict[str, Any]:
    """Build a secret-free canonical snapshot of approved tool declarations."""
    tools: dict[str, dict[str, Any]] = {}
    for node in sorted(graph.nodes.values(), key=lambda item: item.id):
        if node.kind != NodeKind.TOOL:
            continue
        projection = {
            "name": node.name,
            "description": node.attributes.get("description", ""),
            "inputSchema": node.attributes.get("inputSchema", {}),
            "entrypoint": node.attributes.get("entrypoint"),
        }
        tools[node.id] = {
            "digest": sha256_digest(canonical_json_bytes(projection)),
            "projection": projection,
        }
    document: dict[str, Any] = {
        "artifactType": "sova.tool-snapshot",
        "schemaVersion": "0.1.0",
        "tools": tools,
    }
    document["contentDigest"] = sha256_digest(canonical_json_bytes(document))
    return document


def write_tool_snapshot(path: Path, graph: CapabilityGraph) -> str:
    """Write a new snapshot without overwriting prior approval state."""
    if path.exists():
        raise FormatError(
            "SOVA-MAP-SNAPSHOT-EXISTS",
            "tool snapshot destination already exists",
        )
    document = tool_snapshot(graph)
    path.write_bytes(canonical_json_bytes(document) + b"\n")
    return str(document["contentDigest"])


def _load_snapshot(path: Path) -> dict[str, Any]:
    document = strict_json_loads(path.read_bytes())
    if not isinstance(document, dict) or document.get("artifactType") != "sova.tool-snapshot":
        raise FormatError("SOVA-MAP-SNAPSHOT", "unsupported tool snapshot")
    supplied = document.get("contentDigest")
    body = dict(document)
    body.pop("contentDigest", None)
    expected = sha256_digest(canonical_json_bytes(body))
    if supplied != expected:
        raise FormatError("SOVA-MAP-SNAPSHOT-INTEGRITY", "tool snapshot digest mismatch")
    if not isinstance(document.get("tools"), dict):
        raise FormatError("SOVA-MAP-SNAPSHOT", "tool snapshot tools must be an object")
    return document


def compare_tool_snapshot(path: Path, graph: CapabilityGraph) -> tuple[dict[str, Any], ...]:
    """Classify exact, additive, removal, description, and schema drift."""
    approved = _load_snapshot(path)["tools"]
    current = tool_snapshot(graph)["tools"]
    changes: list[dict[str, Any]] = []
    for tool_id in sorted(set(approved) | set(current)):
        before = approved.get(tool_id)
        after = current.get(tool_id)
        if before is None:
            changes.append({"toolId": tool_id, "classification": "added", "risk": "review"})
            continue
        if after is None:
            changes.append({"toolId": tool_id, "classification": "removed", "risk": "review"})
            continue
        if before.get("digest") == after.get("digest"):
            continue
        before_projection = before.get("projection", {})
        after_projection = after.get("projection", {})
        if not isinstance(before_projection, dict) or not isinstance(after_projection, dict):
            classification = "semantic-unknown"
            risk = "high"
        elif before_projection.get("inputSchema") != after_projection.get("inputSchema"):
            classification = "input-schema-change"
            risk = "high"
        elif before_projection.get("entrypoint") != after_projection.get("entrypoint"):
            classification = "entrypoint-change"
            risk = "high"
        elif before_projection.get("description") != after_projection.get("description"):
            classification = "description-change"
            risk = "review"
        else:
            classification = "semantic-unknown"
            risk = "high"
        changes.append(
            {
                "toolId": tool_id,
                "classification": classification,
                "risk": risk,
                "approvedDigest": before.get("digest"),
                "currentDigest": after.get("digest"),
            }
        )
    return tuple(changes)


__all__ = ["compare_tool_snapshot", "tool_snapshot", "write_tool_snapshot"]
