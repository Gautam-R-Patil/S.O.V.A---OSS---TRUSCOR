# SPDX-License-Identifier: Apache-2.0
"""Versioned local-MCP tool and invocation contracts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

MCP_PROTOCOL_VERSION = "2025-11-25"
SOVA_MCP_MANIFEST_VERSION = "0.1.0"
_MAX_INVOCATION_SECONDS = 3600


@dataclass(frozen=True, slots=True)
class LocalToolDefinition:
    """One stable SOVA tool schema and its security posture."""

    name: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    read_only: bool
    destructive: bool
    open_world: bool
    gated: bool
    side_effects: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.name.startswith("sova.") or not self.description:
            raise FormatError("SOVA-LOCAL-MCP-TOOL", "tool identity is invalid")
        if self.gated and self.read_only:
            raise FormatError("SOVA-LOCAL-MCP-TOOL", "gated tools cannot claim read-only")

    def to_mcp_mapping(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
            "outputSchema": self.output_schema,
            "annotations": {
                "title": self.name,
                "readOnlyHint": self.read_only,
                "destructiveHint": self.destructive,
                "idempotentHint": self.read_only,
                "openWorldHint": self.open_world,
            },
            "_meta": {
                "sova/schemaVersion": SOVA_MCP_MANIFEST_VERSION,
                "sova/gated": self.gated,
                "sova/sideEffects": list(self.side_effects),
                "sova/annotationsAreHints": True,
            },
        }


@dataclass(frozen=True, slots=True)
class InvocationDescriptor:
    """Exact human-review surface for one gated invocation."""

    tool: str
    arguments: dict[str, Any]
    target: str
    scope: tuple[str, ...]
    actions: tuple[str, ...]
    limits: dict[str, Any]
    duration_seconds: int
    risks: tuple[str, ...]
    ownership: str = "self"

    def __post_init__(self) -> None:
        if self.ownership != "self":
            raise FormatError(
                "SOVA-LOCAL-MCP-OWNERSHIP",
                "local MCP defaults to self-owned targets only",
            )
        if not self.tool.startswith("sova.") or not self.target:
            raise FormatError("SOVA-LOCAL-MCP-INVOCATION", "invocation identity is invalid")
        if not 1 <= self.duration_seconds <= _MAX_INVOCATION_SECONDS:
            raise FormatError("SOVA-LOCAL-MCP-DURATION", "duration must be between 1 and 3600")
        if not self.scope or not self.actions or not self.risks:
            raise FormatError(
                "SOVA-LOCAL-MCP-INVOCATION",
                "scope, actions, and risks must be explicit",
            )

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))

    def to_mapping(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "arguments": self.arguments,
            "target": self.target,
            "scope": list(self.scope),
            "actions": list(self.actions),
            "limits": self.limits,
            "durationSeconds": self.duration_seconds,
            "risks": list(self.risks),
            "ownership": self.ownership,
        }


def manifest_document(tools: tuple[LocalToolDefinition, ...]) -> dict[str, Any]:
    """Return a deterministic, drift-detectable local-MCP manifest."""
    rows = [tool.to_mcp_mapping() for tool in sorted(tools, key=lambda item: item.name)]
    core = {
        "artifactType": "sova.mcp-tool-manifest",
        "schemaVersion": SOVA_MCP_MANIFEST_VERSION,
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "tools": rows,
    }
    return {**core, "manifestDigest": sha256_digest(canonical_json_bytes(core))}


__all__ = [
    "MCP_PROTOCOL_VERSION",
    "SOVA_MCP_MANIFEST_VERSION",
    "InvocationDescriptor",
    "LocalToolDefinition",
    "manifest_document",
]
