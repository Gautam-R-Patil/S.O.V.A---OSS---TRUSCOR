# SPDX-License-Identifier: Apache-2.0
"""Capability mapping and transitive-reach analysis."""

from sova.mapping.analysis import analyze_capability_graph, capability_closures, reachable_paths
from sova.mapping.discovery import (
    DiscoveryInput,
    DiscoveryResult,
    discover_workspace,
    discovery_projection,
    import_inventory,
)
from sova.mapping.drift import compare_tool_snapshot, tool_snapshot, write_tool_snapshot
from sova.mapping.model import (
    CapabilityGraph,
    CapabilityMapReport,
    EdgeKind,
    EvidenceClass,
    GraphEdge,
    GraphNode,
    MapFinding,
    NodeKind,
    Provenance,
    projected_provenance,
    scoped_identifier,
)
from sova.mapping.report import (
    build_capability_map,
    read_capability_map,
    validate_map_report,
    write_capability_map,
)

__all__ = [
    "CapabilityGraph",
    "CapabilityMapReport",
    "DiscoveryInput",
    "DiscoveryResult",
    "EdgeKind",
    "EvidenceClass",
    "GraphEdge",
    "GraphNode",
    "MapFinding",
    "NodeKind",
    "Provenance",
    "analyze_capability_graph",
    "build_capability_map",
    "capability_closures",
    "compare_tool_snapshot",
    "discover_workspace",
    "discovery_projection",
    "import_inventory",
    "projected_provenance",
    "reachable_paths",
    "read_capability_map",
    "scoped_identifier",
    "tool_snapshot",
    "validate_map_report",
    "write_capability_map",
    "write_tool_snapshot",
]
