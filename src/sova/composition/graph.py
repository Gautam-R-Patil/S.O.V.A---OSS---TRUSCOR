# SPDX-License-Identifier: Apache-2.0
"""Strict construction of metadata-only composition graphs."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from sova.composition.model import (
    ComponentNode,
    CompositionGraph,
    DependencyEdge,
    EdgeKind,
    NodeKind,
)
from sova.formats.errors import FormatError

_MAX_NODES = 10_000
_MAX_EDGES = 50_000
_MAX_TEXT_LENGTH = 512
_MAX_RISK_WEIGHT = 100
_FORBIDDEN_SECRET_FIELDS = {
    "apikey",
    "authorization",
    "cookie",
    "credential",
    "password",
    "secret",
    "token",
}


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_TEXT_LENGTH:
        raise FormatError("SOVA-COMPOSE-FIELD", f"{name} must be a bounded non-empty string")
    return value.strip()


def _reject_secret_material(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized_key = (
                key.casefold().replace("_", "").replace("-", "") if isinstance(key, str) else ""
            )
            if normalized_key in _FORBIDDEN_SECRET_FIELDS:
                raise FormatError(
                    "SOVA-COMPOSE-SECRET-MATERIAL",
                    "composition graphs contain credential metadata, never credential values",
                    path=f"{path}.{key}",
                )
            _reject_secret_material(child, f"{path}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for index, child in enumerate(value):
            _reject_secret_material(child, f"{path}[{index}]")


def graph_from_mapping(value: Mapping[str, Any]) -> CompositionGraph:  # noqa: PLR0912
    """Parse a bounded graph and reject embedded credential values."""
    _reject_secret_material(value)
    raw_nodes = value.get("nodes")
    raw_edges = value.get("edges")
    if not isinstance(raw_nodes, Sequence) or isinstance(raw_nodes, (str, bytes)):
        raise FormatError("SOVA-COMPOSE-NODES", "nodes must be an array")
    if not isinstance(raw_edges, Sequence) or isinstance(raw_edges, (str, bytes)):
        raise FormatError("SOVA-COMPOSE-EDGES", "edges must be an array")
    if len(raw_nodes) > _MAX_NODES or len(raw_edges) > _MAX_EDGES:
        raise FormatError("SOVA-COMPOSE-GRAPH-LIMIT", "composition graph limit exceeded")
    nodes: list[ComponentNode] = []
    node_ids: set[str] = set()
    for raw in raw_nodes:
        if not isinstance(raw, Mapping):
            raise FormatError("SOVA-COMPOSE-NODE", "node must be an object")
        node_id = _text(raw.get("id"), "node id")
        if node_id in node_ids:
            raise FormatError("SOVA-COMPOSE-DUPLICATE-NODE", "node id is duplicated")
        node_ids.add(node_id)
        try:
            node_kind = NodeKind(_text(raw.get("kind"), "node kind"))
        except ValueError as error:
            raise FormatError("SOVA-COMPOSE-NODE-KIND", "unsupported node kind") from error
        actor_id = raw.get("actorId")
        nodes.append(
            ComponentNode(
                node_id=node_id,
                kind=node_kind,
                name=_text(raw.get("name"), "node name"),
                version=_text(raw.get("version", "unknown"), "node version"),
                actor_id=_text(actor_id, "actor id") if actor_id is not None else None,
            )
        )
    edges: list[DependencyEdge] = []
    edge_ids: set[str] = set()
    for raw in raw_edges:
        if not isinstance(raw, Mapping):
            raise FormatError("SOVA-COMPOSE-EDGE", "edge must be an object")
        edge_id = _text(raw.get("id"), "edge id")
        if edge_id in edge_ids:
            raise FormatError("SOVA-COMPOSE-DUPLICATE-EDGE", "edge id is duplicated")
        edge_ids.add(edge_id)
        source = _text(raw.get("source"), "edge source")
        target = _text(raw.get("target"), "edge target")
        if source not in node_ids or target not in node_ids:
            raise FormatError("SOVA-COMPOSE-ENDPOINT", "edge endpoint is not a declared node")
        risk = raw.get("riskWeight", 0)
        if not isinstance(risk, int) or isinstance(risk, bool) or not 0 <= risk <= _MAX_RISK_WEIGHT:
            raise FormatError("SOVA-COMPOSE-RISK", "riskWeight must be an integer from 0 to 100")
        order = raw.get("order")
        if order is not None and (
            not isinstance(order, int) or isinstance(order, bool) or order < 0
        ):
            raise FormatError("SOVA-COMPOSE-ORDER", "edge order must be a non-negative integer")
        try:
            edge_kind = EdgeKind(_text(raw.get("kind"), "edge kind"))
        except ValueError as error:
            raise FormatError("SOVA-COMPOSE-EDGE-KIND", "unsupported edge kind") from error
        observed = raw.get("observed", False)
        if not isinstance(observed, bool):
            raise FormatError("SOVA-COMPOSE-OBSERVED", "observed must be a boolean")
        edges.append(
            DependencyEdge(
                edge_id=edge_id,
                source=source,
                target=target,
                kind=edge_kind,
                provenance=_text(raw.get("provenance", "declared"), "edge provenance"),
                observed=observed,
                risk_weight=risk,
                permission=(
                    _text(raw.get("permission"), "permission")
                    if raw.get("permission") is not None
                    else None
                ),
                shared_resource=(
                    _text(raw.get("sharedResource"), "shared resource")
                    if raw.get("sharedResource") is not None
                    else None
                ),
                order=order,
                state_condition=(
                    _text(raw.get("stateCondition"), "state condition")
                    if raw.get("stateCondition") is not None
                    else None
                ),
            )
        )
    return CompositionGraph(tuple(nodes), tuple(edges))


__all__ = ["graph_from_mapping"]
