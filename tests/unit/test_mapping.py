# SPDX-License-Identifier: Apache-2.0
"""Topic 09 capability mapping, provenance, drift, and safety contracts."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.mapping import (
    CapabilityGraph,
    DiscoveryResult,
    EdgeKind,
    EvidenceClass,
    NodeKind,
    Provenance,
    analyze_capability_graph,
    build_capability_map,
    capability_closures,
    compare_tool_snapshot,
    discover_workspace,
    discovery_projection,
    import_inventory,
    projected_provenance,
    reachable_paths,
    read_capability_map,
    validate_map_report,
    write_capability_map,
    write_tool_snapshot,
)

if TYPE_CHECKING:
    from pathlib import Path


def _workspace(root: Path) -> Path:
    root.mkdir(parents=True)
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "browser": {
                        "command": "npx",
                        "args": ["server", "--token", "do-not-record-this"],
                        "url": "https://user:password@example.test/mcp?token=secret",
                        "env": {
                            "BROWSER_TOKEN": "do-not-record-this",
                            "REGION": "test",
                        },
                        "tools": [
                            {
                                "name": "open_page",
                                "description": "Open an authorized test page",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "url": {"type": "string"},
                                        "api_key": {"type": "string", "default": "hidden"},
                                    },
                                },
                            }
                        ],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (root / ".env").write_text("REAL_SECRET=not-readable\n", encoding="utf-8")
    (root / "tools.py").write_text(
        "def tool(fn): return fn\n@tool\ndef inspect_fixture(): return None\n",
        encoding="utf-8",
    )
    return root


def test_mapper_never_emits_secret_values_and_separates_closure(tmp_path: Path) -> None:
    root = _workspace(tmp_path / "project")
    report = build_capability_map(root)
    document = report.to_mapping()
    validate_map_report(document)
    encoded = canonical_json_bytes(document)
    assert b"do-not-record-this" not in encoded
    assert b"password" not in encoded
    assert b"token=secret" not in encoded
    assert b"not-readable" not in encoded
    assert b"BROWSER_TOKEN" in encoded
    assert document["claims"] == {
        "executedVulnerability": False,
        "safeOrClean": False,
        "inferenceIsEvidence": False,
    }
    assert document["closures"]["declared"]
    assert document["closures"]["possible"]
    assert not document["closures"]["witnessLinked"]
    assert {item["risk"] for item in document["inventory"]} >= {"info", "high", "medium"}
    codes = {finding["code"] for finding in document["findings"]}
    assert "SOVA-MAP-CREDENTIAL-PATH" in codes
    assert "SOVA-MAP-EGRESS-PATH" in codes
    env_input = next(item for item in document["inputs"] if item["kind"] == "environment-file")
    assert env_input["status"] == "name-only"


def test_cross_machine_discovery_projection_uses_relative_paths(tmp_path: Path) -> None:
    first = _workspace(tmp_path / "one" / "project")
    second = _workspace(tmp_path / "two" / "project")
    assert discovery_projection(discover_workspace(first)) == discovery_projection(
        discover_workspace(second)
    )


def test_observed_inventory_requires_authorization_and_keeps_witness_closure(
    tmp_path: Path,
) -> None:
    root = _workspace(tmp_path / "project")
    inventory = tmp_path / "observed.json"
    inventory.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "runtime-only": {
                        "command": "runtime-server",
                        "tools": [{"name": "observed_tool", "inputSchema": {}}],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    result = discover_workspace(root)
    with pytest.raises(FormatError, match="authorization"):
        import_inventory(result, inventory, observed=True)
    report = build_capability_map(
        root,
        observed_inventories=(inventory,),
        runtime_authorized=True,
    ).to_mapping()
    assert report["closures"]["witnessLinked"]
    assert any(
        finding["code"] == "SOVA-MAP-UNDECLARED-OBSERVED-REACH" for finding in report["findings"]
    )
    observed_edges = [
        edge for edge in report["graph"]["edges"] if edge["evidenceClass"] == "observed"
    ]
    assert observed_edges
    assert all(edge["attributes"]["witnessRefs"] for edge in observed_edges)


def test_tool_snapshot_detects_schema_drift_and_refuses_overwrite(tmp_path: Path) -> None:
    root = _workspace(tmp_path / "project")
    graph = discover_workspace(root).graph
    snapshot = tmp_path / "approved.json"
    digest = write_tool_snapshot(snapshot, graph)
    assert digest.startswith("sha256:")
    with pytest.raises(FormatError, match="already exists"):
        write_tool_snapshot(snapshot, graph)
    document = json.loads((root / ".mcp.json").read_text(encoding="utf-8"))
    document["mcpServers"]["browser"]["tools"][0]["inputSchema"]["required"] = ["url"]
    (root / ".mcp.json").write_text(json.dumps(document), encoding="utf-8")
    drift = compare_tool_snapshot(snapshot, discover_workspace(root).graph)
    assert any(change["classification"] == "input-schema-change" for change in drift)
    assert all(change["risk"] in {"review", "high"} for change in drift)


def test_map_report_round_trip_and_tamper_detection(tmp_path: Path) -> None:
    root = _workspace(tmp_path / "project")
    output = tmp_path / "result.sova-map.json"
    digest = write_capability_map(output, build_capability_map(root))
    assert read_capability_map(output)["contentDigest"] == digest
    with pytest.raises(FormatError, match="already exists"):
        write_capability_map(output, build_capability_map(root))
    tampered = json.loads(output.read_text(encoding="utf-8"))
    tampered["limitations"].append("tampered")
    with pytest.raises(FormatError, match="digest mismatch"):
        validate_map_report(tampered)


def test_malformed_declaration_is_partial_not_a_crash(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / ".mcp.json").write_text("{", encoding="utf-8")
    result = discover_workspace(root)
    assert any("Could not parse" in limitation for limitation in result.limitations)
    assert result.graph.nodes


def test_generic_inventory_models_identity_permission_approval_and_refutation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "project"
    (root / "worker").mkdir(parents=True)
    (root / "worker" / "AGENTS.md").write_text("Worker instructions", encoding="utf-8")
    inventory = tmp_path / "inventory.json"
    inventory.write_text(
        json.dumps(
            {
                "nodes": [
                    {"key": "identity", "kind": "identity", "name": "synthetic-user"},
                    {"key": "permission", "kind": "permission", "name": "fixture.read"},
                    {"key": "gate", "kind": "approval-gate", "name": "human approval"},
                ],
                "edges": [
                    {
                        "source": "workspace",
                        "target": "identity",
                        "kind": "uses",
                    },
                    {
                        "source": "identity",
                        "target": "permission",
                        "kind": "grants",
                    },
                    {
                        "source": "permission",
                        "target": "gate",
                        "kind": "protected-by",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    report = build_capability_map(root, inventories=(inventory,)).to_mapping()
    kinds = {node["kind"] for node in report["graph"]["nodes"]}
    assert {"sub-agent", "identity", "permission", "approval-gate"}.issubset(kinds)
    assert any(
        finding["code"] == "SOVA-MAP-POSSIBLE-PERMISSION-ROT" for finding in report["findings"]
    )

    refutation = tmp_path / "refutation.json"
    refutation.write_text(
        json.dumps(
            {
                "nodes": [{"key": "identity", "kind": "identity", "name": "synthetic-user"}],
                "edges": [
                    {
                        "source": "workspace",
                        "target": "identity",
                        "kind": "uses",
                        "evidenceClass": "refuted",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    observed = build_capability_map(
        root,
        observed_inventories=(refutation,),
        runtime_authorized=True,
    ).to_mapping()
    assert observed["closures"]["conflicts"]


def test_all_static_declaration_collectors_and_partial_inputs(tmp_path: Path) -> None:
    root = tmp_path / "project"
    (root / ".codex-plugin").mkdir(parents=True)
    (root / ".codex-plugin" / "plugin.json").write_text(
        '{"name":"fixture-plugin","version":"1"}', encoding="utf-8"
    )
    (root / "package.json").write_text(
        '{"name":"fixture-js","version":"1","scripts":{"test":"fixture"},'
        '"dependencies":{"dep":"1"}}',
        encoding="utf-8",
    )
    (root / "pyproject.toml").write_text(
        '[project]\nname="fixture-python"\nversion="0.1"\n'
        'dependencies=["dep"]\n[project.scripts]\nfixture="fixture:main"\n',
        encoding="utf-8",
    )
    (root / "config.toml").write_text(
        '[mcpServers.local]\ncommand="fixture"\n'
        '[[mcpServers.local.tools]]\nname="inspect"\ndescription="Inspect"\n',
        encoding="utf-8",
    )
    skill = root / "skills" / "fixture"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: fixture-skill\n---\n", encoding="utf-8")
    (root / "AGENTS.md").write_text("root", encoding="utf-8")
    worker = root / "worker"
    worker.mkdir()
    (worker / "AGENTS.md").write_text("worker", encoding="utf-8")
    (root / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    (root / "bad.toml").write_text("invalid = [", encoding="utf-8")
    (root / "array.json").write_text("[]", encoding="utf-8")
    (root / "oversized.json").write_bytes(b" " * 1_048_577)
    ignored_cache = root / ".uv-cache"
    ignored_cache.mkdir()
    (ignored_cache / "package.json").write_text("{", encoding="utf-8")

    result = discover_workspace(root)
    kinds = {node.kind for node in result.graph.nodes.values()}
    assert {
        NodeKind.PLUGIN,
        NodeKind.PACKAGE,
        NodeKind.TOOL,
        NodeKind.SKILL,
        NodeKind.SUB_AGENT,
        NodeKind.MCP_SERVER,
    }.issubset(kinds)
    assert any("Could not parse" in item for item in result.limitations)
    assert any("Could not parse Python" in item for item in result.limitations)

    with pytest.raises(FormatError, match="existing directory"):
        discover_workspace(root / "missing")


@pytest.mark.parametrize(
    "document, message",
    [
        ([], "root"),
        ({"nodes": [1], "edges": []}, "node must"),
        ({"nodes": [{"name": "n", "kind": "tool"}], "edges": []}, "key"),
        ({"nodes": [{"key": "n", "kind": "tool"}], "edges": []}, "name"),
        ({"nodes": [{"key": "n", "name": "n"}], "edges": []}, "kind"),
        (
            {"nodes": [{"key": "n", "name": "n", "kind": "unknown"}], "edges": []},
            "unsupported inventory node kind",
        ),
        (
            {
                "nodes": [{"key": "n", "name": "n", "kind": "tool", "attributes": []}],
                "edges": [],
            },
            "node attributes",
        ),
        ({"nodes": [], "edges": [1]}, "edge must"),
        ({"nodes": [], "edges": [{"target": "workspace", "kind": "uses"}]}, "source"),
        ({"nodes": [], "edges": [{"source": "workspace", "kind": "uses"}]}, "target"),
        (
            {"nodes": [], "edges": [{"source": "workspace", "target": "workspace"}]},
            "kind",
        ),
        (
            {
                "nodes": [],
                "edges": [{"source": "workspace", "target": "missing", "kind": "uses"}],
            },
            "unknown endpoint",
        ),
        (
            {
                "nodes": [],
                "edges": [{"source": "workspace", "target": "workspace", "kind": "unknown"}],
            },
            "unsupported inventory edge kind",
        ),
        (
            {
                "nodes": [],
                "edges": [
                    {
                        "source": "workspace",
                        "target": "workspace",
                        "kind": "uses",
                        "attributes": [],
                    }
                ],
            },
            "edge attributes",
        ),
        ({"unsupported": True}, "supported mcpServers"),
    ],
)
def test_hostile_inventory_shapes_fail_visibly(
    tmp_path: Path,
    document: object,
    message: str,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    result = discover_workspace(root)
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(FormatError, match=message):
        import_inventory(result, inventory)


def test_inventory_requires_workspace_node(tmp_path: Path) -> None:
    inventory = tmp_path / "inventory.json"
    inventory.write_text('{"nodes":[],"edges":[]}', encoding="utf-8")
    with pytest.raises(FormatError, match="workspace node"):
        import_inventory(DiscoveryResult(), inventory)


def test_generic_inventory_redacts_secret_patterns_arguments_and_key_fields(
    tmp_path: Path,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    inventory = tmp_path / "inventory.json"
    inventory.write_text(
        json.dumps(
            {
                "nodes": [
                    {
                        "key": "tool",
                        "name": "tool",
                        "kind": "tool",
                        "attributes": {
                            "apiKey": "must-not-appear",
                            "headers": ["Bearer must-not-appear"],
                            "note": "xo" + "xb-must-not-appear",
                        },
                    }
                ],
                "edges": [{"source": "workspace", "target": "tool", "kind": "uses"}],
            }
        ),
        encoding="utf-8",
    )
    encoded = canonical_json_bytes(
        build_capability_map(root, inventories=(inventory,)).to_mapping()
    )
    assert b"must-not-appear" not in encoded
    assert b"redacted" in encoded


def _tool_graph(
    *,
    name: str = "tool",
    description: str = "d",
    schema: object = None,
    entrypoint: str | None = "fixture:main",
) -> CapabilityGraph:
    graph = CapabilityGraph()
    provenance = projected_provenance("fixture", "$", EvidenceClass.DECLARED, {})
    graph.add_node(
        NodeKind.TOOL,
        "stable-tool",
        name,
        attributes={
            "description": description,
            "inputSchema": {} if schema is None else schema,
            "entrypoint": entrypoint,
        },
        provenance=provenance,
    )
    return graph


@pytest.mark.parametrize(
    "changed, classification",
    [
        ({"description": "changed"}, "description-change"),
        ({"entrypoint": "other:main"}, "entrypoint-change"),
        ({"name": "renamed"}, "semantic-unknown"),
    ],
)
def test_tool_snapshot_classifies_non_schema_changes(
    tmp_path: Path,
    changed: dict[str, str],
    classification: str,
) -> None:
    snapshot = tmp_path / "snapshot.json"
    write_tool_snapshot(snapshot, _tool_graph())
    current = _tool_graph(**changed)
    assert compare_tool_snapshot(snapshot, current)[0]["classification"] == classification


def test_tool_snapshot_add_remove_and_hostile_snapshots(tmp_path: Path) -> None:
    empty = CapabilityGraph()
    populated = _tool_graph()
    baseline_empty = tmp_path / "empty.json"
    write_tool_snapshot(baseline_empty, empty)
    assert compare_tool_snapshot(baseline_empty, populated)[0]["classification"] == "added"
    baseline_populated = tmp_path / "populated.json"
    write_tool_snapshot(baseline_populated, populated)
    assert compare_tool_snapshot(baseline_populated, empty)[0]["classification"] == "removed"

    malformed = tmp_path / "malformed.json"
    malformed.write_text("[]", encoding="utf-8")
    with pytest.raises(FormatError, match="unsupported"):
        compare_tool_snapshot(malformed, empty)
    document = json.loads(baseline_empty.read_text(encoding="utf-8"))
    document["contentDigest"] = "sha256:" + "0" * 64
    malformed.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(FormatError, match="digest mismatch"):
        compare_tool_snapshot(malformed, empty)
    document.pop("contentDigest")
    document["tools"] = []
    document["contentDigest"] = sha256_digest(canonical_json_bytes(document))
    malformed.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(FormatError, match="tools must"):
        compare_tool_snapshot(malformed, empty)


def test_graph_invariants_reach_depth_approval_gap_and_report_links(tmp_path: Path) -> None:
    provenance = projected_provenance("fixture", "$", EvidenceClass.DECLARED, {})
    graph = CapabilityGraph()
    agent = graph.add_node(NodeKind.AGENT, "agent", "agent", provenance=provenance)
    first = graph.add_node(NodeKind.TOOL, "first", "first", provenance=provenance)
    high = graph.add_node(
        NodeKind.EXTERNAL_SYSTEM,
        "high",
        "high",
        attributes={"consequence": "high", "external": True},
        provenance=provenance,
    )
    graph.add_node(
        NodeKind.TOOL,
        "first",
        "first",
        attributes={"merged": True},
        provenance=projected_provenance("fixture-2", "$", EvidenceClass.DECLARED, {}),
    )
    edge = graph.add_edge(
        agent,
        first,
        EdgeKind.USES,
        evidence_class=EvidenceClass.DECLARED,
        provenance=provenance,
    )
    graph.add_edge(
        first,
        high,
        EdgeKind.REACHES,
        evidence_class=EvidenceClass.INFERRED,
        provenance=provenance,
    )
    assert reachable_paths(graph, agent, max_depth=1) == {first: (edge,)}
    assert capability_closures(graph)["possible"]
    assert "SOVA-MAP-APPROVAL-GAP" in {item.code for item in analyze_capability_graph(graph)}
    with pytest.raises(FormatError, match="endpoints"):
        graph.add_edge(
            agent,
            "missing",
            EdgeKind.USES,
            evidence_class=EvidenceClass.DECLARED,
            provenance=provenance,
        )
    with pytest.raises(FormatError, match="source and pointer"):
        Provenance("", "$", EvidenceClass.DECLARED, "sha256:" + "1" * 64)
    with pytest.raises(FormatError, match="SHA-256"):
        Provenance("fixture", "$", EvidenceClass.DECLARED, "bad")

    root = _workspace(tmp_path / "mapped")
    valid = build_capability_map(root).to_mapping()
    valid["graph"]["edges"][0]["target"] = "map:tool:" + "f" * 32
    valid.pop("contentDigest")
    valid["contentDigest"] = sha256_digest(canonical_json_bytes(valid))
    with pytest.raises(FormatError, match="dangling edge"):
        validate_map_report(valid)

    valid = build_capability_map(root).to_mapping()
    valid["findings"][0]["nodeIds"] = ["map:tool:" + "e" * 32]
    valid.pop("contentDigest")
    valid["contentDigest"] = sha256_digest(canonical_json_bytes(valid))
    with pytest.raises(FormatError, match="unknown node"):
        validate_map_report(valid)

    valid = build_capability_map(root).to_mapping()
    valid["findings"][0]["edgeIds"] = ["map:edge:" + "d" * 32]
    valid.pop("contentDigest")
    valid["contentDigest"] = sha256_digest(canonical_json_bytes(valid))
    with pytest.raises(FormatError, match="unknown edge"):
        validate_map_report(valid)

    not_object = tmp_path / "not-object.json"
    not_object.write_text("[]", encoding="utf-8")
    with pytest.raises(FormatError, match="root"):
        read_capability_map(not_object)
