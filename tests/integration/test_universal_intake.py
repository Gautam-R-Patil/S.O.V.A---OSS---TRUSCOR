# SPDX-License-Identifier: Apache-2.0
"""Owned multi-surface acceptance test for universal target intake."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from sova.formats import PackageReader
from sova.intake import (
    EntryPoint,
    EntryPointKind,
    InputKind,
    ProfileTargetKind,
    SourceClass,
    TargetProfile,
    describe_material,
    read_intake_report,
    run_universal_intake,
)
from sova.trace import TraceReader

if TYPE_CHECKING:
    from pathlib import Path


def _json_material(root: Path, name: str, value: Any) -> Path:
    path = root / name
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    return path


def test_owned_composite_intake_covers_every_p1_target_class(tmp_path: Path) -> None:
    source = tmp_path / "owned-source"
    source.mkdir()
    (source / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {"fixture-lib": "1.0.0"},
                "scripts": {"start": "node app.js"},
            }
        ),
        encoding="utf-8",
    )
    (source / "Dockerfile").write_text(
        "FROM scratch\nUSER 1000\nEXPOSE 8080\n",
        encoding="utf-8",
    )
    (source / ".env.example").write_text("API_KEY=\n", encoding="utf-8")
    html = tmp_path / "index.html"
    html.write_text(
        '<a href="/orders">Orders</a><form action="/login" method="post">'
        '<input name="username"><input type="password" name="password"></form>',
        encoding="utf-8",
    )
    graphql = tmp_path / "schema.graphql"
    graphql.write_text(
        "type Query { viewer: User } type Mutation { login: Session }", encoding="utf-8"
    )
    lockfile = tmp_path / "requirements.txt"
    lockfile.write_text("requests==2.32.0\n", encoding="utf-8")

    materials: list[tuple[str, InputKind, SourceClass, Path]] = [
        ("html", InputKind.HTML, SourceClass.SUPPLIED, html),
        (
            "web-inventory",
            InputKind.WEB_INVENTORY,
            SourceClass.PASSIVE,
            _json_material(
                tmp_path,
                "web-inventory.json",
                {
                    "pages": [
                        {
                            "url": "https://owned.example/app",
                            "robots": {"allow": "/", "disallow": "/private"},
                            "policies": [{"kind": "security.txt", "present": True}],
                            "routes": ["/orders"],
                            "forms": [
                                {
                                    "action": "/upload",
                                    "method": "post",
                                    "inputs": [{"name": "file", "type": "file"}],
                                }
                            ],
                            "serviceWorkers": ["/service-worker.js"],
                            "webSockets": ["wss://owned.example/events"],
                            "downloads": ["/exports/orders.csv"],
                            "uploads": ["/upload"],
                            "storage": [{"kind": "indexeddb"}],
                            "authenticationTransitions": [
                                {"from": "anonymous", "to": "member", "trigger": "login"}
                            ],
                        }
                    ]
                },
            ),
        ),
        (
            "har",
            InputKind.HAR,
            SourceClass.PASSIVE,
            _json_material(
                tmp_path,
                "session.har",
                {
                    "log": {
                        "entries": [
                            {
                                "request": {
                                    "method": "GET",
                                    "url": "https://owned.example/api/orders?id=",
                                    "headers": [{"name": "Authorization", "value": "omitted"}],
                                    "queryString": [{"name": "id", "value": "omitted"}],
                                },
                                "response": {"status": 200},
                            }
                        ]
                    }
                },
            ),
        ),
        (
            "openapi",
            InputKind.OPENAPI,
            SourceClass.SUPPLIED,
            _json_material(
                tmp_path,
                "openapi.json",
                {
                    "openapi": "3.1.0",
                    "paths": {
                        "/orders/{id}": {
                            "get": {
                                "operationId": "getOrder",
                                "parameters": [{"name": "id", "in": "path", "required": True}],
                                "responses": {
                                    "200": {
                                        "description": "owned fixture",
                                        "links": {
                                            "createRelated": {
                                                "operationId": "createOrder",
                                                "parameters": {"sourceId": "$response.body#/id"},
                                            }
                                        },
                                    }
                                },
                            }
                        },
                        "/orders": {
                            "post": {
                                "operationId": "createOrder",
                                "responses": {"201": {"description": "created"}},
                            }
                        },
                    },
                },
            ),
        ),
        ("graphql", InputKind.GRAPHQL_SCHEMA, SourceClass.SUPPLIED, graphql),
        (
            "grpc",
            InputKind.GRPC_DESCRIPTOR,
            SourceClass.SUPPLIED,
            _json_material(
                tmp_path,
                "grpc.json",
                {
                    "services": [
                        {
                            "name": "Orders",
                            "methods": [{"name": "Get", "input": "OrderId", "output": "Order"}],
                        }
                    ]
                },
            ),
        ),
        (
            "postman",
            InputKind.POSTMAN,
            SourceClass.SUPPLIED,
            _json_material(
                tmp_path,
                "postman.json",
                {
                    "item": [
                        {
                            "request": {
                                "method": "POST",
                                "url": "https://owned.example/api/orders",
                            }
                        }
                    ]
                },
            ),
        ),
        ("source", InputKind.SOURCE_TREE, SourceClass.STATIC, source),
        (
            "sbom",
            InputKind.SBOM,
            SourceClass.SUPPLIED,
            _json_material(
                tmp_path,
                "sbom.json",
                {
                    "components": [{"name": "fixture-lib", "version": "1.0.0", "type": "library"}],
                    "vulnerabilities": [
                        {
                            "id": "CVE-FIXTURE-0001",
                            "ratings": [{"severity": "low"}],
                            "affects": [{"ref": "fixture-lib"}],
                        }
                    ],
                },
            ),
        ),
        ("lock", InputKind.LOCKFILE, SourceClass.SUPPLIED, lockfile),
        (
            "oci-manifest",
            InputKind.OCI_MANIFEST,
            SourceClass.SUPPLIED,
            _json_material(
                tmp_path,
                "oci-manifest.json",
                {
                    "config": {
                        "digest": "sha256:" + "1" * 64,
                        "mediaType": "application/json",
                        "size": 1,
                    },
                    "layers": [],
                },
            ),
        ),
        (
            "oci-config",
            InputKind.OCI_CONFIG,
            SourceClass.SUPPLIED,
            _json_material(
                tmp_path,
                "oci-config.json",
                {
                    "config": {
                        "User": "1000",
                        "Env": ["MODE=owned"],
                        "ExposedPorts": {"8080/tcp": {}},
                    }
                },
            ),
        ),
        (
            "oci-runtime",
            InputKind.OCI_INVENTORY,
            SourceClass.PASSIVE,
            _json_material(
                tmp_path,
                "oci-runtime.json",
                {
                    "capabilities": [],
                    "mounts": [],
                    "ports": [8080],
                    "networkMode": "none",
                    "privileged": False,
                },
            ),
        ),
        (
            "network",
            InputKind.NETWORK_INVENTORY,
            SourceClass.PASSIVE,
            _json_material(
                tmp_path,
                "network.json",
                {
                    "hosts": [
                        {
                            "address": "127.0.0.1",
                            "services": [{"port": 8080, "protocol": "tcp", "service": "http"}],
                        }
                    ],
                    "dnsRelationships": [
                        {
                            "source": "owned.example",
                            "target": "127.0.0.1",
                            "recordType": "A",
                        }
                    ],
                    "segments": [
                        {
                            "id": "loopback",
                            "cidrs": ["127.0.0.0/8"],
                            "members": ["127.0.0.1"],
                            "controls": ["owned-only"],
                        }
                    ],
                    "segmentationEvidence": [{"fixture": True}],
                },
            ),
        ),
        (
            "tls",
            InputKind.TLS_REPORT,
            SourceClass.PASSIVE,
            _json_material(
                tmp_path,
                "tls.json",
                {
                    "protocols": ["TLSv1.3"],
                    "ciphers": ["fixture"],
                    "certificates": [],
                    "issues": [],
                },
            ),
        ),
        (
            "process",
            InputKind.PROCESS_INVENTORY,
            SourceClass.PASSIVE,
            _json_material(
                tmp_path,
                "process.json",
                {
                    "processes": [
                        {
                            "executable": "owned.exe",
                            "generation": 1,
                            "elevated": True,
                            "sideEffects": ["filesystem.write", "network.loopback"],
                            "crossProcessTargets": ["owned-helper.exe"],
                            "windows": [{"role": "window", "automationId": "main"}],
                        }
                    ]
                },
            ),
        ),
        (
            "accessibility",
            InputKind.ACCESSIBILITY_TREE,
            SourceClass.PASSIVE,
            _json_material(
                tmp_path,
                "accessibility.json",
                {
                    "nodes": [
                        {
                            "role": "button",
                            "automationId": "submit",
                            "actions": ["invoke"],
                            "enabled": True,
                        }
                    ]
                },
            ),
        ),
        (
            "agent",
            InputKind.AGENT_MANIFEST,
            SourceClass.SUPPLIED,
            _json_material(
                tmp_path,
                "agent.json",
                {
                    "name": "owned-agent",
                    "provider": "fixture",
                    "model": "fixture-model",
                    "tools": [{"name": "lookup", "inputSchema": {"type": "object"}}],
                    "memory": {"kind": "ephemeral"},
                    "identity": {"scheme": "fixture"},
                    "prompts": [{"id": "system"}],
                    "policies": [{"id": "owned-only"}],
                    "skills": [{"id": "lookup"}],
                    "protocols": ["mcp"],
                    "handoffs": [{"target": "reviewer", "condition": "review"}],
                    "consequentialActions": [{"kind": "fixture-write"}],
                },
            ),
        ),
        (
            "mcp",
            InputKind.MCP_MANIFEST,
            SourceClass.SUPPLIED,
            _json_material(
                tmp_path,
                "mcp.json",
                {
                    "mcpServers": {"owned": {"url": "http://127.0.0.1:9000/mcp"}},
                    "tools": [{"name": "read_fixture", "inputSchema": {}}],
                },
            ),
        ),
        (
            "a2a",
            InputKind.A2A_CARD,
            SourceClass.SUPPLIED,
            _json_material(
                tmp_path,
                "a2a.json",
                {
                    "name": "owned-a2a",
                    "url": "http://127.0.0.1:9001/a2a",
                    "skills": [{"id": "summarize"}],
                    "authentication": {"schemes": ["none"]},
                },
            ),
        ),
    ]
    descriptors = tuple(
        describe_material(path, identifier=identifier, kind=kind, source_class=source_class)
        for identifier, kind, source_class, path in materials
    )
    bindings = {identifier: path for identifier, _kind, _source, path in materials}
    profile = TargetProfile(
        identifier="owned-all-surfaces",
        version="0.1.0",
        title="Owned all-surface fixture",
        target_kinds=tuple(ProfileTargetKind),
        authorization_scope="owned deterministic fixture only",
        entrypoints=(
            EntryPoint(
                "web",
                EntryPointKind.URL,
                "https://owned.example/app",
                (ProfileTargetKind.WEB, ProfileTargetKind.API, ProfileTargetKind.THIRD_PARTY),
            ),
            EntryPoint(
                "desktop",
                EntryPointKind.PROCESS,
                "owned.exe",
                (ProfileTargetKind.DESKTOP,),
            ),
        ),
        inputs=descriptors,
        constraints={"networkCollectionDefault": "disabled"},
        provenance=({"source": "owned-test-fixture", "evidenceClass": "declared"},),
    )

    artifacts = run_universal_intake(profile, bindings, tmp_path / "intake")
    report = read_intake_report(artifacts.report)
    TraceReader(artifacts.trace).verify()
    PackageReader(artifacts.capsule).verify("sova.capsule")

    states = {
        item["subject"]: item["state"]
        for item in report["coverage"]["items"]
        if item["dimension"] == "target-kind"
    }
    assert set(states) == {kind.value for kind in ProfileTargetKind}
    assert states["third-party-service"] == "unknown"
    assert states["web"] == "discovered"
    assert report["status"] == "partial"
    assert report["claims"] == {
        "targetCodeExecuted": False,
        "activeObservationsIndependentlyAttested": False,
        "inferenceIsExecutionEvidence": False,
        "allWorkflowsUnderstood": False,
        "allAttackSurfacesEnumerated": False,
        "allVulnerabilitiesFound": False,
        "safeOrClean": False,
    }
    assert len(report["workflowGraph"]["nodes"]) >= 10
    assert any(
        edge["kind"] == "stateful-operation-link" and edge["attributes"]["targetResolved"] is True
        for edge in report["workflowGraph"]["edges"]
    )
    assert len(report["attackSurfaceGraph"]["nodes"]) >= 30
    surface_kinds = {item["kind"] for item in report["attackSurfaceGraph"]["nodes"]}
    assert {"privilege", "trust-boundary", "data-flow", "configuration"} <= surface_kinds
    assert all(item["status"] == "parsed" for item in report["inputs"])
