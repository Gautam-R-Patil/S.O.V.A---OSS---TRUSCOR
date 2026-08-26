# SPDX-License-Identifier: Apache-2.0
"""Fail-closed and alternate-format coverage for universal target intake."""

from __future__ import annotations

import copy
import io
import json
import tarfile
import zipfile
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pytest

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.intake import (
    CredentialReference,
    EntryPoint,
    EntryPointKind,
    EnvironmentConstraint,
    InputDescriptor,
    InputKind,
    ProfileTargetKind,
    SourceClass,
    TargetProfile,
    materials,
    read_intake_report,
    read_target_profile,
    run_universal_intake,
    target_profile_from_mapping,
    target_profile_template,
    validate_intake_report,
)
from sova.intake.frontends import (
    IntakeDiscovery,
    _header_names,
    _list,
    _mapping,
    _postman_requests,
    _postman_url,
    _query_names,
    _safe_url_projection,
    _source_file_category,
    discover_material,
)
from sova.intake.materials import (
    LoadedMaterial,
    _read_archive,
    _read_tree,
    _safe_archive_name,
    finalize_material_fingerprints,
    fingerprint_material_path,
    load_profile_materials,
)
from sova.intake.model import (
    CoverageContract,
    CoverageItem,
    CoverageState,
    GenerationState,
    IntakeEdge,
    IntakeGraph,
    IntakeNode,
    IntakeProvenance,
    WorkflowNodeKind,
    intake_provenance,
)
from sova.mapping import EvidenceClass

if TYPE_CHECKING:
    from collections.abc import Callable

_DIGEST = "sha256:" + "1" * 64


def _all_kind_profile() -> TargetProfile:
    return TargetProfile(
        identifier="edge-all",
        version="0.1.0",
        title="Owned intake edge fixture",
        target_kinds=tuple(ProfileTargetKind),
        authorization_scope="owned fixture only",
        entrypoints=(
            EntryPoint(
                "url", EntryPointKind.URL, "https://example.invalid/app", (ProfileTargetKind.WEB,)
            ),
            EntryPoint(
                "host", EntryPointKind.HOST, "example.invalid", (ProfileTargetKind.NETWORK,)
            ),
            EntryPoint("cidr", EntryPointKind.CIDR, "127.0.0.0/8", (ProfileTargetKind.NETWORK,)),
            EntryPoint(
                "package", EntryPointKind.PACKAGE, "fixture-package", (ProfileTargetKind.PACKAGE,)
            ),
            EntryPoint(
                "process", EntryPointKind.PROCESS, "fixture.exe", (ProfileTargetKind.DESKTOP,)
            ),
            EntryPoint("agent", EntryPointKind.AGENT, "fixture-agent", (ProfileTargetKind.AGENT,)),
        ),
        credential_references=(
            CredentialReference("sova-secret:fixture", "test authority", ("read",), required=True),
        ),
        environments=(EnvironmentConstraint("windows", "windows", "amd64", ("owned",)),),
    )


def _material(
    kind: InputKind,
    *,
    value: Any | None = None,
    text: str | None = None,
    files: dict[str, bytes] | None = None,
    source_class: SourceClass = SourceClass.SUPPLIED,
) -> LoadedMaterial:
    payload = None
    if value is not None:
        payload = json.dumps(value).encode()
    elif text is not None:
        payload = text.encode()
    descriptor = InputDescriptor(
        id=f"edge-{kind.value}",
        kind=kind,
        source_class=source_class,
        logical_locator="fixture.bin",
        media_type="application/json",
        expected_digest=_DIGEST,
    )
    return LoadedMaterial(descriptor, Path("fixture.bin"), _DIGEST, payload, files or {})


@pytest.mark.parametrize(
    "factory,match",
    [
        (
            lambda: EntryPoint("bad id", EntryPointKind.HOST, "host", (ProfileTargetKind.NETWORK,)),
            "identifier",
        ),
        (
            lambda: EntryPoint(
                "host", EntryPointKind.HOST, "bad/host", (ProfileTargetKind.NETWORK,)
            ),
            "host",
        ),
        (
            lambda: EntryPoint("cidr", EntryPointKind.CIDR, "bad", (ProfileTargetKind.NETWORK,)),
            "CIDR",
        ),
        (
            lambda: EntryPoint(
                "url", EntryPointKind.URL, "ftp://example.invalid", (ProfileTargetKind.WEB,)
            ),
            "scheme",
        ),
        (
            lambda: EntryPoint(
                "url", EntryPointKind.URL, "https://user@example.invalid", (ProfileTargetKind.WEB,)
            ),
            "user info",
        ),
        (
            lambda: EntryPoint(
                "url", EntryPointKind.URL, "https://example.invalid/?x=1", (ProfileTargetKind.WEB,)
            ),
            "query",
        ),
        (lambda: EntryPoint("host", EntryPointKind.HOST, "host", ()), "non-empty"),
        (
            lambda: InputDescriptor(
                "x", InputKind.HTML, SourceClass.SUPPLIED, "../x", "text/html", _DIGEST
            ),
            "portable",
        ),
        (
            lambda: InputDescriptor("x", InputKind.HTML, SourceClass.SUPPLIED, "x", "bad", _DIGEST),
            "media",
        ),
        (
            lambda: InputDescriptor(
                "x", InputKind.HTML, SourceClass.SUPPLIED, "x", "text/html", "bad"
            ),
            "SHA-256",
        ),
        (lambda: CredentialReference("env:KEY", "purpose", ("read",)), "opaque"),
        (lambda: CredentialReference("sova-secret:x", "purpose", ()), "non-empty"),
        (lambda: EnvironmentConstraint("env", "windows", None, ("x", "x")), "unique"),
    ],
)
def test_profile_nested_contracts_reject_unsafe_values(
    factory: Callable[[], object],
    match: str,
) -> None:
    with pytest.raises(FormatError, match=match):
        factory()


def test_profile_rejects_unsafe_configuration_and_cross_contract_duplicates() -> None:
    base = target_profile_template(
        identifier="edge",
        title="Edge",
        target_kinds=(ProfileTargetKind.WEB,),
        authorization_scope="owned fixture only",
    )
    with pytest.raises(FormatError, match="keys must be strings"):
        replace(base, constraints=cast("dict[str, Any]", {1: "x"}))
    with pytest.raises(FormatError, match="secret-bearing"):
        replace(base, constraints={"api_key": "redacted"})
    with pytest.raises(FormatError, match="unsupported"):
        replace(base, constraints={"ratio": 1.5})
    entry = EntryPoint(
        "web", EntryPointKind.URL, "https://example.invalid", (ProfileTargetKind.WEB,)
    )
    with pytest.raises(FormatError, match="unique"):
        replace(base, entrypoints=(entry, entry))
    with pytest.raises(FormatError, match="not declared"):
        replace(
            base,
            entrypoints=(
                EntryPoint(
                    "api", EntryPointKind.API, "https://example.invalid", (ProfileTargetKind.API,)
                ),
            ),
        )


def test_profile_parser_rejects_fields_types_and_enums() -> None:
    document = _all_kind_profile().to_mapping()
    cases: list[tuple[dict[str, Any], str]] = [
        ({**document, "extra": True}, "missing or unknown"),
        ({**document, "schemaVersion": "9.9.9"}, "unsupported"),
        ({**document, "constraints": []}, "objects"),
        ({**document, "targetKinds": [1]}, "array type"),
        ({**document, "entrypoints": [1]}, "object array"),
        ({**document, "identifier": 1}, "string"),
        ({**document, "legacyTargetManifest": []}, "object or null"),
    ]
    bad_enum = copy.deepcopy(document)
    bad_enum["targetKinds"] = ["not-a-kind"]
    cases.append((bad_enum, "enum"))
    bad_optional = copy.deepcopy(document)
    bad_optional["environments"][0]["architecture"] = 1
    cases.append((bad_optional, "enum"))
    bad_bool = copy.deepcopy(document)
    bad_bool["inputs"] = [
        {
            "id": "x",
            "kind": "html",
            "sourceClass": "supplied",
            "logicalLocator": "x",
            "mediaType": "text/html",
            "expectedDigest": _DIGEST,
            "required": 1,
        }
    ]
    cases.append((bad_bool, "enum"))
    for value, match in cases:
        with pytest.raises(FormatError, match=match):
            target_profile_from_mapping(value)


def test_material_loading_missing_unknown_drift_and_finalize_unavailable(tmp_path: Path) -> None:
    source = tmp_path / "source.json"
    source.write_text("{}", encoding="utf-8")
    descriptor = InputDescriptor(
        "input",
        InputKind.OPENAPI,
        SourceClass.SUPPLIED,
        "source.json",
        "application/json",
        fingerprint_material_path(source, kind=InputKind.OPENAPI),
    )
    profile = replace(
        target_profile_template(
            identifier="materials",
            title="Materials",
            target_kinds=(ProfileTargetKind.API,),
            authorization_scope="owned fixture only",
        ),
        inputs=(descriptor,),
    )
    with pytest.raises(FormatError, match="unknown input"):
        load_profile_materials(profile, {"absent": source})
    missing = load_profile_materials(profile, {})
    assert missing.fingerprints[0].state == GenerationState.INCOMPLETE

    loaded = load_profile_materials(profile, {"input": source})
    source.unlink()
    assert (
        finalize_material_fingerprints(loaded)[0].reason == "material-unavailable-after-discovery"
    )

    changed = tmp_path / "changed.json"
    changed.write_text('{"changed":true}', encoding="utf-8")
    drift = load_profile_materials(profile, {"input": changed})
    assert drift.fingerprints[0].state == GenerationState.DRIFT


def test_material_tree_and_archive_bounds(  # noqa: PLR0915 - bound cases share fixtures
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    with pytest.raises(FormatError, match="source-tree"):
        fingerprint_material_path(tmp_path / "absent", kind=InputKind.SOURCE_TREE)
    with pytest.raises(FormatError, match="real file"):
        fingerprint_material_path(tmp_path, kind=InputKind.HTML)

    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "folder").mkdir()
    (tree / "ok.py").write_text("pass", encoding="utf-8")
    ignored = tree / ".git"
    ignored.mkdir()
    (ignored / "secret").write_text("ignored", encoding="utf-8")
    assert set(_read_tree(tree)) == {"ok.py"}
    monkeypatch.setattr(materials, "_MAX_TREE_FILES", 0)
    with pytest.raises(FormatError, match="file limit"):
        _read_tree(tree)
    monkeypatch.setattr(materials, "_MAX_TREE_FILES", 10_000)
    monkeypatch.setattr(materials, "_MAX_TREE_BYTES", 1)
    with pytest.raises(FormatError, match="byte limit"):
        _read_tree(tree)
    monkeypatch.setattr(materials, "_MAX_TREE_BYTES", 64 * 1024 * 1024)
    monkeypatch.setattr(materials, "_MAX_FILE_BYTES", 1)
    assert _read_tree(tree) == {}
    large = tmp_path / "large.json"
    large.write_bytes(b"{}")
    with pytest.raises(FormatError, match="byte limit"):
        fingerprint_material_path(large, kind=InputKind.OPENAPI)

    archive_path = tmp_path / "fixture.tar"
    payload = b"owned"
    with tarfile.open(archive_path, "w") as archive:
        directory = tarfile.TarInfo("folder")
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        info = tarfile.TarInfo("folder/file.txt")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    monkeypatch.setattr(materials, "_MAX_TREE_BYTES", 64 * 1024 * 1024)
    monkeypatch.setattr(materials, "_MAX_FILE_BYTES", 8 * 1024 * 1024)
    assert _read_archive(archive_path) == {"folder/file.txt": payload}
    monkeypatch.setattr(materials, "_MAX_FILE_BYTES", 1)
    assert _read_archive(archive_path) == {}
    monkeypatch.setattr(materials, "_MAX_FILE_BYTES", 8 * 1024 * 1024)
    monkeypatch.setattr(materials, "_MAX_TREE_FILES", 0)
    with pytest.raises(FormatError, match="archive limit"):
        _read_archive(archive_path)
    monkeypatch.setattr(materials, "_MAX_TREE_FILES", 10_000)
    zip_path = tmp_path / "fixture.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("folder/", b"")
        archive.writestr("folder/file.txt", payload)
    assert _read_archive(zip_path) == {"folder/file.txt": payload}
    monkeypatch.setattr(materials, "_MAX_FILE_BYTES", 1)
    assert _read_archive(zip_path) == {}
    monkeypatch.setattr(materials, "_MAX_FILE_BYTES", 8 * 1024 * 1024)
    monkeypatch.setattr(materials, "_MAX_TREE_FILES", 0)
    with pytest.raises(FormatError, match="archive limit"):
        _read_archive(zip_path)
    monkeypatch.setattr(materials, "_MAX_TREE_FILES", 10_000)
    malformed = tmp_path / "bad.archive"
    malformed.write_text("not an archive", encoding="utf-8")
    with pytest.raises(FormatError, match="malformed"):
        _read_archive(malformed)
    for name in ("/absolute", "../escape", "bad\\..\\escape", "bad\0name"):
        with pytest.raises(FormatError, match="unsafe"):
            _safe_archive_name(name)


def test_material_symlink_path_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "fixture.json"
    path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(Path, "is_symlink", lambda _path: True)
    with pytest.raises(FormatError, match="symlink"):
        fingerprint_material_path(path, kind=InputKind.OPENAPI)


def test_intake_models_merge_validate_and_preserve_partial_states() -> None:
    provenance = intake_provenance(
        "fixture", "$/x", SourceClass.SUPPLIED, EvidenceClass.DECLARED, {"x": 1}
    )
    with pytest.raises(FormatError, match="required"):
        IntakeProvenance("", "$/x", SourceClass.SUPPLIED, EvidenceClass.DECLARED, _DIGEST)
    with pytest.raises(FormatError, match="SHA-256"):
        replace(provenance, projection_digest="bad")
    with pytest.raises(FormatError, match="confidence"):
        IntakeNode("id", "kind", "name", {}, EvidenceClass.DECLARED, 2.0, (provenance,))
    with pytest.raises(FormatError, match="provenance"):
        IntakeNode("id", "kind", "name", {}, EvidenceClass.DECLARED, 1.0, ())
    with pytest.raises(FormatError, match="confidence"):
        IntakeEdge("id", "a", "b", "kind", (), (), {}, EvidenceClass.DECLARED, -1.0, (provenance,))
    with pytest.raises(FormatError, match="provenance"):
        IntakeEdge("id", "a", "b", "kind", (), (), {}, EvidenceClass.DECLARED, 1.0, ())

    graph = IntakeGraph("edge")
    left = graph.add_node(
        WorkflowNodeKind.ENTRY,
        "left",
        "left",
        attributes=None,
        evidence_class=EvidenceClass.INFERRED,
        confidence=0.4,
        provenance=provenance,
    )
    right = graph.add_node(
        "state",
        "right",
        "right",
        attributes={"a": 1},
        evidence_class=EvidenceClass.DECLARED,
        confidence=0.7,
        provenance=provenance,
    )
    graph.add_node(
        "state",
        "right",
        "ignored",
        attributes={"b": 2},
        evidence_class=EvidenceClass.OBSERVED,
        confidence=0.9,
        provenance=replace(provenance, pointer="$/y"),
    )
    edge = graph.add_edge(
        left,
        right,
        "flows",
        preconditions=("one",),
        effects=("read",),
        attributes=None,
        evidence_class=EvidenceClass.DECLARED,
        confidence=0.5,
        provenance=provenance,
    )
    assert (
        graph.add_edge(
            left,
            right,
            "flows",
            preconditions=("two",),
            effects=("write",),
            attributes={"merged": True},
            evidence_class=EvidenceClass.OBSERVED,
            confidence=0.8,
            provenance=replace(provenance, pointer="$/z"),
        )
        == edge
    )
    with pytest.raises(FormatError, match="endpoints"):
        graph.add_edge(
            "absent",
            right,
            "bad",
            evidence_class=EvidenceClass.DECLARED,
            confidence=1.0,
            provenance=provenance,
        )
    coverage = CoverageContract(
        (
            CoverageItem("x", "input", CoverageState.UNKNOWN, "missing", ()),
            CoverageItem("y", "input", CoverageState.UNSUPPORTED, "unsupported", ()),
        )
    ).to_mapping()
    assert coverage["partial"] is True


def test_report_and_profile_readers_reject_non_objects_and_semantic_tampering(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root.json"
    root.write_text("[]", encoding="utf-8")
    with pytest.raises(FormatError, match="profile root"):
        read_target_profile(root)
    with pytest.raises(FormatError, match="report root"):
        read_intake_report(root)

    profile = target_profile_template(
        identifier="report",
        title="Report",
        target_kinds=(ProfileTargetKind.WEB,),
        authorization_scope="owned fixture only",
    )
    profile = replace(
        profile,
        entrypoints=(
            EntryPoint(
                "web",
                EntryPointKind.URL,
                "https://example.invalid",
                (ProfileTargetKind.WEB,),
            ),
        ),
    )
    artifacts = run_universal_intake(profile, {}, tmp_path / "intake")
    report = json.loads(artifacts.report.read_text(encoding="utf-8"))
    duplicate = copy.deepcopy(report)
    duplicate["workflowGraph"]["nodes"].append(
        copy.deepcopy(duplicate["workflowGraph"]["nodes"][0])
    )
    body = dict(duplicate)
    body.pop("contentDigest")
    duplicate["contentDigest"] = sha256_digest(canonical_json_bytes(body))
    with pytest.raises(FormatError, match="unique"):
        validate_intake_report(duplicate)
    unsafe = copy.deepcopy(report)
    unsafe["claims"]["safeOrClean"] = True
    body = dict(unsafe)
    body.pop("contentDigest")
    unsafe["contentDigest"] = sha256_digest(canonical_json_bytes(body))
    with pytest.raises(FormatError, match="false was expected"):
        validate_intake_report(unsafe)
    with pytest.raises(FormatError, match="already exists"):
        run_universal_intake(profile, {}, artifacts.destination)

    dangling = copy.deepcopy(report)
    dangling["workflowGraph"]["edges"][0]["target"] = "intake:workflow-node:" + "0" * 32
    body = dict(dangling)
    body.pop("contentDigest")
    dangling["contentDigest"] = sha256_digest(canonical_json_bytes(body))
    with pytest.raises(FormatError, match="dangling"):
        validate_intake_report(dangling)

    blocked_destination = tmp_path / "blocked"
    blocked_destination.with_name(".blocked.partial").mkdir()
    with pytest.raises(FormatError, match="staging"):
        run_universal_intake(profile, {}, blocked_destination)

    failing_profile = replace(
        profile,
        inputs=(
            InputDescriptor(
                "known",
                InputKind.HTML,
                SourceClass.SUPPLIED,
                "known.html",
                "text/html",
                _DIGEST,
            ),
        ),
    )
    failed_destination = tmp_path / "failed"
    with pytest.raises(FormatError, match="unknown input"):
        run_universal_intake(
            failing_profile,
            {"unknown": tmp_path / "absent"},
            failed_destination,
        )
    assert not failed_destination.with_name(".failed.partial").exists()


def test_frontend_alternate_source_formats_and_safe_helpers() -> None:
    discovery = IntakeDiscovery(_all_kind_profile())
    discovery.seed_profile()
    files = {
        "empty.txt": b"",
        "binary.bin": b"\0binary",
        "tests/fixture.py": b"pass",
        "package.json": json.dumps(
            {
                "dependencies": {"one": "1"},
                "devDependencies": {"two": "2"},
                "peerDependencies": {"three": "3"},
                "optionalDependencies": {"four": "4"},
                "scripts": {"start": "ignored"},
            }
        ).encode(),
        "pyproject.toml": (
            b"[project]\ndependencies=['requests>=2', 1]\n[project.scripts]\nfixture='pkg:main'\n"
        ),
        "bad/pyproject.toml": b"not = [valid",
        "requirements.txt": b"# comment\nrequests==2\n\n" + b"x" * 201 + b"==1\n",
        "bad/requirements.txt": b"\xff",
        "Containerfile": (
            b"FROM scratch\nEXPOSE 80 443\nUSER root\nENV A=1 B=2\nARG C\n"
            b"ENTRYPOINT []\nCMD []\nHEALTHCHECK NONE\nRUN ignored\n"
        ),
        "bad/Dockerfile": b"\xff",
        ".github/workflows/ci.yml": b"name: ci",
        ".env": b"token=\n",
    }
    discover_material(discovery, _material(InputKind.SOURCE_TREE, files=files))
    assert discovery.surface.nodes
    assert _source_file_category("x.exe", b"MZ") == "binary"
    assert _source_file_category("x.py", b"print(1)") == "source"

    assert _safe_url_projection(1) == {"present": False}
    assert _safe_url_projection("/relative?x=")["relative"] is True
    assert _safe_url_projection("http://127.0.0.1:80/x")["loopback"] is True
    assert _header_names(None) == []
    assert _header_names([{"name": "X"}, 1, {}]) == ["X"]
    assert _query_names(None) == []
    assert _query_names([{"name": "q"}, None]) == ["q"]
    assert _mapping([]) == {}
    assert _list({}) == []
    assert list(_postman_requests(None)) == []
    assert len(list(_postman_requests([1, {"item": [{"request": {"method": "GET"}}]}]))) == 1
    assert _postman_url("https://example.invalid") == "https://example.invalid"
    assert _postman_url({"raw": "https://example.invalid/raw"}).endswith("/raw")
    assert (
        _postman_url({"protocol": "http", "host": ["example", "invalid"], "path": ["x"]})
        == "http://example.invalid/x"
    )
    assert _postman_url(1) == "https://invalid.local/"


def test_frontend_alternate_representation_branches() -> None:
    discovery = IntakeDiscovery(_all_kind_profile())
    discovery.seed_profile()
    values = [
        (
            InputKind.WEB_INVENTORY,
            {"pages": [1, {"url": 1}, {"url": "/relative", "forms": [1], "routes": [1]}]},
        ),
        (
            InputKind.HAR,
            {"log": {"entries": [1, {"request": {"url": "/x", "headers": "bad"}, "response": {}}]}},
        ),
        (
            InputKind.OPENAPI,
            {
                "swagger": "2.0",
                "paths": {
                    "/x": {"parameters": [], "get": {"parameters": "bad", "responses": []}},
                    1: {},
                },
            },
        ),
        (
            InputKind.GRPC_DESCRIPTOR,
            {"services": [1, {"name": "S", "methods": [1, {"name": "M"}]}]},
        ),
        (
            InputKind.POSTMAN,
            {
                "item": [
                    1,
                    {
                        "request": {
                            "method": "GET",
                            "url": {"protocol": "https", "host": "example.invalid", "path": "x"},
                        }
                    },
                ]
            },
        ),
        (
            InputKind.SBOM,
            {
                "components": [1, {"name": "x"}],
                "vulnerabilities": [1, {"id": "CVE-X", "ratings": "bad", "affects": "bad"}],
            },
        ),
        (InputKind.OCI_MANIFEST, {"config": "bad", "layers": [1, {"digest": _DIGEST}]}),
        (InputKind.OCI_CONFIG, {"config": {"Env": "bad", "ExposedPorts": [], "User": ""}}),
        (InputKind.OCI_INVENTORY, {"capabilities": "bad", "mounts": [1], "ports": "bad"}),
        (
            InputKind.NETWORK_INVENTORY,
            {"hosts": [1, {"services": [1]}], "dnsRelationships": [1], "segments": [1]},
        ),
        (
            InputKind.TLS_REPORT,
            {"protocols": "bad", "ciphers": [1], "certificates": "bad", "issues": [1]},
        ),
        (
            InputKind.PROCESS_INVENTORY,
            {
                "processes": [
                    1,
                    {"windows": [1], "sideEffects": "bad", "crossProcessTargets": "bad"},
                ]
            },
        ),
        (InputKind.ACCESSIBILITY_TREE, {"nodes": [1, {"role": "button", "actions": "bad"}]}),
        (
            InputKind.AGENT_MANIFEST,
            {"name": "edge", "tools": [1], "skills": [1], "handoffs": [1], "protocols": [1]},
        ),
        (InputKind.MCP_MANIFEST, {"mcpServers": [1], "tools": [1]}),
        (InputKind.A2A_CARD, {"name": "edge", "skills": [1], "authentication": []}),
        (
            InputKind.RUNTIME_OBSERVATIONS,
            {
                "workflow": {"nodes": [1], "edges": [1]},
                "attackSurface": {"nodes": [1], "edges": [1]},
            },
        ),
    ]
    for kind, value in values:
        discover_material(discovery, _material(kind, value=value, source_class=SourceClass.PASSIVE))
    discover_material(
        discovery, _material(InputKind.GRAPHQL_SCHEMA, text="type Query { x: String }")
    )
    discover_material(discovery, _material(InputKind.LOCKFILE, text="# comment\nrequests==2\n"))
    assert discovery.processed_inputs


def test_frontend_valid_runtime_graph_and_non_object_roots() -> None:
    discovery = IntakeDiscovery(_all_kind_profile())
    discovery.seed_profile()
    runtime = {
        "workflow": {
            "nodes": [
                {
                    "key": "start",
                    "kind": "not-a-kind",
                    "confidence": 0.8,
                    "attributes": {
                        "token": "redacted",
                        "label": "owned",
                        "count": 2,
                        "flags": [1, 2],
                        "nested": {"enabled": True},
                    },
                },
                {"key": "end", "kind": "data-state"},
            ],
            "edges": [
                {
                    "source": "start",
                    "target": "end",
                    "kind": "bad kind",
                    "evidenceClass": "refuted",
                    "confidence": 0.7,
                    "attributes": {"reason": "control"},
                }
            ],
        },
        "attackSurface": {"nodes": [], "edges": []},
    }
    discover_material(
        discovery,
        _material(InputKind.RUNTIME_OBSERVATIONS, value=runtime, source_class=SourceClass.ACTIVE),
    )
    assert any(
        node.evidence_class == EvidenceClass.REFUTED for node in discovery.workflow.edges.values()
    )

    invalid_root_kinds = (
        InputKind.WEB_INVENTORY,
        InputKind.OPENAPI,
        InputKind.POSTMAN,
        InputKind.SBOM,
        InputKind.OCI_MANIFEST,
        InputKind.OCI_CONFIG,
        InputKind.OCI_INVENTORY,
        InputKind.NETWORK_INVENTORY,
        InputKind.TLS_REPORT,
        InputKind.PROCESS_INVENTORY,
        InputKind.ACCESSIBILITY_TREE,
        InputKind.AGENT_MANIFEST,
        InputKind.MCP_MANIFEST,
        InputKind.A2A_CARD,
        InputKind.RUNTIME_OBSERVATIONS,
    )
    for kind in invalid_root_kinds:
        with pytest.raises(FormatError):
            discover_material(discovery, _material(kind, value=[]))
    discover_material(discovery, _material(InputKind.HAR, value=[]))
    discover_material(discovery, _material(InputKind.GRPC_DESCRIPTOR, value=[]))
