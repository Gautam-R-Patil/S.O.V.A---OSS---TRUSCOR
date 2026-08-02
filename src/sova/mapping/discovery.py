# SPDX-License-Identifier: Apache-2.0
"""Air-gapped, secret-value-blind capability declaration discovery."""

from __future__ import annotations

import ast
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from sova.formats import canonical_json_bytes, strict_json_loads
from sova.formats.errors import FormatError
from sova.mapping.model import (
    CapabilityGraph,
    EdgeKind,
    EvidenceClass,
    NodeKind,
    projected_provenance,
)

_IGNORED_DIRECTORIES = {
    ".cache",
    ".claude",
    ".codex",
    ".git",
    ".hypothesis",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".sova",
    ".uv-cache",
    ".venv",
    "__pycache__",
    "browser-profiles",
    "client-data",
    "confidential",
    "dist",
    "node_modules",
    "private",
    "temp",
    "tmp",
    "traces",
}
_ENV_REFERENCE = re.compile(
    r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)|%([A-Za-z_][A-Za-z0-9_]*)%"
)
_SENSITIVE_NAME = re.compile(
    r"(?:^|[_-])(api[_-]?key|access[_-]?key|authorization|cookie|credential|key|password|secret|session|token)(?:$|[_-])",
    re.IGNORECASE,
)
_SECRET_VALUE = re.compile(
    r"^(?:Bearer\s+|Basic\s+|sk-[A-Za-z0-9]|gh[pousr]_|xox[baprs]-|eyJ[A-Za-z0-9_-]+\.)",
    re.IGNORECASE,
)
_MAX_FILE_BYTES = 1_048_576
_MAX_FILES = 10_000


@dataclass(frozen=True, slots=True)
class DiscoveryInput:
    """One inspected input without embedding secret values."""

    path: str
    kind: str
    status: str

    def to_mapping(self) -> dict[str, str]:
        return {"path": self.path, "kind": self.kind, "status": self.status}


@dataclass(slots=True)
class DiscoveryResult:
    """Graph plus explicit partial-discovery limitations."""

    graph: CapabilityGraph = field(default_factory=CapabilityGraph)
    inputs: list[DiscoveryInput] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


def _safe_relative(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as error:
        raise FormatError(
            "SOVA-MAP-PATH-ESCAPE",
            "discovery input resolves outside the authorized root",
        ) from error


def _projection(value: object, *, parent: str = "") -> object:  # noqa: PLR0911
    """Remove values likely to be credentials before hashing provenance."""
    if isinstance(value, dict):
        return {
            str(key): (
                {"redacted": True, "present": child is not None}
                if _SENSITIVE_NAME.search(str(key))
                else _projection(child, parent=str(key))
            )
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_projection(item, parent=parent) for item in value]
    if isinstance(value, str):
        if parent.casefold() in {
            "arg",
            "args",
            "argument",
            "arguments",
            "argv",
            "header",
            "headers",
        }:
            return "<value-redacted>"
        if _SECRET_VALUE.search(value.strip()):
            return "<secret-pattern-redacted>"
        if _ENV_REFERENCE.search(value):
            return "<environment-reference>"
        parsed = urlsplit(value)
        if parsed.scheme in {"http", "https", "ws", "wss"} and parsed.hostname:
            return {
                "endpoint": True,
                "scheme": parsed.scheme,
                "external": parsed.hostname not in {"localhost", "127.0.0.1", "::1"},
                "locatorRedacted": True,
            }
        return value
    return value


def _environment_names(value: object, *, parent: str = "") -> set[str]:
    names: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            if parent.casefold() == "env" or _SENSITIVE_NAME.search(key_text):
                names.add(key_text)
            names.update(_environment_names(child, parent=key_text))
    elif isinstance(value, list):
        for item in value:
            names.update(_environment_names(item, parent=parent))
    elif isinstance(value, str):
        for match in _ENV_REFERENCE.finditer(value):
            name = next(group for group in match.groups() if group is not None)
            names.add(name)
    return names


def _endpoint_projection(value: object) -> dict[str, Any]:
    if not isinstance(value, str):
        return {"present": False}
    parsed = urlsplit(value)
    if parsed.scheme in {"http", "https", "ws", "wss"} and parsed.hostname:
        return {
            "present": True,
            "scheme": parsed.scheme,
            "hostDigestInput": parsed.hostname.casefold(),
            "external": parsed.hostname not in {"localhost", "127.0.0.1", "::1"},
        }
    return {"present": True, "scheme": "opaque", "external": False}


def _add_environment_references(
    result: DiscoveryResult,
    source_node: str,
    source: str,
    pointer: str,
    value: object,
) -> None:
    for name in sorted(_environment_names(value)):
        sensitive = bool(_SENSITIVE_NAME.search(name))
        projection = {"name": name, "sensitive": sensitive}
        provenance = projected_provenance(
            source,
            f"{pointer}/environment/{name}",
            EvidenceClass.DECLARED,
            projection,
        )
        node = result.graph.add_node(
            NodeKind.DATA_SOURCE,
            f"environment:{name.casefold()}",
            name,
            attributes={
                "sourceType": "environment-reference",
                "sensitivity": "credential" if sensitive else "configuration",
                "valueRead": False,
            },
            provenance=provenance,
        )
        result.graph.add_edge(
            source_node,
            node,
            EdgeKind.READS,
            evidence_class=EvidenceClass.DECLARED,
            provenance=provenance,
        )


def _discover_mcp_document(
    result: DiscoveryResult,
    relative: str,
    document: dict[str, Any],
    workspace_node: str,
    *,
    evidence_class: EvidenceClass = EvidenceClass.DECLARED,
) -> bool:
    servers = document.get("mcpServers", document.get("mcp_servers"))
    if not isinstance(servers, dict):
        return False
    for name, raw in sorted(servers.items(), key=lambda item: str(item[0])):
        if not isinstance(raw, dict):
            result.limitations.append(f"Ignored malformed MCP declaration at {relative}:{name}")
            continue
        pointer = f"$/mcpServers/{name}"
        command = raw.get("command")
        endpoint = _endpoint_projection(raw.get("url", raw.get("endpoint")))
        tools = raw.get("tools")
        safe = {
            "name": str(name),
            "commandName": Path(command).name if isinstance(command, str) else None,
            "argumentCount": len(raw.get("args", [])) if isinstance(raw.get("args"), list) else 0,
            "endpoint": {
                "present": endpoint["present"],
                "scheme": endpoint.get("scheme"),
                "external": endpoint.get("external", False),
                "locatorRedacted": True,
            },
            "environmentNames": sorted(_environment_names(raw)),
            "tools": _projection(tools) if isinstance(tools, list) else [],
        }
        provenance = projected_provenance(relative, pointer, evidence_class, safe)
        edge_attributes = (
            {"witnessRefs": [provenance.projection_digest], "conditions": []}
            if evidence_class == EvidenceClass.OBSERVED
            else {"conditions": []}
        )
        server = result.graph.add_node(
            NodeKind.MCP_SERVER,
            f"mcp:{name}",
            str(name),
            attributes={
                "transport": "stdio" if isinstance(command, str) else endpoint["scheme"],
                "commandName": Path(command).name if isinstance(command, str) else None,
                "argumentCount": len(raw.get("args", []))
                if isinstance(raw.get("args"), list)
                else 0,
                "endpointExternal": endpoint.get("external", False),
            },
            provenance=provenance,
        )
        result.graph.add_edge(
            workspace_node,
            server,
            EdgeKind.USES,
            evidence_class=evidence_class,
            attributes=edge_attributes,
            provenance=provenance,
        )
        _add_environment_references(result, server, relative, pointer, raw)
        if isinstance(tools, list):
            for index, tool in enumerate(tools):
                if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
                    continue
                tool_name = tool["name"]
                tool_projection = _projection(tool)
                tool_provenance = projected_provenance(
                    relative,
                    f"{pointer}/tools/{index}",
                    evidence_class,
                    tool_projection,
                )
                tool_node = result.graph.add_node(
                    NodeKind.TOOL,
                    f"mcp:{name}:tool:{tool_name}",
                    tool_name,
                    attributes={
                        "server": str(name),
                        "description": str(tool.get("description", ""))[:512],
                        "inputSchema": (
                            tool_projection.get("inputSchema", {})
                            if isinstance(tool_projection, dict)
                            else {}
                        ),
                    },
                    provenance=tool_provenance,
                )
                result.graph.add_edge(
                    server,
                    tool_node,
                    EdgeKind.DECLARES,
                    evidence_class=evidence_class,
                    attributes=edge_attributes,
                    provenance=tool_provenance,
                )
        if endpoint.get("external", False):
            destination = result.graph.add_node(
                NodeKind.EXTERNAL_SYSTEM,
                f"mcp-endpoint:{endpoint['hostDigestInput']}",
                "external MCP endpoint",
                attributes={"external": True, "locatorRedacted": True},
                provenance=provenance,
            )
            result.graph.add_edge(
                server,
                destination,
                EdgeKind.EGRESS,
                evidence_class=evidence_class,
                attributes=edge_attributes,
                provenance=provenance,
            )
    return True


def _discover_plugin(
    result: DiscoveryResult,
    relative: str,
    document: dict[str, Any],
    workspace_node: str,
) -> bool:
    if not relative.endswith(".codex-plugin/plugin.json"):
        return False
    name = document.get("name")
    if not isinstance(name, str) or not name:
        return False
    safe = _projection(document)
    provenance = projected_provenance(relative, "$", EvidenceClass.DECLARED, safe)
    plugin = result.graph.add_node(
        NodeKind.PLUGIN,
        f"plugin:{name}",
        name,
        attributes={"version": document.get("version"), "manifest": relative},
        provenance=provenance,
    )
    result.graph.add_edge(
        workspace_node,
        plugin,
        EdgeKind.USES,
        evidence_class=EvidenceClass.DECLARED,
        provenance=provenance,
    )
    _add_environment_references(result, plugin, relative, "$", document)
    return True


def _discover_package_json(
    result: DiscoveryResult,
    relative: str,
    document: dict[str, Any],
    workspace_node: str,
) -> bool:
    if Path(relative).name != "package.json":
        return False
    package_name = str(document.get("name", Path(relative).parent.name or "package"))
    projection = {
        "name": package_name,
        "version": document.get("version"),
        "scripts": sorted(document.get("scripts", {}))
        if isinstance(document.get("scripts"), dict)
        else [],
        "dependencies": sorted(document.get("dependencies", {}))
        if isinstance(document.get("dependencies"), dict)
        else [],
    }
    provenance = projected_provenance(relative, "$", EvidenceClass.DECLARED, projection)
    package = result.graph.add_node(
        NodeKind.PACKAGE,
        f"package:{relative}:{package_name}",
        package_name,
        attributes=projection,
        provenance=provenance,
    )
    result.graph.add_edge(
        workspace_node,
        package,
        EdgeKind.DEPENDS_ON,
        evidence_class=EvidenceClass.DECLARED,
        provenance=provenance,
    )
    _add_environment_references(result, package, relative, "$", document)
    return True


def _discover_pyproject(
    result: DiscoveryResult,
    relative: str,
    document: dict[str, Any],
    workspace_node: str,
) -> bool:
    if Path(relative).name != "pyproject.toml":
        return False
    project = document.get("project", {})
    if not isinstance(project, dict):
        return False
    name = str(project.get("name", Path(relative).parent.name or "python-project"))
    scripts = project.get("scripts", {})
    dependencies = project.get("dependencies", [])
    projection = {
        "name": name,
        "version": project.get("version"),
        "scripts": sorted(scripts) if isinstance(scripts, dict) else [],
        "dependencyCount": len(dependencies) if isinstance(dependencies, list) else 0,
    }
    provenance = projected_provenance(relative, "$/project", EvidenceClass.DECLARED, projection)
    package = result.graph.add_node(
        NodeKind.PACKAGE,
        f"python-package:{relative}:{name}",
        name,
        attributes=projection,
        provenance=provenance,
    )
    result.graph.add_edge(
        workspace_node,
        package,
        EdgeKind.DEPENDS_ON,
        evidence_class=EvidenceClass.DECLARED,
        provenance=provenance,
    )
    if isinstance(scripts, dict):
        for script_name, entrypoint in sorted(scripts.items()):
            tool_projection = {"name": script_name, "entrypoint": str(entrypoint)}
            tool_provenance = projected_provenance(
                relative,
                f"$/project/scripts/{script_name}",
                EvidenceClass.DECLARED,
                tool_projection,
            )
            tool = result.graph.add_node(
                NodeKind.TOOL,
                f"python-script:{relative}:{script_name}",
                script_name,
                attributes={"entrypoint": str(entrypoint)},
                provenance=tool_provenance,
            )
            result.graph.add_edge(
                package,
                tool,
                EdgeKind.DECLARES,
                evidence_class=EvidenceClass.DECLARED,
                provenance=tool_provenance,
            )
    return True


def _discover_skill(
    result: DiscoveryResult,
    root: Path,
    path: Path,
    workspace_node: str,
) -> bool:
    if path.name != "SKILL.md":
        return False
    relative = _safe_relative(root, path)
    text = path.read_text(encoding="utf-8", errors="replace")[:16_384]
    name_match = re.search(r"(?m)^name:\s*[\"']?([^\r\n\"']+)", text)
    name = name_match.group(1).strip() if name_match else path.parent.name
    projection = {"name": name, "path": relative}
    provenance = projected_provenance(relative, "$frontmatter", EvidenceClass.DECLARED, projection)
    skill = result.graph.add_node(
        NodeKind.SKILL,
        f"skill:{relative}:{name}",
        name,
        attributes={"manifest": relative},
        provenance=provenance,
    )
    result.graph.add_edge(
        workspace_node,
        skill,
        EdgeKind.USES,
        evidence_class=EvidenceClass.DECLARED,
        provenance=provenance,
    )
    result.inputs.append(DiscoveryInput(relative, "skill", "parsed"))
    return True


def _discover_agent_manifest(
    result: DiscoveryResult,
    root: Path,
    path: Path,
    workspace_node: str,
) -> bool:
    if path.name not in {"AGENTS.md", "AGENT.md"}:
        return False
    relative = _safe_relative(root, path)
    if path.parent.resolve() == root.resolve():
        result.inputs.append(DiscoveryInput(relative, "agent-manifest", "parsed"))
        return True
    projection = {"path": relative, "name": path.parent.name}
    provenance = projected_provenance(
        relative,
        "$instructions",
        EvidenceClass.DECLARED,
        projection,
    )
    agent = result.graph.add_node(
        NodeKind.SUB_AGENT,
        f"sub-agent:{relative}",
        path.parent.name,
        attributes={"manifest": relative, "contentRead": False},
        provenance=provenance,
    )
    result.graph.add_edge(
        workspace_node,
        agent,
        EdgeKind.DELEGATES,
        evidence_class=EvidenceClass.DECLARED,
        attributes={"conditions": []},
        provenance=provenance,
    )
    result.inputs.append(DiscoveryInput(relative, "sub-agent-manifest", "parsed"))
    return True


def _decorator_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _decorator_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        return _decorator_name(node.func)
    return ""


def _discover_python_tools(
    result: DiscoveryResult,
    root: Path,
    path: Path,
    workspace_node: str,
) -> bool:
    if path.suffix != ".py":
        return False
    relative = _safe_relative(root, path)
    if path.stat().st_size > _MAX_FILE_BYTES:
        result.limitations.append(f"Skipped oversized Python source: {relative}")
        return True
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="strict"), filename=relative)
    except (SyntaxError, UnicodeError) as error:
        result.limitations.append(
            f"Could not parse Python source {relative}: {type(error).__name__}"
        )
        return True
    found = False
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        decorators = {_decorator_name(item).casefold() for item in node.decorator_list}
        if not any(name == "tool" or name.endswith(".tool") for name in decorators):
            continue
        found = True
        projection = {"name": node.name, "decorators": sorted(decorators)}
        provenance = projected_provenance(
            relative,
            f"$ast/function/{node.name}:{node.lineno}",
            EvidenceClass.INFERRED,
            projection,
        )
        tool = result.graph.add_node(
            NodeKind.TOOL,
            f"python-tool:{relative}:{node.name}",
            node.name,
            attributes={"language": "python", "declarationInferred": True},
            provenance=provenance,
        )
        result.graph.add_edge(
            workspace_node,
            tool,
            EdgeKind.DECLARES,
            evidence_class=EvidenceClass.INFERRED,
            provenance=provenance,
        )
    if found:
        result.inputs.append(DiscoveryInput(relative, "python-source", "parsed"))
    return found


def _read_structured(path: Path) -> dict[str, Any] | None:
    if path.stat().st_size > _MAX_FILE_BYTES:
        return None
    raw = path.read_bytes()
    value: object
    if path.suffix.casefold() == ".json" or path.name in {".mcp.json", "mcp.json"}:
        value = strict_json_loads(raw)
    elif path.suffix.casefold() == ".toml":
        try:
            value = tomllib.loads(raw.decode("utf-8", errors="strict"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as error:
            raise FormatError("SOVA-MAP-TOML", f"invalid TOML: {path.name}") from error
    else:
        return None
    return value if isinstance(value, dict) else None


def _walk(root: Path) -> list[Path]:
    files: list[Path] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            children = sorted(directory.iterdir(), key=lambda item: item.name.casefold())
        except OSError:
            continue
        for child in children:
            if child.is_symlink():
                continue
            if child.is_dir():
                if child.name.casefold() not in _IGNORED_DIRECTORIES:
                    pending.append(child)
                continue
            files.append(child)
            if len(files) >= _MAX_FILES:
                return files
    return sorted(files, key=lambda item: item.as_posix().casefold())


def discover_workspace(root: Path) -> DiscoveryResult:
    """Discover static declarations without executing code or reading `.env`."""
    resolved = root.resolve()
    if not resolved.is_dir():
        raise FormatError("SOVA-MAP-ROOT", "mapping root must be an existing directory")
    result = DiscoveryResult()
    root_projection = {"kind": "workspace", "name": resolved.name}
    root_provenance = projected_provenance(
        ".",
        "$",
        EvidenceClass.DECLARED,
        root_projection,
    )
    workspace_node = result.graph.add_node(
        NodeKind.AGENT,
        "workspace-root",
        resolved.name,
        attributes={"root": ".", "authorizedStaticInspection": True},
        provenance=root_provenance,
    )
    files = _walk(resolved)
    if len(files) >= _MAX_FILES:
        result.limitations.append(f"Discovery stopped at the {_MAX_FILES}-file safety limit")
    for path in files:
        relative = _safe_relative(resolved, path)
        if path.name.casefold().startswith(".env"):
            result.inputs.append(DiscoveryInput(relative, "environment-file", "name-only"))
            continue
        if _discover_agent_manifest(result, resolved, path, workspace_node):
            continue
        if _discover_skill(result, resolved, path, workspace_node):
            continue
        if _discover_python_tools(result, resolved, path, workspace_node):
            continue
        if path.name not in {
            ".mcp.json",
            "mcp.json",
            "package.json",
            "plugin.json",
            "pyproject.toml",
            "config.toml",
        } and path.suffix.casefold() not in {".json", ".toml"}:
            continue
        try:
            document = _read_structured(path)
        except (FormatError, OSError) as error:
            result.limitations.append(f"Could not parse {relative}: {type(error).__name__}")
            continue
        if document is None:
            continue
        matched = (
            _discover_mcp_document(result, relative, document, workspace_node)
            or _discover_plugin(result, relative, document, workspace_node)
            or _discover_package_json(result, relative, document, workspace_node)
            or _discover_pyproject(result, relative, document, workspace_node)
        )
        if matched:
            result.inputs.append(DiscoveryInput(relative, "declaration", "parsed"))
    if not result.inputs:
        result.limitations.append("No recognized capability declarations were found")
    return result


def import_inventory(  # noqa: PLR0912, PLR0915
    result: DiscoveryResult,
    path: Path,
    *,
    observed: bool = False,
    authorized: bool = False,
) -> None:
    """Merge a declared or explicitly authorized observed inventory."""
    if observed and not authorized:
        raise FormatError(
            "SOVA-MAP-RUNTIME-AUTHORIZATION",
            "observed runtime inventory requires explicit authorization",
        )
    document = strict_json_loads(path.read_bytes())
    if not isinstance(document, dict):
        raise FormatError("SOVA-MAP-INVENTORY", "inventory root must be an object")
    evidence_class = EvidenceClass.OBSERVED if observed else EvidenceClass.DECLARED
    source = path.name
    workspace = next(
        (node.id for node in result.graph.nodes.values() if node.kind == NodeKind.AGENT),
        None,
    )
    if workspace is None:
        raise FormatError("SOVA-MAP-INVENTORY", "inventory merge requires a workspace node")
    if _discover_mcp_document(
        result,
        source,
        document,
        workspace,
        evidence_class=evidence_class,
    ):
        result.inputs.append(
            DiscoveryInput(source, "observed-inventory" if observed else "inventory", "parsed")
        )
        return
    nodes = document.get("nodes")
    edges = document.get("edges")
    if isinstance(nodes, list) and isinstance(edges, list):
        aliases: dict[str, str] = {"workspace": workspace}
        for index, raw_node in enumerate(nodes):
            if not isinstance(raw_node, dict):
                raise FormatError("SOVA-MAP-INVENTORY", "inventory node must be an object")
            key = raw_node.get("key")
            name = raw_node.get("name")
            kind_value = raw_node.get("kind")
            if not isinstance(key, str) or not key:
                raise FormatError(
                    "SOVA-MAP-INVENTORY",
                    "inventory node requires a non-empty key",
                )
            if not isinstance(name, str) or not name:
                raise FormatError(
                    "SOVA-MAP-INVENTORY",
                    "inventory node requires a non-empty name",
                )
            if not isinstance(kind_value, str) or not kind_value:
                raise FormatError(
                    "SOVA-MAP-INVENTORY",
                    "inventory node requires a non-empty kind",
                )
            try:
                node_kind = NodeKind(kind_value)
            except ValueError as error:
                raise FormatError(
                    "SOVA-MAP-INVENTORY",
                    "unsupported inventory node kind",
                ) from error
            attributes = raw_node.get("attributes", {})
            if not isinstance(attributes, dict):
                raise FormatError("SOVA-MAP-INVENTORY", "node attributes must be an object")
            safe_attributes = _projection(attributes)
            if not isinstance(safe_attributes, dict):  # pragma: no cover - input is a dict
                safe_attributes = {}
            provenance = projected_provenance(
                source,
                f"$/nodes/{index}",
                evidence_class,
                {
                    "key": key,
                    "name": name,
                    "kind": node_kind.value,
                    "attributes": safe_attributes,
                },
            )
            aliases[key] = result.graph.add_node(
                node_kind,
                f"inventory:{key}",
                name,
                attributes=safe_attributes,
                provenance=provenance,
            )
        for index, raw_edge in enumerate(edges):
            if not isinstance(raw_edge, dict):
                raise FormatError("SOVA-MAP-INVENTORY", "inventory edge must be an object")
            source_alias = raw_edge.get("source")
            target_alias = raw_edge.get("target")
            kind_value = raw_edge.get("kind")
            if not isinstance(source_alias, str) or not source_alias:
                raise FormatError(
                    "SOVA-MAP-INVENTORY",
                    "inventory edge requires a non-empty source",
                )
            if not isinstance(target_alias, str) or not target_alias:
                raise FormatError(
                    "SOVA-MAP-INVENTORY",
                    "inventory edge requires a non-empty target",
                )
            if not isinstance(kind_value, str) or not kind_value:
                raise FormatError(
                    "SOVA-MAP-INVENTORY",
                    "inventory edge requires a non-empty kind",
                )
            if source_alias not in aliases or target_alias not in aliases:
                raise FormatError("SOVA-MAP-INVENTORY", "inventory edge has an unknown endpoint")
            try:
                edge_kind = EdgeKind(kind_value)
            except ValueError as error:
                raise FormatError(
                    "SOVA-MAP-INVENTORY",
                    "unsupported inventory edge kind",
                ) from error
            requested_class = raw_edge.get("evidenceClass")
            edge_class = evidence_class
            if observed and requested_class == EvidenceClass.REFUTED.value:
                edge_class = EvidenceClass.REFUTED
            elif requested_class == EvidenceClass.INFERRED.value and not observed:
                edge_class = EvidenceClass.INFERRED
            attributes = raw_edge.get("attributes", {})
            if not isinstance(attributes, dict):
                raise FormatError("SOVA-MAP-INVENTORY", "edge attributes must be an object")
            safe_attributes = _projection(attributes)
            if not isinstance(safe_attributes, dict):  # pragma: no cover - input is a dict
                safe_attributes = {}
            provenance = projected_provenance(
                source,
                f"$/edges/{index}",
                edge_class,
                {
                    "source": source_alias,
                    "target": target_alias,
                    "kind": edge_kind.value,
                    "attributes": safe_attributes,
                },
            )
            if edge_class in {EvidenceClass.OBSERVED, EvidenceClass.REFUTED}:
                safe_attributes.setdefault("witnessRefs", [provenance.projection_digest])
            safe_attributes.setdefault("conditions", [])
            result.graph.add_edge(
                aliases[source_alias],
                aliases[target_alias],
                edge_kind,
                evidence_class=edge_class,
                attributes=safe_attributes,
                provenance=provenance,
            )
        result.inputs.append(
            DiscoveryInput(source, "observed-inventory" if observed else "inventory", "parsed")
        )
        return
    raise FormatError(
        "SOVA-MAP-INVENTORY",
        "inventory must contain a supported mcpServers declaration",
    )


def discovery_projection(result: DiscoveryResult) -> bytes:
    """Return deterministic secret-free bytes for cross-machine parity tests."""
    return canonical_json_bytes(
        {
            "graph": result.graph.to_mapping(),
            "inputs": [item.to_mapping() for item in result.inputs],
            "limitations": sorted(result.limitations),
        }
    )


__all__ = [
    "DiscoveryInput",
    "DiscoveryResult",
    "discover_workspace",
    "discovery_projection",
    "import_inventory",
]
