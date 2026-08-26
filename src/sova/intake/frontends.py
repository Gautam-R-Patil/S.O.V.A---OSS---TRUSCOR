# SPDX-License-Identifier: Apache-2.0
"""Non-executing universal intake front ends for supported target representations."""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, urljoin, urlsplit

from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError
from sova.intake.contracts import (
    EntryPointKind,
    InputKind,
    ProfileTargetKind,
    SourceClass,
    TargetProfile,
)
from sova.intake.model import (
    CoverageContract,
    CoverageItem,
    CoverageState,
    IntakeGraph,
    SurfaceNodeKind,
    WorkflowNodeKind,
    intake_provenance,
)
from sova.mapping import EvidenceClass

_HTTP_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
_URL_PATTERN = re.compile(r"(?P<url>(?:https?|wss?)://[^\s\"'<>]+)", re.IGNORECASE)
_ROUTE_PATTERN = re.compile(
    r"(?:fetch|open|WebSocket|EventSource|serviceWorker\.register)\s*\(\s*[\"']([^\"']+)",
    re.IGNORECASE,
)
_GRAPHQL_TYPE = re.compile(r"\btype\s+(Query|Mutation|Subscription)\s*\{([^}]*)}", re.DOTALL)
_GRAPHQL_FIELD = re.compile(r"^\s*([_A-Za-z][_0-9A-Za-z]*)\s*(?:\([^)]*\))?\s*:", re.MULTILINE)
_PROTO_SERVICE = re.compile(r"\bservice\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{([^}]*)}", re.DOTALL)
_PROTO_RPC = re.compile(
    r"\brpc\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*returns\s*\(([^)]*)\)",
    re.IGNORECASE,
)
_SECRET_NAME = re.compile(
    r"(?:api[_-]?key|authorization|cookie|credential|password|secret|session|token)",
    re.IGNORECASE,
)
_POTENTIAL_SECRET = re.compile(
    rb"(?i)(?:-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    rb"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}|\bsk-[A-Za-z0-9_-]{12,}|"
    rb"\bAKIA[A-Z0-9]{16}\b|(?:api[_-]?key|password|secret|token)\s*[:=])"
)
_SAFE_RUNTIME_KIND = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
_MAX_ITEMS = 10_000
_MAX_DEPENDENCY_NAME = 200
_OPENAPI_REF_PARTS = 2

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sova.intake.materials import LoadedMaterial
    from sova.intake.model import IntakeProvenance


@dataclass(slots=True)
class IntakeDiscovery:
    """Shared graph and coverage state populated by all front ends."""

    profile: TargetProfile
    workflow: IntakeGraph = field(default_factory=lambda: IntakeGraph("workflow"))
    surface: IntakeGraph = field(default_factory=lambda: IntakeGraph("surface"))
    limitations: list[str] = field(default_factory=list)
    processed_inputs: list[dict[str, Any]] = field(default_factory=list)
    _coverage: dict[tuple[str, str], CoverageItem] = field(default_factory=dict)
    _entry_nodes: dict[str, str] = field(default_factory=dict)
    _surface_roots: dict[ProfileTargetKind, str] = field(default_factory=dict)
    _actor_node: str | None = None

    def seed_profile(self) -> None:
        """Add declared target kinds, entrypoints, environments, and secret references."""
        profile_source = "target-profile"
        actor_provenance = intake_provenance(
            profile_source,
            "$/authorizationScope",
            SourceClass.SUPPLIED,
            EvidenceClass.DECLARED,
            {"authorizationScopeDigest": sha256_digest(self.profile.authorization_scope.encode())},
        )
        actor_node = self.workflow.add_node(
            WorkflowNodeKind.ACTOR,
            "authorized-operator",
            "authorized operator",
            attributes={
                "authorizationScopeDigest": sha256_digest(
                    self.profile.authorization_scope.encode()
                ),
                "controlEvidenceRequired": True,
            },
            evidence_class=EvidenceClass.DECLARED,
            confidence=1.0,
            provenance=actor_provenance,
        )
        self._actor_node = actor_node
        for kind in self.profile.target_kinds:
            provenance = intake_provenance(
                profile_source,
                f"$/targetKinds/{kind.value}",
                SourceClass.SUPPLIED,
                EvidenceClass.DECLARED,
                {"kind": kind.value},
            )
            node = self.surface.add_node(
                SurfaceNodeKind.TRUST_BOUNDARY,
                f"target-kind:{kind.value}",
                kind.value,
                attributes={"targetKind": kind.value, "profileRoot": True},
                evidence_class=EvidenceClass.DECLARED,
                confidence=1.0,
                provenance=provenance,
            )
            self._surface_roots[kind] = node
            self.cover(kind.value, "target-kind", CoverageState.UNKNOWN, "not-yet-discovered")
        for index, entrypoint in enumerate(self.profile.entrypoints):
            provenance = intake_provenance(
                profile_source,
                f"$/entrypoints/{index}",
                SourceClass.SUPPLIED,
                EvidenceClass.DECLARED,
                entrypoint.to_mapping(),
            )
            workflow_node = self.workflow.add_node(
                WorkflowNodeKind.ENTRY,
                entrypoint.id,
                entrypoint.id,
                attributes=_entrypoint_attributes(entrypoint.kind, entrypoint.locator),
                evidence_class=EvidenceClass.DECLARED,
                confidence=1.0,
                provenance=provenance,
            )
            self._entry_nodes[entrypoint.id] = workflow_node
            self.workflow.add_edge(
                actor_node,
                workflow_node,
                "may-enter",
                preconditions=("fresh-authorization-and-control-evidence",),
                evidence_class=EvidenceClass.DECLARED,
                confidence=1.0,
                provenance=provenance,
            )
            surface_kind = (
                SurfaceNodeKind.ENDPOINT
                if entrypoint.kind
                in {
                    EntryPointKind.URL,
                    EntryPointKind.API,
                    EntryPointKind.HOST,
                    EntryPointKind.CIDR,
                    EntryPointKind.MCP,
                    EntryPointKind.A2A,
                }
                else SurfaceNodeKind.PROCESS
                if entrypoint.kind == EntryPointKind.PROCESS
                else SurfaceNodeKind.CONFIGURATION
            )
            surface_node = self.surface.add_node(
                surface_kind,
                f"entrypoint:{entrypoint.id}",
                entrypoint.id,
                attributes=_entrypoint_attributes(entrypoint.kind, entrypoint.locator),
                evidence_class=EvidenceClass.DECLARED,
                confidence=1.0,
                provenance=provenance,
            )
            for kind in entrypoint.target_kinds:
                self.surface.add_edge(
                    self._surface_roots[kind],
                    surface_node,
                    "declares-entrypoint",
                    evidence_class=EvidenceClass.DECLARED,
                    confidence=1.0,
                    provenance=provenance,
                )
            self.cover(entrypoint.id, "entrypoint", CoverageState.DECLARED, "profile-declaration")
        for index, reference in enumerate(self.profile.credential_references):
            provenance = intake_provenance(
                profile_source,
                f"$/credentialReferences/{index}",
                SourceClass.SUPPLIED,
                EvidenceClass.DECLARED,
                {"reference": reference.reference, "scopes": sorted(reference.scopes)},
            )
            node = self.surface.add_node(
                SurfaceNodeKind.SECRET_REFERENCE,
                reference.reference,
                "opaque credential reference",
                attributes={
                    "referenceDigest": sha256_digest(reference.reference.encode()),
                    "purpose": reference.purpose,
                    "scopes": sorted(reference.scopes),
                    "required": reference.required,
                    "secretValuePresent": False,
                },
                evidence_class=EvidenceClass.DECLARED,
                confidence=1.0,
                provenance=provenance,
            )
            for root in self._surface_roots.values():
                self.surface.add_edge(
                    root,
                    node,
                    "references-credential",
                    evidence_class=EvidenceClass.DECLARED,
                    confidence=1.0,
                    provenance=provenance,
                )
        for index, environment in enumerate(self.profile.environments):
            provenance = intake_provenance(
                profile_source,
                f"$/environments/{index}",
                SourceClass.SUPPLIED,
                EvidenceClass.DECLARED,
                environment.to_mapping(),
            )
            node = self.surface.add_node(
                SurfaceNodeKind.CONFIGURATION,
                f"environment:{environment.id}",
                environment.id,
                attributes={
                    "platform": environment.platform,
                    "architecture": environment.architecture,
                    "requirements": sorted(environment.requirements),
                },
                evidence_class=EvidenceClass.DECLARED,
                confidence=1.0,
                provenance=provenance,
            )
            for root in self._surface_roots.values():
                self.surface.add_edge(
                    root,
                    node,
                    "requires-environment",
                    evidence_class=EvidenceClass.DECLARED,
                    confidence=1.0,
                    provenance=provenance,
                )

    def cover(
        self,
        subject: str,
        dimension: str,
        state: CoverageState,
        reason: str,
        *evidence_refs: str,
    ) -> None:
        """Promote one coverage item without allowing unknown to overwrite evidence."""
        if dimension == "target-kind" and subject not in {
            item.value for item in self.profile.target_kinds
        }:
            return
        key = (dimension, subject)
        current = self._coverage.get(key)
        order = {
            CoverageState.UNKNOWN: 0,
            CoverageState.DECLARED: 1,
            CoverageState.DISCOVERED: 2,
            CoverageState.EXERCISED: 3,
            CoverageState.REPRODUCED: 4,
            CoverageState.BLOCKED: 5,
            CoverageState.UNSUPPORTED: 5,
        }
        if current is not None and order[current.state] > order[state]:
            return
        self._coverage[key] = CoverageItem(
            subject=subject,
            dimension=dimension,
            state=state,
            reason=reason,
            evidence_refs=tuple(sorted(set(evidence_refs))),
        )

    def coverage_contract(self) -> CoverageContract:
        return CoverageContract(tuple(self._coverage.values()))


def discover_material(discovery: IntakeDiscovery, material: LoadedMaterial) -> None:
    """Dispatch one material to the appropriate non-executing front end."""
    handlers = {
        InputKind.HTML: _discover_html,
        InputKind.WEB_INVENTORY: _discover_web_inventory,
        InputKind.HAR: _discover_har,
        InputKind.OPENAPI: _discover_openapi,
        InputKind.GRAPHQL_SCHEMA: _discover_graphql,
        InputKind.GRPC_DESCRIPTOR: _discover_grpc,
        InputKind.POSTMAN: _discover_postman,
        InputKind.SOURCE_TREE: _discover_source_collection,
        InputKind.ARCHIVE: _discover_source_collection,
        InputKind.SBOM: _discover_sbom,
        InputKind.LOCKFILE: _discover_lockfile,
        InputKind.OCI_MANIFEST: _discover_oci_manifest,
        InputKind.OCI_CONFIG: _discover_oci_config,
        InputKind.OCI_INVENTORY: _discover_oci_inventory,
        InputKind.NETWORK_INVENTORY: _discover_network_inventory,
        InputKind.TLS_REPORT: _discover_tls_report,
        InputKind.PROCESS_INVENTORY: _discover_process_inventory,
        InputKind.ACCESSIBILITY_TREE: _discover_accessibility_tree,
        InputKind.AGENT_MANIFEST: _discover_agent_manifest,
        InputKind.MCP_MANIFEST: _discover_mcp_manifest,
        InputKind.A2A_CARD: _discover_a2a_card,
        InputKind.RUNTIME_OBSERVATIONS: _discover_runtime_observations,
    }
    handlers[material.descriptor.kind](discovery, material)
    evidence_state = (
        CoverageState.EXERCISED
        if material.descriptor.source_class == SourceClass.ACTIVE
        else CoverageState.DISCOVERED
    )
    discovery.cover(
        material.descriptor.id,
        "input",
        evidence_state,
        f"{material.descriptor.kind.value}-parsed",
        material.start_digest,
    )
    discovery.processed_inputs.append(
        {
            "id": material.descriptor.id,
            "kind": material.descriptor.kind.value,
            "sourceClass": material.descriptor.source_class.value,
            "digest": material.start_digest,
            "status": "parsed",
            "targetCodeExecuted": False,
        }
    )


def _evidence_class(material: LoadedMaterial) -> EvidenceClass:
    return (
        EvidenceClass.OBSERVED
        if material.descriptor.source_class in {SourceClass.PASSIVE, SourceClass.ACTIVE}
        else EvidenceClass.DECLARED
    )


def _provenance(
    material: LoadedMaterial,
    pointer: str,
    projection: object,
    *,
    evidence_class: EvidenceClass | None = None,
) -> IntakeProvenance:
    return intake_provenance(
        material.descriptor.id,
        pointer,
        material.descriptor.source_class,
        evidence_class or _evidence_class(material),
        projection,
    )


def _material_json(material: LoadedMaterial) -> Any:
    if material.payload is None:
        raise FormatError("SOVA-INTAKE-MATERIAL", "material has no file payload")
    return strict_json_loads(material.payload)


def _material_text(material: LoadedMaterial) -> str:
    if material.payload is None:
        raise FormatError("SOVA-INTAKE-MATERIAL", "material has no file payload")
    try:
        return material.payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise FormatError("SOVA-INTAKE-ENCODING", "text material must be UTF-8") from error


class _HTMLInventory(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[dict[str, str]] = []
        self.forms: list[dict[str, Any]] = []
        self.scripts: list[str] = []
        self._current_form: dict[str, Any] | None = None
        self.inline_scripts: list[str] = []
        self._script_text: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key.casefold(): value or "" for key, value in attrs}
        if tag.casefold() in {"a", "link"} and attributes.get("href"):
            self.links.append({"tag": tag.casefold(), "href": attributes["href"]})
        elif tag.casefold() == "form":
            self._current_form = {
                "action": attributes.get("action", ""),
                "method": attributes.get("method", "get").casefold(),
                "inputs": [],
            }
            self.forms.append(self._current_form)
        elif tag.casefold() in {"input", "select", "textarea", "button"}:
            if self._current_form is not None:
                self._current_form["inputs"].append(
                    {
                        "name": attributes.get("name", ""),
                        "type": attributes.get("type", tag.casefold()).casefold(),
                    }
                )
        elif tag.casefold() == "script":
            if attributes.get("src"):
                self.scripts.append(attributes["src"])
            self._script_text = []

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() == "form":
            self._current_form = None
        elif tag.casefold() == "script" and self._script_text is not None:
            self.inline_scripts.append("".join(self._script_text))
            self._script_text = None

    def handle_data(self, data: str) -> None:
        if self._script_text is not None:
            self._script_text.append(data)


def _discover_html(discovery: IntakeDiscovery, material: LoadedMaterial) -> None:
    document = _material_text(material)
    parser = _HTMLInventory()
    parser.feed(document)
    base = next(
        (
            entrypoint.locator
            for entrypoint in discovery.profile.entrypoints
            if entrypoint.kind == EntryPointKind.URL
        ),
        "http://invalid.local/",
    )
    page_key = _safe_url_key(base)
    provenance = _provenance(
        material, "$", {"forms": len(parser.forms), "links": len(parser.links)}
    )
    page = discovery.workflow.add_node(
        WorkflowNodeKind.PAGE,
        page_key,
        _url_name(base),
        attributes={"formCount": len(parser.forms), "linkCount": len(parser.links)},
        evidence_class=_evidence_class(material),
        confidence=0.9,
        provenance=provenance,
    )
    for entry_node in discovery._entry_nodes.values():
        discovery.workflow.add_edge(
            entry_node,
            page,
            "opens",
            evidence_class=_evidence_class(material),
            confidence=0.9,
            provenance=provenance,
        )
    for index, form in enumerate(parser.forms[:_MAX_ITEMS]):
        target = urljoin(base, str(form["action"]))
        method = str(form["method"]).upper()
        form_projection = {
            "action": _safe_url_projection(target),
            "method": method,
            "inputNames": [item["name"] for item in form["inputs"] if item["name"]],
            "inputTypes": [item["type"] for item in form["inputs"]],
        }
        form_provenance = _provenance(material, f"$/forms/{index}", form_projection)
        action = discovery.workflow.add_node(
            WorkflowNodeKind.USER_ACTION,
            f"form:{_safe_url_key(target)}:{method}:{index}",
            f"{method} form",
            attributes={"method": method, "target": _safe_url_projection(target)},
            evidence_class=_evidence_class(material),
            confidence=0.95,
            provenance=form_provenance,
        )
        discovery.workflow.add_edge(
            page,
            action,
            "submits",
            effects=("network.request",),
            evidence_class=_evidence_class(material),
            confidence=0.95,
            provenance=form_provenance,
        )
        endpoint = _surface_endpoint(discovery, material, target, f"$/forms/{index}/action")
        for input_index, item in enumerate(form["inputs"]):
            name = str(item["name"] or f"unnamed-{input_index}")
            input_node = discovery.surface.add_node(
                SurfaceNodeKind.INPUT,
                f"form:{_safe_url_key(target)}:{method}:{name}",
                name,
                attributes={"inputType": item["type"], "method": method},
                evidence_class=_evidence_class(material),
                confidence=0.95,
                provenance=form_provenance,
            )
            discovery.surface.add_edge(
                input_node,
                endpoint,
                "submitted-to",
                evidence_class=_evidence_class(material),
                confidence=0.95,
                provenance=form_provenance,
            )
            if item["type"] == "password":
                identity = discovery.surface.add_node(
                    SurfaceNodeKind.IDENTITY,
                    "browser-authentication",
                    "browser authentication",
                    attributes={"credentialValueCaptured": False},
                    evidence_class=EvidenceClass.INFERRED,
                    confidence=0.7,
                    provenance=_provenance(
                        material,
                        f"$/forms/{index}/inputs/{input_index}",
                        {"type": "password"},
                        evidence_class=EvidenceClass.INFERRED,
                    ),
                )
                discovery.surface.add_edge(
                    input_node,
                    identity,
                    "may-authenticate",
                    evidence_class=EvidenceClass.INFERRED,
                    confidence=0.7,
                    provenance=form_provenance,
                )
    discovered_routes = [item["href"] for item in parser.links] + parser.scripts
    for script in parser.inline_scripts:
        discovered_routes.extend(match.group(1) for match in _ROUTE_PATTERN.finditer(script))
        discovered_routes.extend(match.group("url") for match in _URL_PATTERN.finditer(script))
        if "localStorage" in script or "sessionStorage" in script:
            storage = discovery.surface.add_node(
                SurfaceNodeKind.DATA_STORE,
                "browser-storage",
                "browser storage",
                attributes={"contentCaptured": False},
                evidence_class=EvidenceClass.INFERRED,
                confidence=0.65,
                provenance=_provenance(
                    material,
                    "$/scripts",
                    {"browserStorageReference": True},
                    evidence_class=EvidenceClass.INFERRED,
                ),
            )
            root = discovery._surface_roots.get(ProfileTargetKind.WEB)
            if root is not None:
                discovery.surface.add_edge(
                    root,
                    storage,
                    "uses",
                    evidence_class=EvidenceClass.INFERRED,
                    confidence=0.65,
                    provenance=provenance,
                )
    for index, route in enumerate(dict.fromkeys(discovered_routes[:_MAX_ITEMS])):
        target = urljoin(base, route)
        route_provenance = _provenance(material, f"$/routes/{index}", _safe_url_projection(target))
        route_node = discovery.workflow.add_node(
            WorkflowNodeKind.PAGE,
            _safe_url_key(target),
            _url_name(target),
            attributes={"locator": _safe_url_projection(target)},
            evidence_class=_evidence_class(material),
            confidence=0.8,
            provenance=route_provenance,
        )
        discovery.workflow.add_edge(
            page,
            route_node,
            "may-navigate",
            evidence_class=EvidenceClass.INFERRED,
            confidence=0.65,
            provenance=route_provenance,
        )
        _surface_endpoint(discovery, material, target, f"$/routes/{index}")
    discovery.cover("web", "target-kind", CoverageState.DISCOVERED, "html-inspected")


def _discover_web_inventory(discovery: IntakeDiscovery, material: LoadedMaterial) -> None:
    """Import bounded crawler/browser inventory without trusting captured content."""
    document = _material_json(material)
    if not isinstance(document, dict) or not isinstance(document.get("pages"), list):
        raise FormatError("SOVA-INTAKE-WEB", "web inventory requires a pages array")
    base = next(
        (
            entrypoint.locator
            for entrypoint in discovery.profile.entrypoints
            if entrypoint.kind == EntryPointKind.URL
        ),
        "http://invalid.local/",
    )
    root = _workflow_root(discovery, material, "web-inventory", WorkflowNodeKind.ENTRY)
    for page_index, page_value in enumerate(document["pages"][:_MAX_ITEMS]):
        if not isinstance(page_value, dict):
            continue
        raw_url = page_value.get("url")
        if not isinstance(raw_url, str):
            continue
        url = urljoin(base, raw_url)
        if urlsplit(url).hostname is None:
            continue
        projection = {
            "url": _safe_url_projection(url),
            "routeCount": len(_list(page_value.get("routes"))),
            "formCount": len(_list(page_value.get("forms"))),
            "serviceWorkerCount": len(_list(page_value.get("serviceWorkers"))),
            "webSocketCount": len(_list(page_value.get("webSockets"))),
            "storageCount": len(_list(page_value.get("storage"))),
            "authenticationTransitionCount": len(
                _list(page_value.get("authenticationTransitions"))
            ),
        }
        provenance = _provenance(material, f"$/pages/{page_index}", projection)
        page = discovery.workflow.add_node(
            WorkflowNodeKind.PAGE,
            f"web-inventory:{_safe_url_key(url)}",
            _url_name(url),
            attributes=projection,
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=provenance,
        )
        discovery.workflow.add_edge(
            root,
            page,
            "observed-page",
            preconditions=("authorized-observation-import",),
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=provenance,
        )
        endpoint = _surface_endpoint(discovery, material, url, f"$/pages/{page_index}/url")
        _discover_web_policy(discovery, material, page_value, page_index, endpoint)
        _discover_web_forms(discovery, material, page_value, page_index, page, endpoint, url)
        _discover_web_routes(discovery, material, page_value, page_index, page, url)
        _discover_web_browser_surfaces(discovery, material, page_value, page_index, endpoint, url)
        _discover_web_auth_transitions(discovery, material, page_value, page_index, page)
    state = (
        CoverageState.EXERCISED
        if material.descriptor.source_class == SourceClass.ACTIVE
        else CoverageState.DISCOVERED
    )
    discovery.cover("web", "target-kind", state, "web-inventory-imported")


def _discover_web_policy(
    discovery: IntakeDiscovery,
    material: LoadedMaterial,
    page: dict[str, Any],
    page_index: int,
    endpoint: str,
) -> None:
    robots = _mapping(page.get("robots"))
    policies = _list(page.get("policies"))
    if not robots and not policies:
        return
    policy_projection = {
        "robotsObserved": bool(robots),
        "robotsDirectiveNames": sorted(str(key) for key in robots)[:256],
        "robotsValueDigests": [
            sha256_digest(str(value).encode()) for _key, value in sorted(robots.items())[:256]
        ],
        "policyDigests": [
            sha256_digest(canonical_json_bytes(item))
            for item in policies[:256]
            if isinstance(item, (dict, list, str, bool, int)) or item is None
        ],
        "policyContentCaptured": False,
    }
    provenance = _provenance(
        material,
        f"$/pages/{page_index}/policy",
        policy_projection,
    )
    policy_node = discovery.surface.add_node(
        SurfaceNodeKind.CONFIGURATION,
        f"web-policy:{page_index}:{provenance.projection_digest}",
        "web crawl and disclosure policy",
        attributes=policy_projection,
        evidence_class=_evidence_class(material),
        confidence=1.0,
        provenance=provenance,
    )
    discovery.surface.add_edge(
        policy_node,
        endpoint,
        "constrains-observation",
        evidence_class=_evidence_class(material),
        confidence=1.0,
        provenance=provenance,
    )


def _discover_web_forms(  # noqa: PLR0913, PLR0917 - bindings stay explicit
    discovery: IntakeDiscovery,
    material: LoadedMaterial,
    page_value: dict[str, Any],
    page_index: int,
    page_node: str,
    page_endpoint: str,
    base_url: str,
) -> None:
    for form_index, form in enumerate(_list(page_value.get("forms"))[:_MAX_ITEMS]):
        if not isinstance(form, dict):
            continue
        action_url = urljoin(base_url, str(form.get("action", "")))
        method = str(form.get("method", "GET")).upper()
        inputs = _list(form.get("inputs"))
        projection = {
            "action": _safe_url_projection(action_url),
            "method": method,
            "inputCount": len(inputs),
            "uploadPresent": any(
                isinstance(item, dict) and item.get("type") == "file" for item in inputs
            ),
        }
        provenance = _provenance(
            material,
            f"$/pages/{page_index}/forms/{form_index}",
            projection,
        )
        action = discovery.workflow.add_node(
            WorkflowNodeKind.USER_ACTION,
            f"web-form:{page_index}:{form_index}:{_safe_url_key(action_url)}",
            f"{method} form",
            attributes=projection,
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=provenance,
        )
        discovery.workflow.add_edge(
            page_node,
            action,
            "submits",
            effects=("network.request",),
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=provenance,
        )
        endpoint = _surface_endpoint(
            discovery,
            material,
            action_url,
            f"$/pages/{page_index}/forms/{form_index}/action",
        )
        discovery.surface.add_edge(
            page_endpoint,
            endpoint,
            "may-submit-to",
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=provenance,
        )
        for input_index, input_value in enumerate(inputs[:_MAX_ITEMS]):
            if not isinstance(input_value, dict):
                continue
            input_type = str(input_value.get("type", "text"))
            input_name = str(input_value.get("name", f"input-{input_index}"))
            input_projection = {
                "inputType": input_type,
                "required": bool(input_value.get("required", False)),
                "valueCaptured": False,
                "upload": input_type == "file",
            }
            input_provenance = _provenance(
                material,
                f"$/pages/{page_index}/forms/{form_index}/inputs/{input_index}",
                input_projection,
            )
            input_node = discovery.surface.add_node(
                SurfaceNodeKind.INPUT,
                f"web-form-input:{page_index}:{form_index}:{input_index}:{input_name}",
                input_name,
                attributes=input_projection,
                evidence_class=_evidence_class(material),
                confidence=1.0,
                provenance=input_provenance,
            )
            discovery.surface.add_edge(
                input_node,
                endpoint,
                "submitted-to",
                evidence_class=_evidence_class(material),
                confidence=1.0,
                provenance=input_provenance,
            )


def _discover_web_routes(  # noqa: PLR0913, PLR0917 - bindings stay explicit
    discovery: IntakeDiscovery,
    material: LoadedMaterial,
    page_value: dict[str, Any],
    page_index: int,
    page_node: str,
    base_url: str,
) -> None:
    for route_index, route in enumerate(_list(page_value.get("routes"))[:_MAX_ITEMS]):
        route_url = urljoin(base_url, str(route))
        if urlsplit(route_url).hostname is None:
            continue
        provenance = _provenance(
            material,
            f"$/pages/{page_index}/routes/{route_index}",
            _safe_url_projection(route_url),
        )
        route_node = discovery.workflow.add_node(
            WorkflowNodeKind.PAGE,
            f"web-route:{_safe_url_key(route_url)}",
            _url_name(route_url),
            attributes={"locator": _safe_url_projection(route_url)},
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=provenance,
        )
        discovery.workflow.add_edge(
            page_node,
            route_node,
            "navigates-to",
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=provenance,
        )
        _surface_endpoint(
            discovery,
            material,
            route_url,
            f"$/pages/{page_index}/routes/{route_index}",
        )


def _discover_web_browser_surfaces(  # noqa: PLR0913, PLR0917 - bindings stay explicit
    discovery: IntakeDiscovery,
    material: LoadedMaterial,
    page_value: dict[str, Any],
    page_index: int,
    page_endpoint: str,
    base_url: str,
) -> None:
    for role, relation, values in (
        ("service-worker", "registers", _list(page_value.get("serviceWorkers"))),
        ("websocket", "connects-to", _list(page_value.get("webSockets"))),
        ("download", "downloads-from", _list(page_value.get("downloads"))),
        ("upload", "uploads-to", _list(page_value.get("uploads"))),
    ):
        for index, value in enumerate(values[:_MAX_ITEMS]):
            raw_url = value.get("url") if isinstance(value, dict) else value
            if not isinstance(raw_url, str):
                continue
            target_url = urljoin(base_url, raw_url)
            if urlsplit(target_url).hostname is None:
                continue
            projection = {"role": role, "url": _safe_url_projection(target_url)}
            provenance = _provenance(
                material,
                f"$/pages/{page_index}/{role}/{index}",
                projection,
            )
            surface = _surface_endpoint(
                discovery,
                material,
                target_url,
                f"$/pages/{page_index}/{role}/{index}/url",
            )
            discovery.surface.add_edge(
                page_endpoint,
                surface,
                relation,
                evidence_class=_evidence_class(material),
                confidence=1.0,
                provenance=provenance,
            )
    for storage_index, storage in enumerate(_list(page_value.get("storage"))[:_MAX_ITEMS]):
        storage_kind = (
            str(storage.get("kind", "browser-storage"))
            if isinstance(storage, dict)
            else str(storage)
        )
        storage_projection: dict[str, Any] = {
            "kindDigest": sha256_digest(storage_kind.encode()),
            "contentCaptured": False,
        }
        provenance = _provenance(
            material,
            f"$/pages/{page_index}/storage/{storage_index}",
            storage_projection,
        )
        data_store = discovery.surface.add_node(
            SurfaceNodeKind.DATA_STORE,
            f"browser-storage:{page_index}:{storage_index}:{storage_projection['kindDigest']}",
            "browser storage",
            attributes=storage_projection,
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=provenance,
        )
        discovery.surface.add_edge(
            page_endpoint,
            data_store,
            "uses-storage",
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=provenance,
        )


def _discover_web_auth_transitions(
    discovery: IntakeDiscovery,
    material: LoadedMaterial,
    page_value: dict[str, Any],
    page_index: int,
    page_node: str,
) -> None:
    for index, transition in enumerate(
        _list(page_value.get("authenticationTransitions"))[:_MAX_ITEMS]
    ):
        if not isinstance(transition, dict):
            continue
        projection = {
            "fromDigest": sha256_digest(str(transition.get("from", "unknown")).encode()),
            "toDigest": sha256_digest(str(transition.get("to", "unknown")).encode()),
            "triggerDigest": sha256_digest(str(transition.get("trigger", "unknown")).encode()),
            "credentialValueCaptured": False,
        }
        provenance = _provenance(
            material,
            f"$/pages/{page_index}/authenticationTransitions/{index}",
            projection,
        )
        state = discovery.workflow.add_node(
            WorkflowNodeKind.AUTH_STATE,
            f"web-auth-state:{page_index}:{index}:{projection['toDigest']}",
            f"authentication state {index}",
            attributes=projection,
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=provenance,
        )
        discovery.workflow.add_edge(
            page_node,
            state,
            "authentication-transition",
            effects=("identity.state-change",),
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=provenance,
        )


def _discover_har(discovery: IntakeDiscovery, material: LoadedMaterial) -> None:
    document = _material_json(material)
    entries = (
        document.get("log", {}).get("entries", [])
        if isinstance(document, dict) and isinstance(document.get("log"), dict)
        else []
    )
    if not isinstance(entries, list):
        raise FormatError("SOVA-INTAKE-HAR", "HAR entries must be an array")
    previous: str | None = None
    for index, entry in enumerate(entries[:_MAX_ITEMS]):
        if not isinstance(entry, dict) or not isinstance(entry.get("request"), dict):
            continue
        request = _mapping(entry["request"])
        method = str(request.get("method", "GET")).upper()
        url = str(request.get("url", ""))
        if not urlsplit(url).hostname:
            continue
        response = _mapping(entry.get("response"))
        request_header_names = _header_names(request.get("headers"))
        query_names = _query_names(request.get("queryString"))
        projection = {
            "method": method,
            "url": _safe_url_projection(url),
            "status": response.get("status"),
            "requestHeaderNames": request_header_names,
            "queryNames": query_names,
        }
        provenance = _provenance(material, f"$/log/entries/{index}", projection)
        operation = discovery.workflow.add_node(
            WorkflowNodeKind.API_OPERATION,
            f"har:{method}:{_safe_url_key(url)}",
            f"{method} {_url_name(url)}",
            attributes=projection,
            evidence_class=EvidenceClass.OBSERVED,
            confidence=1.0,
            provenance=provenance,
        )
        if previous is not None:
            discovery.workflow.add_edge(
                previous,
                operation,
                "followed-by",
                evidence_class=EvidenceClass.OBSERVED,
                confidence=1.0,
                provenance=provenance,
            )
        previous = operation
        endpoint = _surface_endpoint(discovery, material, url, f"$/log/entries/{index}/request")
        for name in query_names:
            input_node = discovery.surface.add_node(
                SurfaceNodeKind.INPUT,
                f"har-query:{method}:{_safe_url_key(url)}:{name}",
                name,
                attributes={"location": "query", "valueCaptured": False},
                evidence_class=EvidenceClass.OBSERVED,
                confidence=1.0,
                provenance=provenance,
            )
            discovery.surface.add_edge(
                input_node,
                endpoint,
                "sent-to",
                evidence_class=EvidenceClass.OBSERVED,
                confidence=1.0,
                provenance=provenance,
            )
        if any(_SECRET_NAME.search(name) for name in request_header_names):
            auth = discovery.surface.add_node(
                SurfaceNodeKind.IDENTITY,
                "har-authentication",
                "observed authentication boundary",
                attributes={"headerValuesCaptured": False},
                evidence_class=EvidenceClass.OBSERVED,
                confidence=0.95,
                provenance=provenance,
            )
            discovery.surface.add_edge(
                auth,
                endpoint,
                "authenticates-to",
                evidence_class=EvidenceClass.OBSERVED,
                confidence=0.95,
                provenance=provenance,
            )
    state = (
        CoverageState.EXERCISED
        if material.descriptor.source_class == SourceClass.ACTIVE
        else CoverageState.DISCOVERED
    )
    discovery.cover("web", "target-kind", state, "har-observed")
    discovery.cover("api", "target-kind", state, "har-observed")


def _discover_openapi(  # noqa: PLR0912, PLR0915 - constructs have distinct projections
    discovery: IntakeDiscovery, material: LoadedMaterial
) -> None:
    document = _material_json(material)
    if not isinstance(document, dict) or not (
        isinstance(document.get("openapi"), str) or isinstance(document.get("swagger"), str)
    ):
        raise FormatError("SOVA-INTAKE-OPENAPI", "OpenAPI document version is missing")
    paths = document.get("paths")
    if not isinstance(paths, dict):
        raise FormatError("SOVA-INTAKE-OPENAPI", "OpenAPI paths must be an object")
    root = _workflow_root(discovery, material, "openapi", WorkflowNodeKind.ENTRY)
    security_schemes = document.get("components", {}).get("securitySchemes", {})
    if not isinstance(security_schemes, dict):
        security_schemes = {}
    for name, scheme in sorted(security_schemes.items()):
        if not isinstance(scheme, dict):
            continue
        provenance = _provenance(
            material, f"$/components/securitySchemes/{name}", {"type": scheme.get("type")}
        )
        discovery.surface.add_node(
            SurfaceNodeKind.IDENTITY,
            f"openapi-security:{name}",
            str(name),
            attributes={
                "type": scheme.get("type"),
                "scheme": scheme.get("scheme"),
                "credentialValueCaptured": False,
            },
            evidence_class=EvidenceClass.DECLARED,
            confidence=1.0,
            provenance=provenance,
        )
    operation_count = 0
    operation_id_nodes: dict[str, str] = {}
    path_method_nodes: dict[tuple[str, str], str] = {}
    pending_links: list[tuple[str, str, str, dict[str, Any]]] = []
    for raw_path, path_item in sorted(paths.items()):
        if not isinstance(raw_path, str) or not isinstance(path_item, dict):
            continue
        for method, operation in sorted(path_item.items()):
            if method.casefold() not in _HTTP_METHODS or not isinstance(operation, dict):
                continue
            operation_count += 1
            projection = {
                "method": method.upper(),
                "path": raw_path,
                "operationId": operation.get("operationId"),
                "deprecated": bool(operation.get("deprecated", False)),
            }
            provenance = _provenance(material, f"$/paths/{raw_path}/{method}", projection)
            operation_node = discovery.workflow.add_node(
                WorkflowNodeKind.API_OPERATION,
                f"openapi:{method.casefold()}:{raw_path}",
                f"{method.upper()} {raw_path}",
                attributes=projection,
                evidence_class=EvidenceClass.DECLARED,
                confidence=1.0,
                provenance=provenance,
            )
            path_method_nodes[(raw_path, method.casefold())] = operation_node
            if isinstance(operation.get("operationId"), str):
                operation_id_nodes[operation["operationId"]] = operation_node
            discovery.workflow.add_edge(
                root,
                operation_node,
                "declares-operation",
                effects=("api.request",),
                evidence_class=EvidenceClass.DECLARED,
                confidence=1.0,
                provenance=provenance,
            )
            endpoint = discovery.surface.add_node(
                SurfaceNodeKind.ENDPOINT,
                f"openapi:{method.casefold()}:{raw_path}",
                f"{method.upper()} {raw_path}",
                attributes=projection,
                evidence_class=EvidenceClass.DECLARED,
                confidence=1.0,
                provenance=provenance,
            )
            path_parameters = path_item.get("parameters", [])
            operation_parameters = operation.get("parameters", [])
            parameters = [
                *(path_parameters if isinstance(path_parameters, list) else []),
                *(operation_parameters if isinstance(operation_parameters, list) else []),
            ]
            for parameter_index, parameter in enumerate(parameters):
                if not isinstance(parameter, dict) or not isinstance(parameter.get("name"), str):
                    continue
                name = parameter["name"]
                input_node = discovery.surface.add_node(
                    SurfaceNodeKind.INPUT,
                    f"openapi:{method}:{raw_path}:{parameter.get('in')}:{name}",
                    name,
                    attributes={
                        "location": parameter.get("in"),
                        "required": bool(parameter.get("required", False)),
                    },
                    evidence_class=EvidenceClass.DECLARED,
                    confidence=1.0,
                    provenance=_provenance(
                        material,
                        f"$/paths/{raw_path}/{method}/parameters/{parameter_index}",
                        {"name": name, "in": parameter.get("in")},
                    ),
                )
                discovery.surface.add_edge(
                    input_node,
                    endpoint,
                    "accepted-by",
                    evidence_class=EvidenceClass.DECLARED,
                    confidence=1.0,
                    provenance=provenance,
                )
            if "requestBody" in operation:
                body = discovery.surface.add_node(
                    SurfaceNodeKind.INPUT,
                    f"openapi:{method}:{raw_path}:request-body",
                    "request body",
                    attributes={"location": "body"},
                    evidence_class=EvidenceClass.DECLARED,
                    confidence=1.0,
                    provenance=provenance,
                )
                discovery.surface.add_edge(
                    body,
                    endpoint,
                    "accepted-by",
                    evidence_class=EvidenceClass.DECLARED,
                    confidence=1.0,
                    provenance=provenance,
                )
            responses = operation.get("responses")
            if isinstance(responses, dict):
                for response_code, response in sorted(responses.items()):
                    if not isinstance(response, dict) or not isinstance(
                        response.get("links"), dict
                    ):
                        continue
                    for link_name, link in sorted(response["links"].items()):
                        if isinstance(link_name, str) and isinstance(link, dict):
                            pending_links.append(
                                (
                                    operation_node,
                                    str(response_code),
                                    link_name,
                                    link,
                                )
                            )
    _add_openapi_stateful_links(
        discovery,
        material,
        operation_id_nodes,
        path_method_nodes,
        pending_links,
    )
    for index, (name, webhook) in enumerate(sorted(_mapping(document.get("webhooks")).items())):
        provenance = _provenance(material, f"$/webhooks/{name}", {"name": name})
        external = discovery.surface.add_node(
            SurfaceNodeKind.EXTERNAL_RESOURCE,
            f"openapi-webhook:{name}",
            str(name),
            attributes={"outboundCallback": True, "definitionPresent": isinstance(webhook, dict)},
            evidence_class=EvidenceClass.DECLARED,
            confidence=1.0,
            provenance=provenance,
        )
        api_root = discovery._surface_roots.get(ProfileTargetKind.API)
        if api_root is not None:
            discovery.surface.add_edge(
                api_root,
                external,
                "calls",
                key=str(index),
                evidence_class=EvidenceClass.DECLARED,
                confidence=1.0,
                provenance=provenance,
            )
    if operation_count == 0:
        discovery.limitations.append("OpenAPI document declared no supported operations")
    discovery.cover("api", "target-kind", CoverageState.DISCOVERED, "openapi-inspected")


def _add_openapi_stateful_links(
    discovery: IntakeDiscovery,
    material: LoadedMaterial,
    operation_id_nodes: dict[str, str],
    path_method_nodes: dict[tuple[str, str], str],
    pending_links: list[tuple[str, str, str, dict[str, Any]]],
) -> None:
    """Project OpenAPI Link Objects as declared stateful workflow transitions."""
    for index, (source, response_code, link_name, link) in enumerate(pending_links):
        operation_id = link.get("operationId")
        operation_ref = link.get("operationRef")
        target = (
            operation_id_nodes.get(operation_id)
            if isinstance(operation_id, str)
            else _openapi_ref_target(operation_ref, path_method_nodes)
        )
        target_key = operation_id if isinstance(operation_id, str) else operation_ref
        parameter_names = sorted(str(name) for name in _mapping(link.get("parameters")))
        projection = {
            "linkName": link_name,
            "responseCode": response_code,
            "targetReferenceDigest": sha256_digest(str(target_key or "unknown").encode()),
            "targetResolved": target is not None,
            "parameterNames": parameter_names,
            "requestBodyMapped": "requestBody" in link,
        }
        provenance = _provenance(material, f"$/links/{index}", projection)
        if target is None:
            target = discovery.workflow.add_node(
                WorkflowNodeKind.UNKNOWN,
                f"openapi-link-target:{projection['targetReferenceDigest']}",
                "unresolved linked operation",
                attributes={
                    "targetReferenceDigest": projection["targetReferenceDigest"],
                    "resolution": "unknown",
                },
                evidence_class=EvidenceClass.DECLARED,
                confidence=1.0,
                provenance=provenance,
            )
            discovery.limitations.append(
                "An OpenAPI stateful link target could not be resolved within the "
                "supplied document."
            )
        discovery.workflow.add_edge(
            source,
            target,
            "stateful-operation-link",
            key=f"{response_code}:{link_name}:{index}",
            preconditions=(f"response:{response_code}",),
            effects=("api.follow-up-request",),
            attributes=projection,
            evidence_class=EvidenceClass.DECLARED,
            confidence=1.0,
            provenance=provenance,
        )


def _openapi_ref_target(
    operation_ref: object,
    path_method_nodes: dict[tuple[str, str], str],
) -> str | None:
    if not isinstance(operation_ref, str) or not operation_ref.startswith("#/paths/"):
        return None
    components = operation_ref.removeprefix("#/paths/").split("/")
    if len(components) != _OPENAPI_REF_PARTS:
        return None
    raw_path = components[0].replace("~1", "/").replace("~0", "~")
    return path_method_nodes.get((raw_path, components[1].casefold()))


def _discover_graphql(discovery: IntakeDiscovery, material: LoadedMaterial) -> None:
    schema = _material_text(material)
    root = _workflow_root(discovery, material, "graphql", WorkflowNodeKind.ENTRY)
    count = 0
    for type_match in _GRAPHQL_TYPE.finditer(schema):
        operation_type = type_match.group(1).casefold()
        for field_name in _GRAPHQL_FIELD.findall(type_match.group(2)):
            count += 1
            provenance = _provenance(
                material,
                f"$/type/{operation_type}/{field_name}",
                {"operationType": operation_type, "field": field_name},
            )
            operation = discovery.workflow.add_node(
                WorkflowNodeKind.API_OPERATION,
                f"graphql:{operation_type}:{field_name}",
                f"{operation_type} {field_name}",
                attributes={"protocol": "graphql", "operationType": operation_type},
                evidence_class=EvidenceClass.DECLARED,
                confidence=1.0,
                provenance=provenance,
            )
            discovery.workflow.add_edge(
                root,
                operation,
                "declares-operation",
                evidence_class=EvidenceClass.DECLARED,
                confidence=1.0,
                provenance=provenance,
            )
            endpoint = discovery.surface.add_node(
                SurfaceNodeKind.ENDPOINT,
                f"graphql:{operation_type}:{field_name}",
                field_name,
                attributes={"protocol": "graphql", "operationType": operation_type},
                evidence_class=EvidenceClass.DECLARED,
                confidence=1.0,
                provenance=provenance,
            )
            if operation_type in {"mutation", "subscription"}:
                endpoint_root = discovery._surface_roots.get(ProfileTargetKind.API)
                if endpoint_root is not None:
                    discovery.surface.add_edge(
                        endpoint_root,
                        endpoint,
                        "exposes",
                        evidence_class=EvidenceClass.DECLARED,
                        confidence=1.0,
                        provenance=provenance,
                    )
    if count == 0:
        discovery.limitations.append(
            "GraphQL schema contained no Query, Mutation, or Subscription fields"
        )
    discovery.cover("api", "target-kind", CoverageState.DISCOVERED, "graphql-schema-inspected")


def _discover_grpc(discovery: IntakeDiscovery, material: LoadedMaterial) -> None:
    text = _material_text(material)
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        document = None
    services: list[tuple[str, list[tuple[str, str, str]]]] = []
    if isinstance(document, dict) and isinstance(document.get("services"), list):
        for service in document["services"][:_MAX_ITEMS]:
            if not isinstance(service, dict) or not isinstance(service.get("name"), str):
                continue
            methods = [
                (
                    method["name"],
                    str(method.get("input", "")),
                    str(method.get("output", "")),
                )
                for method in service.get("methods", [])
                if isinstance(method, dict) and isinstance(method.get("name"), str)
            ]
            services.append((service["name"], methods))
    else:
        for service_match in _PROTO_SERVICE.finditer(text):
            methods = [tuple(match) for match in _PROTO_RPC.findall(service_match.group(2))]
            services.append((service_match.group(1), methods))
    root = _workflow_root(discovery, material, "grpc", WorkflowNodeKind.ENTRY)
    for service_name, methods in services:
        for method_name, input_type, output_type in methods:
            projection = {
                "service": service_name,
                "method": method_name,
                "inputType": input_type,
                "outputType": output_type,
            }
            provenance = _provenance(
                material, f"$/services/{service_name}/{method_name}", projection
            )
            operation = discovery.workflow.add_node(
                WorkflowNodeKind.API_OPERATION,
                f"grpc:{service_name}:{method_name}",
                f"{service_name}/{method_name}",
                attributes=projection,
                evidence_class=EvidenceClass.DECLARED,
                confidence=1.0,
                provenance=provenance,
            )
            discovery.workflow.add_edge(
                root,
                operation,
                "declares-operation",
                evidence_class=EvidenceClass.DECLARED,
                confidence=1.0,
                provenance=provenance,
            )
            discovery.surface.add_node(
                SurfaceNodeKind.ENDPOINT,
                f"grpc:{service_name}:{method_name}",
                f"{service_name}/{method_name}",
                attributes={"protocol": "grpc", **projection},
                evidence_class=EvidenceClass.DECLARED,
                confidence=1.0,
                provenance=provenance,
            )
    if not services:
        discovery.limitations.append("gRPC descriptor contained no recognized services")
    discovery.cover("api", "target-kind", CoverageState.DISCOVERED, "grpc-descriptor-inspected")


def _discover_postman(discovery: IntakeDiscovery, material: LoadedMaterial) -> None:
    document = _material_json(material)
    if not isinstance(document, dict):
        raise FormatError("SOVA-INTAKE-POSTMAN", "Postman collection root must be an object")
    root = _workflow_root(discovery, material, "postman", WorkflowNodeKind.ENTRY)
    requests = list(_postman_requests(document.get("item", [])))
    for index, request in enumerate(requests[:_MAX_ITEMS]):
        method = str(request.get("method", "GET")).upper()
        url = _postman_url(request.get("url"))
        projection = {"method": method, "url": _safe_url_projection(url)}
        provenance = _provenance(material, f"$/item/{index}/request", projection)
        operation = discovery.workflow.add_node(
            WorkflowNodeKind.API_OPERATION,
            f"postman:{method}:{_safe_url_key(url)}:{index}",
            f"{method} {_url_name(url)}",
            attributes=projection,
            evidence_class=EvidenceClass.DECLARED,
            confidence=0.95,
            provenance=provenance,
        )
        discovery.workflow.add_edge(
            root,
            operation,
            "declares-operation",
            evidence_class=EvidenceClass.DECLARED,
            confidence=0.95,
            provenance=provenance,
        )
        _surface_endpoint(discovery, material, url, f"$/item/{index}/request/url")
    discovery.cover("api", "target-kind", CoverageState.DISCOVERED, "postman-inspected")


def _discover_source_collection(discovery: IntakeDiscovery, material: LoadedMaterial) -> None:
    if not material.files:
        discovery.limitations.append(f"{material.descriptor.id} contained no inspectable files")
    source_root = discovery._surface_roots.get(
        ProfileTargetKind.SOURCE
    ) or discovery._surface_roots.get(ProfileTargetKind.PACKAGE)
    for index, (relative, content) in enumerate(sorted(material.files.items())[:_MAX_ITEMS]):
        category = _source_file_category(relative, content)
        projection = {
            "path": relative,
            "size": len(content),
            "digest": sha256_digest(content),
            "category": category,
        }
        provenance = _provenance(material, f"$/files/{index}", projection)
        file_node = discovery.surface.add_node(
            SurfaceNodeKind.FILE,
            f"source:{relative}",
            PurePosixPath(relative).name,
            attributes={
                "relativePath": relative,
                "size": len(content),
                "digest": projection["digest"],
                "category": category,
            },
            evidence_class=EvidenceClass.DECLARED,
            confidence=1.0,
            provenance=provenance,
        )
        if source_root is not None:
            discovery.surface.add_edge(
                source_root,
                file_node,
                "contains",
                evidence_class=EvidenceClass.DECLARED,
                confidence=1.0,
                provenance=provenance,
            )
        lower = relative.casefold()
        secret_indicator_count = min(len(_POTENTIAL_SECRET.findall(content)), 10_000)
        if secret_indicator_count:
            secret_projection = {
                "indicatorCount": secret_indicator_count,
                "valuesCaptured": False,
                "requiresHumanReview": True,
            }
            secret_provenance = _provenance(
                material,
                f"$/files/{index}/secret-indicators",
                secret_projection,
                evidence_class=EvidenceClass.INFERRED,
            )
            indicator = discovery.surface.add_node(
                SurfaceNodeKind.CONFIGURATION,
                f"secret-indicators:{relative}:{projection['digest']}",
                "potential secret material",
                attributes=secret_projection,
                evidence_class=EvidenceClass.INFERRED,
                confidence=0.6,
                provenance=secret_provenance,
            )
            discovery.surface.add_edge(
                file_node,
                indicator,
                "may-contain",
                evidence_class=EvidenceClass.INFERRED,
                confidence=0.6,
                provenance=secret_provenance,
            )
            discovery.limitations.append(
                "Source secret indicators are heuristic presence signals, not confirmed exposures."
            )
        if lower.endswith("package.json"):
            _discover_package_json(discovery, material, relative, content, file_node)
        elif lower.endswith("pyproject.toml"):
            _discover_pyproject(discovery, material, relative, content, file_node)
        elif PurePosixPath(lower).name in {
            "requirements.txt",
            "poetry.lock",
            "uv.lock",
            "cargo.lock",
            "go.sum",
        }:
            _discover_dependency_lines(discovery, material, relative, content, file_node)
        elif PurePosixPath(lower).name in {"dockerfile", "containerfile"}:
            _discover_containerfile(discovery, material, relative, content, file_node)
        elif lower.endswith((".yaml", ".yml")) and ".github/workflows/" in lower:
            workflow = discovery.surface.add_node(
                SurfaceNodeKind.CONFIGURATION,
                f"ci:{relative}",
                "CI workflow",
                attributes={"relativePath": relative, "contentCaptured": False},
                evidence_class=EvidenceClass.DECLARED,
                confidence=1.0,
                provenance=provenance,
            )
            discovery.surface.add_edge(
                file_node,
                workflow,
                "declares",
                evidence_class=EvidenceClass.DECLARED,
                confidence=1.0,
                provenance=provenance,
            )
    discovery.cover("source", "target-kind", CoverageState.DISCOVERED, "source-material-inspected")
    discovery.cover(
        "package", "target-kind", CoverageState.DISCOVERED, "package-material-inspected"
    )


def _source_file_category(relative: str, content: bytes) -> str:
    path = PurePosixPath(relative.casefold())
    name = path.name
    if b"\x00" in content[:8192]:
        return "binary"
    if any(
        part in {"test", "tests", "fixture", "fixtures", "spec", "specs"} for part in path.parts
    ):
        return "test-fixture"
    if name in {
        ".env",
        "dockerfile",
        "containerfile",
        "package.json",
        "pyproject.toml",
        "requirements.txt",
    } or path.suffix in {".ini", ".json", ".toml", ".yaml", ".yml"}:
        return "configuration"
    if path.suffix in {".exe", ".dll", ".so", ".dylib", ".bin", ".wasm"}:
        return "binary"
    return "source"


def _discover_package_json(
    discovery: IntakeDiscovery,
    material: LoadedMaterial,
    relative: str,
    content: bytes,
    file_node: str,
) -> None:
    try:
        document = strict_json_loads(content)
    except FormatError:
        discovery.limitations.append(f"Could not parse {relative} as package.json")
        return
    if not isinstance(document, dict):
        return
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        dependencies = document.get(section)
        if not isinstance(dependencies, dict):
            continue
        for name, version in sorted(dependencies.items()):
            provenance = _provenance(
                material,
                f"$/files/{relative}/{section}/{name}",
                {"name": name, "version": str(version), "section": section},
            )
            dependency = discovery.surface.add_node(
                SurfaceNodeKind.DEPENDENCY,
                f"npm:{name}:{version}",
                str(name),
                attributes={
                    "ecosystem": "npm",
                    "versionConstraint": str(version),
                    "section": section,
                },
                evidence_class=EvidenceClass.DECLARED,
                confidence=1.0,
                provenance=provenance,
            )
            discovery.surface.add_edge(
                file_node,
                dependency,
                "depends-on",
                evidence_class=EvidenceClass.DECLARED,
                confidence=1.0,
                provenance=provenance,
            )
    scripts = document.get("scripts")
    if isinstance(scripts, dict):
        for name in sorted(str(key) for key in scripts):
            provenance = _provenance(material, f"$/files/{relative}/scripts/{name}", {"name": name})
            process = discovery.surface.add_node(
                SurfaceNodeKind.PROCESS,
                f"npm-script:{relative}:{name}",
                name,
                attributes={"commandCaptured": False, "executable": False},
                evidence_class=EvidenceClass.DECLARED,
                confidence=1.0,
                provenance=provenance,
            )
            discovery.surface.add_edge(
                file_node,
                process,
                "declares-entrypoint",
                evidence_class=EvidenceClass.DECLARED,
                confidence=1.0,
                provenance=provenance,
            )


def _discover_pyproject(
    discovery: IntakeDiscovery,
    material: LoadedMaterial,
    relative: str,
    content: bytes,
    file_node: str,
) -> None:
    try:
        document = tomllib.loads(content.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError):
        discovery.limitations.append(f"Could not parse {relative} as pyproject.toml")
        return
    project = document.get("project") if isinstance(document.get("project"), dict) else {}
    dependencies = project.get("dependencies", []) if isinstance(project, dict) else []
    if isinstance(dependencies, list):
        for index, dependency_value in enumerate(dependencies):
            if not isinstance(dependency_value, str):
                continue
            name = re.split(r"[<>=!~;\[\s]", dependency_value, maxsplit=1)[0]
            provenance = _provenance(
                material,
                f"$/files/{relative}/project/dependencies/{index}",
                {"name": name, "declarationDigest": sha256_digest(dependency_value.encode())},
            )
            dependency = discovery.surface.add_node(
                SurfaceNodeKind.DEPENDENCY,
                f"pypi:{dependency_value}",
                name,
                attributes={"ecosystem": "pypi", "declarationDigest": provenance.projection_digest},
                evidence_class=EvidenceClass.DECLARED,
                confidence=1.0,
                provenance=provenance,
            )
            discovery.surface.add_edge(
                file_node,
                dependency,
                "depends-on",
                evidence_class=EvidenceClass.DECLARED,
                confidence=1.0,
                provenance=provenance,
            )
    scripts = project.get("scripts", {}) if isinstance(project, dict) else {}
    if isinstance(scripts, dict):
        for name in sorted(str(key) for key in scripts):
            provenance = _provenance(
                material, f"$/files/{relative}/project/scripts/{name}", {"name": name}
            )
            process = discovery.surface.add_node(
                SurfaceNodeKind.PROCESS,
                f"python-entry:{relative}:{name}",
                name,
                attributes={"entrypointValueCaptured": False, "executable": False},
                evidence_class=EvidenceClass.DECLARED,
                confidence=1.0,
                provenance=provenance,
            )
            discovery.surface.add_edge(
                file_node,
                process,
                "declares-entrypoint",
                evidence_class=EvidenceClass.DECLARED,
                confidence=1.0,
                provenance=provenance,
            )


def _discover_dependency_lines(
    discovery: IntakeDiscovery,
    material: LoadedMaterial,
    relative: str,
    content: bytes,
    file_node: str,
) -> None:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return
    for index, line in enumerate(text.splitlines()[:_MAX_ITEMS]):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "[[", "version =", "source =")):
            continue
        name = re.split(r"[<>=!~;\[\s]", stripped, maxsplit=1)[0].strip('"')
        if not name or len(name) > _MAX_DEPENDENCY_NAME:
            continue
        provenance = _provenance(
            material,
            f"$/files/{relative}/lines/{index}",
            {"name": name, "lineDigest": sha256_digest(stripped.encode())},
        )
        dependency = discovery.surface.add_node(
            SurfaceNodeKind.DEPENDENCY,
            f"lock:{relative}:{stripped}",
            name,
            attributes={"declarationDigest": provenance.projection_digest},
            evidence_class=EvidenceClass.DECLARED,
            confidence=0.8,
            provenance=provenance,
        )
        discovery.surface.add_edge(
            file_node,
            dependency,
            "depends-on",
            evidence_class=EvidenceClass.DECLARED,
            confidence=0.8,
            provenance=provenance,
        )


def _discover_containerfile(
    discovery: IntakeDiscovery,
    material: LoadedMaterial,
    relative: str,
    content: bytes,
    file_node: str,
) -> None:
    try:
        lines = content.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return
    for index, line in enumerate(lines[:_MAX_ITEMS]):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        instruction, _, remainder = stripped.partition(" ")
        instruction = instruction.upper()
        if instruction not in {
            "FROM",
            "EXPOSE",
            "USER",
            "ENTRYPOINT",
            "CMD",
            "ENV",
            "ARG",
            "HEALTHCHECK",
        }:
            continue
        attributes: dict[str, Any] = {"instruction": instruction}
        if instruction == "EXPOSE":
            attributes["ports"] = remainder.split()[:64]
        elif instruction == "FROM":
            attributes["baseImageDigest"] = sha256_digest(remainder.encode())
        elif instruction == "USER":
            attributes["nonRootDeclared"] = remainder not in {"", "0", "root"}
        elif instruction in {"ENV", "ARG"}:
            attributes["names"] = [
                item.split("=", maxsplit=1)[0]
                for item in remainder.split()
                if item.split("=", maxsplit=1)[0]
            ]
            attributes["valuesCaptured"] = False
        else:
            attributes["valueDigest"] = sha256_digest(remainder.encode())
            attributes["valueCaptured"] = False
        provenance = _provenance(material, f"$/files/{relative}/instructions/{index}", attributes)
        config = discovery.surface.add_node(
            SurfaceNodeKind.CONFIGURATION,
            f"containerfile:{relative}:{index}:{instruction}",
            instruction,
            attributes=attributes,
            evidence_class=EvidenceClass.DECLARED,
            confidence=1.0,
            provenance=provenance,
        )
        discovery.surface.add_edge(
            file_node,
            config,
            "declares",
            evidence_class=EvidenceClass.DECLARED,
            confidence=1.0,
            provenance=provenance,
        )


def _discover_sbom(discovery: IntakeDiscovery, material: LoadedMaterial) -> None:
    document = _material_json(material)
    if not isinstance(document, dict):
        raise FormatError("SOVA-INTAKE-SBOM", "SBOM root must be an object")
    components = document.get("components", [])
    if not isinstance(components, list):
        components = []
    root = discovery._surface_roots.get(ProfileTargetKind.PACKAGE) or discovery._surface_roots.get(
        ProfileTargetKind.OCI
    )
    for index, component in enumerate(components[:_MAX_ITEMS]):
        if not isinstance(component, dict) or not isinstance(component.get("name"), str):
            continue
        projection = {
            "name": component["name"],
            "version": component.get("version"),
            "type": component.get("type"),
            "purl": component.get("purl"),
        }
        provenance = _provenance(material, f"$/components/{index}", projection)
        node = discovery.surface.add_node(
            SurfaceNodeKind.DEPENDENCY,
            f"sbom:{canonical_json_bytes(projection).decode()}",
            component["name"],
            attributes=projection,
            evidence_class=EvidenceClass.DECLARED,
            confidence=1.0,
            provenance=provenance,
        )
        if root is not None:
            discovery.surface.add_edge(
                root,
                node,
                "contains-component",
                evidence_class=EvidenceClass.DECLARED,
                confidence=1.0,
                provenance=provenance,
            )
    vulnerabilities = _list(document.get("vulnerabilities"))
    for index, vulnerability in enumerate(vulnerabilities[:_MAX_ITEMS]):
        if not isinstance(vulnerability, dict):
            continue
        identifier = str(vulnerability.get("id", f"reported-{index}"))
        ratings = _list(vulnerability.get("ratings"))
        severities = sorted(
            str(rating.get("severity"))
            for rating in ratings
            if isinstance(rating, dict) and rating.get("severity") is not None
        )
        projection = {
            "identifierDigest": sha256_digest(identifier.encode()),
            "severities": severities,
            "affectedCount": len(_list(vulnerability.get("affects"))),
            "descriptionCaptured": False,
            "scannerAssertionOnly": True,
        }
        provenance = _provenance(
            material,
            f"$/vulnerabilities/{index}",
            projection,
        )
        node = discovery.surface.add_node(
            SurfaceNodeKind.CONFIGURATION,
            f"sbom-vulnerability:{projection['identifierDigest']}",
            "reported vulnerability assertion",
            attributes=projection,
            evidence_class=EvidenceClass.DECLARED,
            confidence=0.5,
            provenance=provenance,
        )
        if root is not None:
            discovery.surface.add_edge(
                root,
                node,
                "reports-vulnerability",
                evidence_class=EvidenceClass.DECLARED,
                confidence=0.5,
                provenance=provenance,
            )
    discovery.cover("package", "target-kind", CoverageState.DISCOVERED, "sbom-inspected")
    discovery.cover("oci", "target-kind", CoverageState.DISCOVERED, "sbom-inspected")


def _discover_lockfile(discovery: IntakeDiscovery, material: LoadedMaterial) -> None:
    file_provenance = _provenance(material, "$", {"size": len(material.payload or b"")})
    file_node = discovery.surface.add_node(
        SurfaceNodeKind.FILE,
        f"lockfile:{material.descriptor.id}",
        material.descriptor.logical_locator,
        attributes={"digest": material.start_digest},
        evidence_class=EvidenceClass.DECLARED,
        confidence=1.0,
        provenance=file_provenance,
    )
    _discover_dependency_lines(
        discovery,
        material,
        material.descriptor.logical_locator,
        material.payload or b"",
        file_node,
    )
    discovery.cover("package", "target-kind", CoverageState.DISCOVERED, "lockfile-inspected")


def _discover_oci_manifest(discovery: IntakeDiscovery, material: LoadedMaterial) -> None:
    document = _material_json(material)
    if not isinstance(document, dict):
        raise FormatError("SOVA-INTAKE-OCI", "OCI manifest root must be an object")
    root = discovery._surface_roots.get(ProfileTargetKind.OCI)
    annotations = _mapping(document.get("annotations"))
    subject = _mapping(document.get("subject"))
    provenance_projection = {
        "annotationNames": sorted(str(key) for key in annotations),
        "annotationValuesCaptured": False,
        "subjectDigest": subject.get("digest"),
        "subjectMediaType": subject.get("mediaType"),
    }
    manifest_provenance = _provenance(
        material,
        "$/provenance",
        provenance_projection,
    )
    provenance_node = discovery.surface.add_node(
        SurfaceNodeKind.CONFIGURATION,
        f"oci-provenance:{material.start_digest}",
        "OCI image provenance declaration",
        attributes=provenance_projection,
        evidence_class=EvidenceClass.DECLARED,
        confidence=1.0,
        provenance=manifest_provenance,
    )
    if root is not None:
        discovery.surface.add_edge(
            root,
            provenance_node,
            "declares-provenance",
            evidence_class=EvidenceClass.DECLARED,
            confidence=1.0,
            provenance=manifest_provenance,
        )
    descriptors = []
    config = document.get("config")
    if isinstance(config, dict):
        descriptors.append(("config", config))
    layers = document.get("layers")
    if isinstance(layers, list):
        descriptors.extend(("layer", item) for item in layers if isinstance(item, dict))
    for index, (role, descriptor) in enumerate(descriptors[:_MAX_ITEMS]):
        projection = {
            "role": role,
            "digest": descriptor.get("digest"),
            "mediaType": descriptor.get("mediaType"),
            "size": descriptor.get("size"),
        }
        provenance = _provenance(material, f"$/{role}/{index}", projection)
        node = discovery.surface.add_node(
            SurfaceNodeKind.FILE,
            f"oci:{role}:{descriptor.get('digest')}:{index}",
            role,
            attributes=projection,
            evidence_class=EvidenceClass.DECLARED,
            confidence=1.0,
            provenance=provenance,
        )
        if root is not None:
            discovery.surface.add_edge(
                root,
                node,
                "references",
                evidence_class=EvidenceClass.DECLARED,
                confidence=1.0,
                provenance=provenance,
            )
    discovery.cover("oci", "target-kind", CoverageState.DISCOVERED, "oci-manifest-inspected")


def _discover_oci_config(discovery: IntakeDiscovery, material: LoadedMaterial) -> None:
    document = _material_json(material)
    if not isinstance(document, dict):
        raise FormatError("SOVA-INTAKE-OCI", "OCI config root must be an object")
    config = _mapping(document.get("config")) or document
    root = discovery._surface_roots.get(ProfileTargetKind.OCI)
    environment_names = []
    env = config.get("Env")
    if isinstance(env, list):
        environment_names = sorted(
            item.split("=", maxsplit=1)[0]
            for item in env
            if isinstance(item, str) and item.split("=", maxsplit=1)[0]
        )
    projection = {
        "user": config.get("User"),
        "nonRootDeclared": config.get("User") not in {None, "", "0", "root"},
        "environmentNames": environment_names,
        "environmentValuesCaptured": False,
        "entrypointCount": len(config.get("Entrypoint", []))
        if isinstance(config.get("Entrypoint"), list)
        else 0,
        "commandCount": len(config.get("Cmd", [])) if isinstance(config.get("Cmd"), list) else 0,
        "exposedPorts": sorted(_mapping(config.get("ExposedPorts"))),
        "workingDirectoryPresent": bool(config.get("WorkingDir")),
        "workingDirectoryCaptured": False,
    }
    provenance = _provenance(material, "$/config", projection)
    node = discovery.surface.add_node(
        SurfaceNodeKind.CONFIGURATION,
        f"oci-config:{material.start_digest}",
        "OCI image configuration",
        attributes=projection,
        evidence_class=EvidenceClass.DECLARED,
        confidence=1.0,
        provenance=provenance,
    )
    if root is not None:
        discovery.surface.add_edge(
            root,
            node,
            "configured-by",
            evidence_class=EvidenceClass.DECLARED,
            confidence=1.0,
            provenance=provenance,
        )
    discovery.cover("oci", "target-kind", CoverageState.DISCOVERED, "oci-config-inspected")


def _discover_oci_inventory(discovery: IntakeDiscovery, material: LoadedMaterial) -> None:
    document = _material_json(material)
    if not isinstance(document, dict):
        raise FormatError("SOVA-INTAKE-OCI", "OCI inventory root must be an object")
    projection = {
        "capabilities": sorted(str(item) for item in _list(document.get("capabilities"))),
        "mountCount": len(_list(document.get("mounts"))),
        "ports": sorted(str(item) for item in _list(document.get("ports"))),
        "networkMode": document.get("networkMode"),
        "privileged": bool(document.get("privileged", False)),
    }
    provenance = _provenance(material, "$", projection)
    config = discovery.surface.add_node(
        SurfaceNodeKind.CONFIGURATION,
        f"oci-runtime:{material.start_digest}",
        "OCI runtime requirements",
        attributes=projection,
        evidence_class=_evidence_class(material),
        confidence=1.0,
        provenance=provenance,
    )
    root = discovery._surface_roots.get(ProfileTargetKind.OCI)
    if root is not None:
        discovery.surface.add_edge(
            root,
            config,
            "requires-runtime",
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=provenance,
        )
    discovery.cover("oci", "target-kind", CoverageState.DISCOVERED, "oci-runtime-inspected")


def _discover_network_inventory(  # noqa: PLR0912 - network relationship types stay explicit
    discovery: IntakeDiscovery, material: LoadedMaterial
) -> None:
    document = _material_json(material)
    if not isinstance(document, dict) or not isinstance(document.get("hosts"), list):
        raise FormatError("SOVA-INTAKE-NETWORK", "network inventory requires a hosts array")
    host_nodes: dict[str, str] = {}
    for host_index, host in enumerate(document["hosts"][:_MAX_ITEMS]):
        if not isinstance(host, dict):
            continue
        address = str(host.get("address", host.get("host", "unknown")))
        host_key = sha256_digest(address.casefold().encode())
        projection: dict[str, Any] = {
            "addressDigest": host_key,
            "loopback": address in {"localhost", "127.0.0.1", "::1"},
            "serviceCount": len(_list(host.get("services"))),
        }
        provenance = _provenance(material, f"$/hosts/{host_index}", projection)
        host_node = discovery.surface.add_node(
            SurfaceNodeKind.ENDPOINT,
            f"network-host:{host_key}",
            f"host-{host_key.removeprefix('sha256:')[:12]}",
            attributes=projection,
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=provenance,
        )
        host_nodes[address.casefold()] = host_node
        for service_index, service in enumerate(_list(host.get("services"))[:_MAX_ITEMS]):
            if not isinstance(service, dict):
                continue
            service_projection = {
                "port": service.get("port"),
                "protocol": service.get("protocol"),
                "service": service.get("service"),
                "version": service.get("version"),
                "tls": bool(service.get("tls", False)),
            }
            service_provenance = _provenance(
                material,
                f"$/hosts/{host_index}/services/{service_index}",
                service_projection,
            )
            service_node = discovery.surface.add_node(
                SurfaceNodeKind.PROTOCOL,
                f"network-service:{host_key}:{canonical_json_bytes(service_projection).decode()}",
                str(service.get("service", service.get("protocol", "service"))),
                attributes=service_projection,
                evidence_class=_evidence_class(material),
                confidence=1.0,
                provenance=service_provenance,
            )
            discovery.surface.add_edge(
                host_node,
                service_node,
                "exposes",
                evidence_class=_evidence_class(material),
                confidence=1.0,
                provenance=service_provenance,
            )
    for index, relationship in enumerate(_list(document.get("dnsRelationships"))[:_MAX_ITEMS]):
        if not isinstance(relationship, dict):
            continue
        source = str(relationship.get("source", "unknown"))
        target = str(relationship.get("target", "unknown"))
        projection = {
            "sourceDigest": sha256_digest(source.casefold().encode()),
            "targetDigest": sha256_digest(target.casefold().encode()),
            "recordType": relationship.get("recordType"),
            "valuesCaptured": False,
        }
        provenance = _provenance(
            material,
            f"$/dnsRelationships/{index}",
            projection,
        )
        source_node = host_nodes.get(source.casefold()) or discovery.surface.add_node(
            SurfaceNodeKind.ENDPOINT,
            f"network-host:{projection['sourceDigest']}",
            f"host-{projection['sourceDigest'].removeprefix('sha256:')[:12]}",
            attributes={"addressDigest": projection["sourceDigest"], "nameCaptured": False},
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=provenance,
        )
        target_node = host_nodes.get(target.casefold()) or discovery.surface.add_node(
            SurfaceNodeKind.ENDPOINT,
            f"network-host:{projection['targetDigest']}",
            f"host-{projection['targetDigest'].removeprefix('sha256:')[:12]}",
            attributes={"addressDigest": projection["targetDigest"], "nameCaptured": False},
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=provenance,
        )
        discovery.surface.add_edge(
            source_node,
            target_node,
            "dns-resolves-to",
            attributes={"recordType": relationship.get("recordType")},
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=provenance,
        )
    network_root = discovery._surface_roots.get(ProfileTargetKind.NETWORK)
    for index, segment in enumerate(_list(document.get("segments"))[:_MAX_ITEMS]):
        if not isinstance(segment, dict):
            continue
        segment_id = str(segment.get("id", f"segment-{index}"))
        members = [str(item) for item in _list(segment.get("members"))]
        projection = {
            "segmentDigest": sha256_digest(segment_id.encode()),
            "cidrDigests": sorted(
                sha256_digest(str(item).encode()) for item in _list(segment.get("cidrs"))
            ),
            "memberCount": len(members),
            "controlCount": len(_list(segment.get("controls"))),
            "controlValuesCaptured": False,
        }
        provenance = _provenance(material, f"$/segments/{index}", projection)
        segment_node = discovery.surface.add_node(
            SurfaceNodeKind.TRUST_BOUNDARY,
            f"network-segment:{projection['segmentDigest']}",
            f"network segment {index}",
            attributes=projection,
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=provenance,
        )
        if network_root is not None:
            discovery.surface.add_edge(
                network_root,
                segment_node,
                "contains-segment",
                evidence_class=_evidence_class(material),
                confidence=1.0,
                provenance=provenance,
            )
        for member in members:
            member_node = host_nodes.get(member.casefold())
            if member_node is not None:
                discovery.surface.add_edge(
                    member_node,
                    segment_node,
                    "member-of",
                    evidence_class=_evidence_class(material),
                    confidence=1.0,
                    provenance=provenance,
                )
    segmentation_evidence = _list(document.get("segmentationEvidence"))
    if segmentation_evidence:
        projection = {
            "evidenceCount": len(segmentation_evidence),
            "evidenceDigests": [
                sha256_digest(canonical_json_bytes(item))
                for item in segmentation_evidence[:256]
                if isinstance(item, (dict, list, str, bool, int)) or item is None
            ],
            "rawEvidenceCaptured": False,
        }
        provenance = _provenance(material, "$/segmentationEvidence", projection)
        discovery.surface.add_node(
            SurfaceNodeKind.CONFIGURATION,
            f"network-segmentation-evidence:{material.start_digest}",
            "network segmentation evidence",
            attributes=projection,
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=provenance,
        )
    discovery.cover(
        "network",
        "target-kind",
        CoverageState.EXERCISED
        if material.descriptor.source_class == SourceClass.ACTIVE
        else CoverageState.DISCOVERED,
        "network-inventory-inspected",
    )


def _discover_tls_report(discovery: IntakeDiscovery, material: LoadedMaterial) -> None:
    document = _material_json(material)
    if not isinstance(document, dict):
        raise FormatError("SOVA-INTAKE-TLS", "TLS report root must be an object")
    projection = {
        "protocols": sorted(str(item) for item in _list(document.get("protocols"))),
        "cipherCount": len(_list(document.get("ciphers"))),
        "certificateCount": len(_list(document.get("certificates"))),
        "certificateMaterialCaptured": False,
        "issues": sorted(str(item) for item in _list(document.get("issues")))[:256],
    }
    provenance = _provenance(material, "$", projection)
    discovery.surface.add_node(
        SurfaceNodeKind.PROTOCOL,
        f"tls:{material.start_digest}",
        "TLS configuration",
        attributes=projection,
        evidence_class=_evidence_class(material),
        confidence=1.0,
        provenance=provenance,
    )
    discovery.cover("network", "target-kind", CoverageState.DISCOVERED, "tls-report-inspected")


def _discover_process_inventory(discovery: IntakeDiscovery, material: LoadedMaterial) -> None:
    document = _material_json(material)
    if not isinstance(document, dict) or not isinstance(document.get("processes"), list):
        raise FormatError("SOVA-INTAKE-PROCESS", "process inventory requires a processes array")
    for index, process in enumerate(document["processes"][:_MAX_ITEMS]):
        if not isinstance(process, dict):
            continue
        executable = PurePosixPath(
            str(process.get("executable", process.get("name", "process"))).replace("\\", "/")
        ).name
        projection = {
            "executable": executable,
            "generation": process.get("generation"),
            "windowCount": len(_list(process.get("windows"))),
            "sideEffectClasses": sorted(str(item) for item in _list(process.get("sideEffects"))),
            "pidCaptured": False,
            "argumentsCaptured": False,
        }
        provenance = _provenance(material, f"$/processes/{index}", projection)
        process_node = discovery.surface.add_node(
            SurfaceNodeKind.PROCESS,
            f"process:{executable}:{process.get('generation')}:{index}",
            executable,
            attributes=projection,
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=provenance,
        )
        if bool(process.get("elevated", False)):
            privilege = discovery.surface.add_node(
                SurfaceNodeKind.PRIVILEGE,
                f"process-privilege:{executable}:{index}",
                "elevated process boundary",
                attributes={"elevated": True, "authorityCaptured": False},
                evidence_class=_evidence_class(material),
                confidence=1.0,
                provenance=provenance,
            )
            discovery.surface.add_edge(
                process_node,
                privilege,
                "runs-with",
                evidence_class=_evidence_class(material),
                confidence=1.0,
                provenance=provenance,
            )
        for effect_index, effect in enumerate(_list(process.get("sideEffects"))[:_MAX_ITEMS]):
            effect_value = str(effect)
            effect_digest = sha256_digest(effect_value.encode())
            effect_provenance = _provenance(
                material,
                f"$/processes/{index}/sideEffects/{effect_index}",
                {"effectDigest": effect_digest},
            )
            effect_node = discovery.surface.add_node(
                SurfaceNodeKind.DATA_FLOW,
                f"process-effect:{executable}:{effect_digest}",
                "declared process side effect",
                attributes={"effectDigest": effect_digest, "detailsCaptured": False},
                evidence_class=_evidence_class(material),
                confidence=1.0,
                provenance=effect_provenance,
            )
            discovery.surface.add_edge(
                process_node,
                effect_node,
                "may-cause",
                evidence_class=_evidence_class(material),
                confidence=1.0,
                provenance=effect_provenance,
            )
        for target_index, target in enumerate(
            _list(process.get("crossProcessTargets"))[:_MAX_ITEMS]
        ):
            target_digest = sha256_digest(str(target).encode())
            target_provenance = _provenance(
                material,
                f"$/processes/{index}/crossProcessTargets/{target_index}",
                {"targetDigest": target_digest},
            )
            boundary = discovery.surface.add_node(
                SurfaceNodeKind.TRUST_BOUNDARY,
                f"cross-process:{target_digest}",
                "cross-process boundary",
                attributes={"targetDigest": target_digest, "targetCaptured": False},
                evidence_class=_evidence_class(material),
                confidence=1.0,
                provenance=target_provenance,
            )
            discovery.surface.add_edge(
                process_node,
                boundary,
                "crosses-process-boundary",
                evidence_class=_evidence_class(material),
                confidence=1.0,
                provenance=target_provenance,
            )
        workflow_process = discovery.workflow.add_node(
            WorkflowNodeKind.PROCESS_STATE,
            f"process:{executable}:{process.get('generation')}:{index}",
            executable,
            attributes={"generation": process.get("generation")},
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=provenance,
        )
        for window_index, window in enumerate(_list(process.get("windows"))):
            if not isinstance(window, dict):
                continue
            window_projection = {
                "role": window.get("role"),
                "automationId": window.get("automationId"),
                "titleCaptured": False,
            }
            window_provenance = _provenance(
                material, f"$/processes/{index}/windows/{window_index}", window_projection
            )
            window_node = discovery.surface.add_node(
                SurfaceNodeKind.WINDOW,
                f"window:{executable}:{window.get('automationId')}:{window_index}",
                str(window.get("role", "window")),
                attributes=window_projection,
                evidence_class=_evidence_class(material),
                confidence=1.0,
                provenance=window_provenance,
            )
            discovery.surface.add_edge(
                process_node,
                window_node,
                "owns-window",
                evidence_class=_evidence_class(material),
                confidence=1.0,
                provenance=window_provenance,
            )
            workflow_window = discovery.workflow.add_node(
                WorkflowNodeKind.PROCESS_STATE,
                f"window:{executable}:{window.get('automationId')}:{window_index}",
                str(window.get("role", "window")),
                attributes=window_projection,
                evidence_class=_evidence_class(material),
                confidence=1.0,
                provenance=window_provenance,
            )
            discovery.workflow.add_edge(
                workflow_process,
                workflow_window,
                "shows",
                evidence_class=_evidence_class(material),
                confidence=1.0,
                provenance=window_provenance,
            )
    discovery.cover(
        "desktop",
        "target-kind",
        CoverageState.EXERCISED
        if material.descriptor.source_class == SourceClass.ACTIVE
        else CoverageState.DISCOVERED,
        "process-inventory-inspected",
    )


def _discover_accessibility_tree(discovery: IntakeDiscovery, material: LoadedMaterial) -> None:
    document = _material_json(material)
    if not isinstance(document, dict):
        raise FormatError("SOVA-INTAKE-ACCESSIBILITY", "accessibility tree root must be an object")
    nodes = document.get("nodes")
    if not isinstance(nodes, list):
        nodes = [document]
    for index, node in enumerate(nodes[:_MAX_ITEMS]):
        if not isinstance(node, dict):
            continue
        projection = {
            "role": node.get("role"),
            "automationId": node.get("automationId"),
            "actions": sorted(str(item) for item in _list(node.get("actions"))),
            "enabled": node.get("enabled"),
            "textCaptured": False,
        }
        provenance = _provenance(material, f"$/nodes/{index}", projection)
        discovery.surface.add_node(
            SurfaceNodeKind.CONTROL,
            f"control:{node.get('automationId')}:{node.get('role')}:{index}",
            str(node.get("role", "control")),
            attributes=projection,
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=provenance,
        )
    discovery.cover(
        "desktop", "target-kind", CoverageState.DISCOVERED, "accessibility-tree-inspected"
    )


def _discover_agent_manifest(  # noqa: PLR0915 - agent trust surfaces stay explicit
    discovery: IntakeDiscovery, material: LoadedMaterial
) -> None:
    document = _material_json(material)
    if not isinstance(document, dict):
        raise FormatError("SOVA-INTAKE-AGENT", "agent manifest root must be an object")
    projection = {
        "name": document.get("name", document.get("id", "agent")),
        "provider": document.get("provider"),
        "model": document.get("model"),
        "toolCount": len(_list(document.get("tools"))),
        "skillCount": len(_list(document.get("skills"))),
        "memoryDeclared": document.get("memory") is not None,
        "handoffCount": len(_list(document.get("handoffs"))),
    }
    provenance = _provenance(material, "$", projection)
    agent = discovery.surface.add_node(
        SurfaceNodeKind.AGENT,
        f"agent:{projection['name']}",
        str(projection["name"]),
        attributes={"provider": projection["provider"], "credentialCaptured": False},
        evidence_class=_evidence_class(material),
        confidence=1.0,
        provenance=provenance,
    )
    agent_state = discovery.workflow.add_node(
        WorkflowNodeKind.AGENT_STATE,
        f"agent:{projection['name']}:initial",
        "agent initial state",
        attributes={"agent": projection["name"]},
        evidence_class=_evidence_class(material),
        confidence=1.0,
        provenance=provenance,
    )
    if projection["model"] is not None:
        model = discovery.surface.add_node(
            SurfaceNodeKind.MODEL,
            f"model:{projection['provider']}:{projection['model']}",
            str(projection["model"]),
            attributes={"provider": projection["provider"]},
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=provenance,
        )
        discovery.surface.add_edge(
            agent,
            model,
            "uses-model",
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=provenance,
        )
    for index, tool in enumerate(_list(document.get("tools"))[:_MAX_ITEMS]):
        if not isinstance(tool, dict):
            continue
        name = str(tool.get("name", tool.get("id", f"tool-{index}")))
        tool_projection = {
            "name": name,
            "schemaDigest": sha256_digest(canonical_json_bytes(tool.get("inputSchema", {}))),
            "descriptionCaptured": False,
        }
        tool_provenance = _provenance(material, f"$/tools/{index}", tool_projection)
        tool_node = discovery.surface.add_node(
            SurfaceNodeKind.TOOL,
            f"agent-tool:{name}:{tool_projection['schemaDigest']}",
            name,
            attributes=tool_projection,
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=tool_provenance,
        )
        discovery.surface.add_edge(
            agent,
            tool_node,
            "may-invoke",
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=tool_provenance,
        )
    if document.get("memory") is not None:
        memory = discovery.surface.add_node(
            SurfaceNodeKind.MEMORY,
            f"agent-memory:{projection['name']}",
            "agent memory",
            attributes={"contentCaptured": False, "declared": True},
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=provenance,
        )
        discovery.surface.add_edge(
            agent,
            memory,
            "uses-memory",
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=provenance,
        )
    identity_value = document.get("identity")
    if isinstance(identity_value, dict):
        identity_projection = {
            "fieldNames": sorted(str(key) for key in identity_value),
            "identityDigest": sha256_digest(canonical_json_bytes(identity_value)),
            "valuesCaptured": False,
        }
        identity_provenance = _provenance(
            material,
            "$/identity",
            identity_projection,
        )
        identity = discovery.surface.add_node(
            SurfaceNodeKind.IDENTITY,
            f"agent-identity:{identity_projection['identityDigest']}",
            "agent identity declaration",
            attributes=identity_projection,
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=identity_provenance,
        )
        discovery.surface.add_edge(
            agent,
            identity,
            "acts-as",
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=identity_provenance,
        )
    for collection_name in ("prompts", "policies"):
        for index, item in enumerate(_list(document.get(collection_name))[:_MAX_ITEMS]):
            item_digest = sha256_digest(canonical_json_bytes(item))
            item_projection = {
                "kind": collection_name,
                "contentDigest": item_digest,
                "contentCaptured": False,
            }
            item_provenance = _provenance(
                material,
                f"$/{collection_name}/{index}",
                item_projection,
            )
            config = discovery.surface.add_node(
                SurfaceNodeKind.CONFIGURATION,
                f"agent-{collection_name}:{item_digest}",
                f"agent {collection_name[:-1]}",
                attributes=item_projection,
                evidence_class=_evidence_class(material),
                confidence=1.0,
                provenance=item_provenance,
            )
            discovery.surface.add_edge(
                agent,
                config,
                "governed-by",
                evidence_class=_evidence_class(material),
                confidence=1.0,
                provenance=item_provenance,
            )
    for index, skill in enumerate(_list(document.get("skills"))[:_MAX_ITEMS]):
        skill_name = (
            str(skill.get("id", skill.get("name", f"skill-{index}")))
            if isinstance(skill, dict)
            else str(skill)
        )
        skill_projection = {
            "nameDigest": sha256_digest(skill_name.encode()),
            "descriptionCaptured": False,
        }
        skill_provenance = _provenance(
            material,
            f"$/skills/{index}",
            skill_projection,
        )
        skill_node = discovery.surface.add_node(
            SurfaceNodeKind.SKILL,
            f"agent-skill:{skill_projection['nameDigest']}",
            f"agent skill {index}",
            attributes=skill_projection,
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=skill_provenance,
        )
        discovery.surface.add_edge(
            agent,
            skill_node,
            "has-skill",
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=skill_provenance,
        )
    for index, protocol in enumerate(_list(document.get("protocols"))[:_MAX_ITEMS]):
        protocol_digest = sha256_digest(str(protocol).encode())
        protocol_provenance = _provenance(
            material,
            f"$/protocols/{index}",
            {"protocolDigest": protocol_digest},
        )
        protocol_node = discovery.surface.add_node(
            SurfaceNodeKind.PROTOCOL,
            f"agent-protocol:{protocol_digest}",
            f"agent protocol {index}",
            attributes={"protocolDigest": protocol_digest, "detailsCaptured": False},
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=protocol_provenance,
        )
        discovery.surface.add_edge(
            agent,
            protocol_node,
            "uses-protocol",
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=protocol_provenance,
        )
    for index, handoff in enumerate(_list(document.get("handoffs"))[:_MAX_ITEMS]):
        target = (
            str(handoff.get("target", handoff.get("agent", f"agent-{index}")))
            if isinstance(handoff, dict)
            else str(handoff)
        )
        target_digest = sha256_digest(target.encode())
        handoff_projection = {
            "targetDigest": target_digest,
            "conditionDigest": sha256_digest(canonical_json_bytes(handoff)),
            "contentCaptured": False,
        }
        handoff_provenance = _provenance(
            material,
            f"$/handoffs/{index}",
            handoff_projection,
        )
        external_state = discovery.workflow.add_node(
            WorkflowNodeKind.EXTERNAL_STATE,
            f"agent-handoff:{target_digest}",
            f"external agent state {index}",
            attributes=handoff_projection,
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=handoff_provenance,
        )
        discovery.workflow.add_edge(
            agent_state,
            external_state,
            "may-handoff",
            preconditions=("cross-agent-authority-check",),
            effects=("inter-agent.message",),
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=handoff_provenance,
        )
        boundary = discovery.surface.add_node(
            SurfaceNodeKind.TRUST_BOUNDARY,
            f"agent-handoff-boundary:{target_digest}",
            "cross-agent trust boundary",
            attributes=handoff_projection,
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=handoff_provenance,
        )
        discovery.surface.add_edge(
            agent,
            boundary,
            "delegates-across",
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=handoff_provenance,
        )
    for index, action in enumerate(_list(document.get("consequentialActions"))[:_MAX_ITEMS]):
        action_digest = sha256_digest(canonical_json_bytes(action))
        action_provenance = _provenance(
            material,
            f"$/consequentialActions/{index}",
            {"actionDigest": action_digest},
        )
        action_node = discovery.surface.add_node(
            SurfaceNodeKind.DATA_FLOW,
            f"agent-action:{action_digest}",
            "declared consequential action",
            attributes={"actionDigest": action_digest, "detailsCaptured": False},
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=action_provenance,
        )
        discovery.surface.add_edge(
            agent,
            action_node,
            "may-cause",
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=action_provenance,
        )
    discovery.cover("agent", "target-kind", CoverageState.DISCOVERED, "agent-manifest-inspected")
    discovery.cover(
        "ai-model", "target-kind", CoverageState.DISCOVERED, "model-declaration-inspected"
    )


def _discover_mcp_manifest(discovery: IntakeDiscovery, material: LoadedMaterial) -> None:
    document = _material_json(material)
    if not isinstance(document, dict):
        raise FormatError("SOVA-INTAKE-MCP", "MCP manifest root must be an object")
    servers = document.get("mcpServers")
    if not isinstance(servers, dict):
        servers = document.get("servers")
    if not isinstance(servers, dict):
        servers = {str(document.get("name", "mcp-server")): document}
    agent_root = discovery._surface_roots.get(
        ProfileTargetKind.AGENT
    ) or discovery._surface_roots.get(ProfileTargetKind.MCP)
    for index, (name, server) in enumerate(sorted(servers.items())):
        if not isinstance(server, dict):
            continue
        url = server.get("url")
        command = server.get("command")
        projection = {
            "name": str(name),
            "transport": "http" if isinstance(url, str) else "stdio" if command else "unknown",
            "endpoint": _safe_url_projection(url) if isinstance(url, str) else None,
            "commandBasename": PurePosixPath(str(command).replace("\\", "/")).name
            if command
            else None,
            "argumentCount": len(_list(server.get("args"))),
            "environmentNames": sorted(str(key) for key in _mapping(server.get("env"))),
            "environmentValuesCaptured": False,
        }
        provenance = _provenance(material, f"$/servers/{index}", projection)
        server_node = discovery.surface.add_node(
            SurfaceNodeKind.EXTERNAL_RESOURCE,
            f"mcp-server:{name}:{projection['transport']}",
            str(name),
            attributes=projection,
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=provenance,
        )
        if agent_root is not None:
            discovery.surface.add_edge(
                agent_root,
                server_node,
                "connects-to-mcp",
                evidence_class=_evidence_class(material),
                confidence=1.0,
                provenance=provenance,
            )
    for collection_name, node_kind in (
        ("tools", SurfaceNodeKind.TOOL),
        ("resources", SurfaceNodeKind.DATA_STORE),
        ("prompts", SurfaceNodeKind.CONFIGURATION),
    ):
        for index, item in enumerate(_list(document.get(collection_name))[:_MAX_ITEMS]):
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", item.get("uri", f"{collection_name}-{index}")))
            projection = {
                "name": name,
                "schemaDigest": sha256_digest(canonical_json_bytes(item.get("inputSchema", {}))),
                "contentCaptured": False,
            }
            provenance = _provenance(material, f"$/{collection_name}/{index}", projection)
            discovery.surface.add_node(
                node_kind,
                f"mcp-{collection_name}:{name}",
                name,
                attributes=projection,
                evidence_class=_evidence_class(material),
                confidence=1.0,
                provenance=provenance,
            )
    discovery.cover("mcp", "target-kind", CoverageState.DISCOVERED, "mcp-manifest-inspected")


def _discover_a2a_card(discovery: IntakeDiscovery, material: LoadedMaterial) -> None:
    document = _material_json(material)
    if not isinstance(document, dict):
        raise FormatError("SOVA-INTAKE-A2A", "A2A card root must be an object")
    name = str(document.get("name", "a2a-agent"))
    projection = {
        "name": name,
        "endpoint": _safe_url_projection(document.get("url"))
        if isinstance(document.get("url"), str)
        else None,
        "skillCount": len(_list(document.get("skills"))),
        "authenticationSchemes": sorted(
            str(item) for item in _list(document.get("authentication", {}).get("schemes"))
        )
        if isinstance(document.get("authentication"), dict)
        else [],
    }
    provenance = _provenance(material, "$", projection)
    agent = discovery.surface.add_node(
        SurfaceNodeKind.AGENT,
        f"a2a-agent:{name}",
        name,
        attributes=projection,
        evidence_class=_evidence_class(material),
        confidence=1.0,
        provenance=provenance,
    )
    for index, skill in enumerate(_list(document.get("skills"))[:_MAX_ITEMS]):
        if not isinstance(skill, dict):
            continue
        skill_name = str(skill.get("id", skill.get("name", f"skill-{index}")))
        skill_projection = {"name": skill_name, "descriptionCaptured": False}
        skill_provenance = _provenance(material, f"$/skills/{index}", skill_projection)
        skill_node = discovery.surface.add_node(
            SurfaceNodeKind.SKILL,
            f"a2a-skill:{name}:{skill_name}",
            skill_name,
            attributes=skill_projection,
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=skill_provenance,
        )
        discovery.surface.add_edge(
            agent,
            skill_node,
            "offers-skill",
            evidence_class=_evidence_class(material),
            confidence=1.0,
            provenance=skill_provenance,
        )
    discovery.cover("a2a", "target-kind", CoverageState.DISCOVERED, "a2a-card-inspected")


def _discover_runtime_observations(discovery: IntakeDiscovery, material: LoadedMaterial) -> None:
    document = _material_json(material)
    if not isinstance(document, dict):
        raise FormatError("SOVA-INTAKE-OBSERVATIONS", "observation root must be an object")
    aliases: dict[str, str] = {}
    for graph_name, graph in (
        ("workflow", discovery.workflow),
        ("attackSurface", discovery.surface),
    ):
        raw_graph = document.get(graph_name)
        if raw_graph is None:
            continue
        if not isinstance(raw_graph, dict):
            raise FormatError("SOVA-INTAKE-OBSERVATIONS", f"{graph_name} must be an object")
        nodes = raw_graph.get("nodes")
        edges = raw_graph.get("edges")
        if not isinstance(nodes, list) or not isinstance(edges, list):
            raise FormatError(
                "SOVA-INTAKE-OBSERVATIONS", f"{graph_name} requires nodes and edges arrays"
            )
        for index, node in enumerate(nodes[:_MAX_ITEMS]):
            if not isinstance(node, dict):
                continue
            raw_key = str(node.get("key", ""))
            requested_kind = str(node.get("kind", "unknown"))
            if not raw_key:
                raise FormatError("SOVA-INTAKE-OBSERVATIONS", "observation node key is required")
            key_digest = sha256_digest(raw_key.encode())
            allowed_kinds = (
                {item.value for item in WorkflowNodeKind}
                if graph_name == "workflow"
                else {item.value for item in SurfaceNodeKind}
            )
            kind = (
                requested_kind
                if requested_kind in allowed_kinds
                else (
                    WorkflowNodeKind.UNKNOWN.value
                    if graph_name == "workflow"
                    else SurfaceNodeKind.TRUST_BOUNDARY.value
                )
            )
            attributes = _mapping(node.get("attributes"))
            safe_attributes = _safe_observation_attributes(attributes)
            provenance = _provenance(
                material,
                f"$/{graph_name}/nodes/{index}",
                {"keyDigest": key_digest, "kind": kind, "attributes": safe_attributes},
            )
            aliases[f"{graph_name}:{raw_key}"] = graph.add_node(
                kind,
                f"runtime:{key_digest}",
                f"imported {graph_name} node {index}",
                attributes=safe_attributes,
                evidence_class=EvidenceClass.OBSERVED,
                confidence=float(node.get("confidence", 1.0)),
                provenance=provenance,
            )
        for index, edge in enumerate(edges[:_MAX_ITEMS]):
            if not isinstance(edge, dict):
                continue
            source_alias = f"{graph_name}:{edge.get('source')}"
            target_alias = f"{graph_name}:{edge.get('target')}"
            if source_alias not in aliases or target_alias not in aliases:
                raise FormatError("SOVA-INTAKE-OBSERVATIONS", "observation edge is dangling")
            requested = str(edge.get("evidenceClass", "observed"))
            edge_class = EvidenceClass.REFUTED if requested == "refuted" else EvidenceClass.OBSERVED
            requested_kind = str(edge.get("kind", "relates-to"))
            edge_kind = (
                requested_kind
                if _SAFE_RUNTIME_KIND.fullmatch(requested_kind)
                else "observed-relationship"
            )
            attributes = _mapping(edge.get("attributes"))
            safe_attributes = _safe_observation_attributes(attributes)
            provenance = _provenance(
                material,
                f"$/{graph_name}/edges/{index}",
                {"kind": edge_kind, "attributes": safe_attributes},
                evidence_class=edge_class,
            )
            graph.add_edge(
                aliases[source_alias],
                aliases[target_alias],
                edge_kind,
                key=str(index),
                preconditions=(),
                effects=(),
                attributes=safe_attributes,
                evidence_class=edge_class,
                confidence=float(edge.get("confidence", 1.0)),
                provenance=provenance,
            )
    for kind in discovery.profile.target_kinds:
        discovery.cover(
            kind.value,
            "target-kind",
            CoverageState.EXERCISED,
            "authorized-runtime-observations-imported",
            material.start_digest,
        )
    discovery.limitations.append(
        "Imported runtime observations are content-bound, but collector completeness is not "
        "independently attested."
    )


def _safe_observation_attributes(value: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, child in value.items():
        if _SECRET_NAME.search(str(key)):
            result[str(key)] = {"present": child is not None, "valueCaptured": False}
        elif isinstance(child, str):
            result[str(key)] = {
                "valueDigest": sha256_digest(child.encode()),
                "valueCaptured": False,
            }
        elif isinstance(child, (bool, int, float)) or child is None:
            result[str(key)] = child
        elif isinstance(child, list):
            result[str(key)] = {
                "itemCount": min(len(child), 256),
                "valuesCaptured": False,
            }
        elif isinstance(child, dict):
            result[str(key)] = _safe_observation_attributes(child)
    return result


def _surface_endpoint(
    discovery: IntakeDiscovery, material: LoadedMaterial, url: str, pointer: str
) -> str:
    projection = _safe_url_projection(url)
    provenance = _provenance(material, pointer, projection)
    kind = (
        SurfaceNodeKind.EXTERNAL_RESOURCE
        if projection.get("external")
        else SurfaceNodeKind.ENDPOINT
    )
    return discovery.surface.add_node(
        kind,
        f"url:{_safe_url_key(url)}",
        _url_name(url),
        attributes=projection,
        evidence_class=_evidence_class(material),
        confidence=0.95,
        provenance=provenance,
    )


def _workflow_root(
    discovery: IntakeDiscovery,
    material: LoadedMaterial,
    key: str,
    kind: WorkflowNodeKind,
) -> str:
    provenance = _provenance(material, "$", {"root": key})
    return discovery.workflow.add_node(
        kind,
        f"{material.descriptor.id}:{key}",
        key,
        attributes={"inputId": material.descriptor.id},
        evidence_class=_evidence_class(material),
        confidence=1.0,
        provenance=provenance,
    )


def _entrypoint_attributes(kind: EntryPointKind, locator: str) -> dict[str, Any]:
    if kind in {EntryPointKind.URL, EntryPointKind.API, EntryPointKind.MCP, EntryPointKind.A2A}:
        return {"kind": kind.value, **_safe_url_projection(locator)}
    if kind in {EntryPointKind.HOST, EntryPointKind.CIDR}:
        return {
            "kind": kind.value,
            "locatorDigest": sha256_digest(locator.casefold().encode()),
            "locatorCaptured": False,
        }
    return {"kind": kind.value, "locator": locator}


def _safe_url_projection(value: Any) -> dict[str, Any]:
    if not isinstance(value, str):
        return {"present": False}
    parsed = urlsplit(value)
    if parsed.hostname is None:
        return {
            "present": True,
            "relative": True,
            "path": parsed.path or "/",
            "queryNames": sorted(name for name, _value in parse_qsl(parsed.query)),
        }
    host = parsed.hostname.casefold()
    return {
        "present": True,
        "relative": False,
        "scheme": parsed.scheme.casefold(),
        "hostDigest": sha256_digest(host.encode()),
        "loopback": host in {"localhost", "127.0.0.1", "::1"},
        "external": host not in {"localhost", "127.0.0.1", "::1"},
        "port": parsed.port,
        "path": parsed.path or "/",
        "queryNames": sorted(name for name, _value in parse_qsl(parsed.query)),
        "queryValuesCaptured": False,
    }


def _safe_url_key(value: str) -> str:
    return sha256_digest(canonical_json_bytes(_safe_url_projection(value)))


def _url_name(value: str) -> str:
    projection = _safe_url_projection(value)
    return str(projection.get("path", "endpoint"))


def _header_names(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted(
        str(item.get("name"))
        for item in value
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    )


def _query_names(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted(
        str(item.get("name"))
        for item in value
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    )


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _postman_requests(value: Any) -> Iterator[dict[str, Any]]:
    if not isinstance(value, list):
        return
    for item in value:
        if not isinstance(item, dict):
            continue
        request = item.get("request")
        if isinstance(request, dict):
            yield request
        yield from _postman_requests(item.get("item"))


def _postman_url(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        raw = value.get("raw")
        if isinstance(raw, str):
            return raw
        protocol = str(value.get("protocol", "https"))
        host = value.get("host", [])
        path = value.get("path", [])
        host_value = ".".join(str(item) for item in host) if isinstance(host, list) else str(host)
        path_value = "/".join(str(item) for item in path) if isinstance(path, list) else str(path)
        return f"{protocol}://{host_value}/{path_value}"
    return "https://invalid.local/"


__all__ = ["IntakeDiscovery", "discover_material"]
