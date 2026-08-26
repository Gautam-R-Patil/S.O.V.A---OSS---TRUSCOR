# SPDX-License-Identifier: Apache-2.0
"""Versioned SOVA-native playbook library and strict community loader."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from typing import TYPE_CHECKING, Any, cast

from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads, validate_document
from sova.formats.errors import FormatError
from sova.intake import InputKind, ProfileTargetKind
from sova.methodology.contracts import (
    LIBRARY_SCHEMA_VERSION,
    PLAYBOOK_SCHEMA_VERSION,
    CleanupStep,
    EffectClass,
    EvidenceLimits,
    EvidenceRequirement,
    FrameworkMapping,
    MethodologyDomain,
    OracleKind,
    OracleProposal,
    Playbook,
    PlaybookProvenance,
    PlaybookVariant,
    Prerequisite,
    StopRule,
    TargetPredicate,
    Technique,
    ToolRequirement,
)

if TYPE_CHECKING:
    from pathlib import Path

_CATALOG_FILE = "playbook-seeds-0.1.0.json"
_DOMAIN_FOUNDATION = {
    MethodologyDomain.WEB: "sova.playbook.web.surface-inventory",
    MethodologyDomain.API: "sova.playbook.api.inventory",
    MethodologyDomain.NETWORK_HOST_CLOUD: "sova.playbook.network-host-cloud.service-inventory",
    MethodologyDomain.SOURCE_PACKAGE_BINARY: (
        "sova.playbook.source-package-binary.build-inventory"
    ),
    MethodologyDomain.AI_MODEL: "sova.playbook.ai-model.system-inventory",
    MethodologyDomain.AGENTIC: "sova.playbook.agentic.trust-inventory",
}
_TARGET_KINDS = {
    MethodologyDomain.WEB: (ProfileTargetKind.WEB,),
    MethodologyDomain.API: (ProfileTargetKind.API,),
    MethodologyDomain.NETWORK_HOST_CLOUD: (
        ProfileTargetKind.NETWORK,
        ProfileTargetKind.OCI,
        ProfileTargetKind.THIRD_PARTY,
    ),
    MethodologyDomain.SOURCE_PACKAGE_BINARY: (
        ProfileTargetKind.SOURCE,
        ProfileTargetKind.PACKAGE,
        ProfileTargetKind.OCI,
    ),
    MethodologyDomain.AI_MODEL: (ProfileTargetKind.AI_MODEL,),
    MethodologyDomain.AGENTIC: (
        ProfileTargetKind.AGENT,
        ProfileTargetKind.MCP,
        ProfileTargetKind.A2A,
    ),
}
_DISCOVERY_INPUTS = {
    MethodologyDomain.WEB: (
        InputKind.HTML,
        InputKind.WEB_INVENTORY,
        InputKind.HAR,
        InputKind.TLS_REPORT,
        InputKind.RUNTIME_OBSERVATIONS,
    ),
    MethodologyDomain.API: (
        InputKind.OPENAPI,
        InputKind.GRAPHQL_SCHEMA,
        InputKind.GRPC_DESCRIPTOR,
        InputKind.POSTMAN,
        InputKind.HAR,
        InputKind.RUNTIME_OBSERVATIONS,
    ),
    MethodologyDomain.NETWORK_HOST_CLOUD: (
        InputKind.NETWORK_INVENTORY,
        InputKind.TLS_REPORT,
        InputKind.OCI_INVENTORY,
        InputKind.RUNTIME_OBSERVATIONS,
    ),
    MethodologyDomain.SOURCE_PACKAGE_BINARY: (
        InputKind.SOURCE_TREE,
        InputKind.ARCHIVE,
        InputKind.SBOM,
        InputKind.LOCKFILE,
        InputKind.OCI_MANIFEST,
        InputKind.OCI_CONFIG,
    ),
    MethodologyDomain.AI_MODEL: (
        InputKind.AGENT_MANIFEST,
        InputKind.RUNTIME_OBSERVATIONS,
    ),
    MethodologyDomain.AGENTIC: (
        InputKind.AGENT_MANIFEST,
        InputKind.MCP_MANIFEST,
        InputKind.A2A_CARD,
        InputKind.RUNTIME_OBSERVATIONS,
    ),
}
_SURFACE_KINDS = {
    MethodologyDomain.WEB: ("endpoint", "input", "trust-boundary"),
    MethodologyDomain.API: ("endpoint", "input", "protocol"),
    MethodologyDomain.NETWORK_HOST_CLOUD: (
        "endpoint",
        "protocol",
        "privilege",
        "trust-boundary",
    ),
    MethodologyDomain.SOURCE_PACKAGE_BINARY: (
        "file",
        "dependency",
        "configuration",
    ),
    MethodologyDomain.AI_MODEL: ("model", "data-flow", "trust-boundary"),
    MethodologyDomain.AGENTIC: ("agent", "tool", "identity", "trust-boundary"),
}
_TOOLS = {
    MethodologyDomain.WEB: ("browser.observe", ("adapter.zap", "adapter.playwright")),
    MethodologyDomain.API: (
        "protocol.http",
        ("adapter.schemathesis", "adapter.zap", "adapter.postman"),
    ),
    MethodologyDomain.NETWORK_HOST_CLOUD: (
        "network.observe",
        ("adapter.protocol", "adapter.testssl", "adapter.cloud-posture"),
    ),
    MethodologyDomain.SOURCE_PACKAGE_BINARY: (
        "source.inspect",
        ("adapter.semgrep", "adapter.syft", "adapter.trivy", "adapter.fuzzer"),
    ),
    MethodologyDomain.AI_MODEL: (
        "model.query",
        ("adapter.pyrit", "adapter.garak", "adapter.promptfoo"),
    ),
    MethodologyDomain.AGENTIC: (
        "agent.interact",
        ("adapter.mcp", "adapter.a2a", "adapter.promptfoo"),
    ),
}
_STATE_TAGS = frozenset(
    {
        "business-logic",
        "workflow",
        "state",
        "race",
        "file",
        "webhook",
        "memory",
        "persistence",
        "delegation",
        "handoff",
    }
)
_AUTH_TAGS = frozenset(
    {"authentication", "authorization", "identity", "credential", "oauth", "oidc", "saml"}
)
_RESOURCE_TAGS = frozenset({"resource", "resilience", "availability", "dos", "fuzzing"})
_METAMORPHIC_TAGS = frozenset({"input", "parser", "evasion", "consistency", "encoding"})
_MAPPING_KEY = re.compile(r"^(?P<source>[A-Z0-9-]+):(?P<identifier>.+)$")


@dataclass(frozen=True, slots=True)
class ReferenceSource:
    key: str
    framework: str
    catalog_version: str
    url: str
    license_expression: str
    usage: str = "reference-mapping-only"

    def to_mapping(self) -> dict[str, str]:
        return {
            "key": self.key,
            "framework": self.framework,
            "catalogVersion": self.catalog_version,
            "url": self.url,
            "license": self.license_expression,
            "usage": self.usage,
        }


_REFERENCE_SOURCES = {
    source.key: source
    for source in (
        ReferenceSource(
            "NIST",
            "NIST SP 800-115",
            "Final 2008",
            "https://csrc.nist.gov/pubs/sp/800/115/final",
            "US-Government-work/reference-only",
        ),
        ReferenceSource(
            "PTES",
            "Penetration Testing Execution Standard",
            "web-edition-retrieved-2026-08-26",
            "https://www.pentest-standard.org/index.php/Main_Page",
            "license-not-asserted/reference-link-only",
        ),
        ReferenceSource(
            "WSTG",
            "OWASP Web Security Testing Guide",
            "4.2",
            "https://owasp.org/www-project-web-security-testing-guide/v42/",
            "CC-BY-SA-4.0/reference-mapping-only",
        ),
        ReferenceSource(
            "ASVS",
            "OWASP Application Security Verification Standard",
            "5.0.0",
            "https://github.com/OWASP/ASVS/tree/v5.0.0_release/5.0",
            "CC-BY-SA-4.0/reference-mapping-only",
        ),
        ReferenceSource(
            "OWASP-API",
            "OWASP API Security Top 10",
            "2023",
            "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
            "CC-BY-SA-4.0/reference-mapping-only",
        ),
        ReferenceSource(
            "AISVS",
            "OWASP AI Security Verification Standard",
            "1.0@78775233666a2022dcfb82037e5e029116955c00",
            "https://github.com/OWASP/AISVS/tree/78775233666a2022dcfb82037e5e029116955c00/1.0",
            "CC-BY-SA-4.0/reference-mapping-only",
        ),
        ReferenceSource(
            "AITG",
            "OWASP AI Testing Guide",
            "1.0@006e4e9ee060f2ca2176037499b824e47af5360e",
            "https://github.com/OWASP/www-project-ai-testing-guide/tree/006e4e9ee060f2ca2176037499b824e47af5360e/Document",
            "CC-BY-SA-4.0/reference-mapping-only",
        ),
        ReferenceSource(
            "AGENTIC",
            "OWASP Top 10 for Agentic Applications",
            "2026",
            "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/",
            "CC-BY-SA-4.0/reference-mapping-only",
        ),
        ReferenceSource(
            "ATLAS",
            "MITRE ATLAS",
            "2026.07",
            "https://github.com/mitre-atlas/atlas-data/releases/tag/v2026.07",
            "MITRE-terms/reference-mapping-only",
        ),
        ReferenceSource(
            "CWE",
            "Common Weakness Enumeration",
            "4.20",
            "https://cwe.mitre.org/data/downloads.html",
            "CWE-terms/reference-mapping-only",
        ),
        ReferenceSource(
            "CAPEC",
            "Common Attack Pattern Enumeration and Classification",
            "3.9",
            "https://capec.mitre.org/data/downloads.html",
            "CAPEC-terms/reference-mapping-only",
        ),
    )
}


@dataclass(frozen=True, slots=True)
class MethodologyLibrary:
    identifier: str
    version: str
    released: str
    sources: tuple[ReferenceSource, ...]
    playbooks: tuple[Playbook, ...]

    def __post_init__(self) -> None:
        identifiers = [item.identifier for item in self.playbooks]
        if not identifiers or len(identifiers) != len(set(identifiers)):
            raise FormatError("SOVA-PLAYBOOK-LIBRARY", "playbook IDs must be non-empty and unique")
        known = set(identifiers)
        for playbook in self.playbooks:
            unknown = set(playbook.depends_on) - known
            if unknown:
                raise FormatError(
                    "SOVA-PLAYBOOK-DEPENDENCY",
                    "playbook dependency is absent from the library",
                    details={"playbook": playbook.identifier, "unknown": sorted(unknown)},
                )
        _validate_acyclic(self.playbooks)

    @property
    def digest(self) -> str:
        return _library_digest(self)

    def by_id(self) -> dict[str, Playbook]:
        return {item.identifier: item for item in self.playbooks}

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.playbook-library",
            "schemaVersion": LIBRARY_SCHEMA_VERSION,
            "id": self.identifier,
            "version": self.version,
            "released": self.released,
            "sources": [source.to_mapping() for source in self.sources],
            "playbooks": [
                item.to_mapping()
                for item in sorted(self.playbooks, key=lambda value: value.identifier)
            ],
            "claims": {
                "externalProseEmbedded": False,
                "thirdPartyDatasetsEmbedded": False,
                "allTargetsCovered": False,
                "allVulnerabilitiesCovered": False,
            },
        }


@lru_cache(maxsize=64)
def _library_digest(library: MethodologyLibrary) -> str:
    return sha256_digest(canonical_json_bytes(library.to_mapping()))


@lru_cache(maxsize=1)
def load_builtin_library() -> MethodologyLibrary:
    """Expand the compact native seed catalog into complete playbook contracts."""
    resource = files("sova.methodology.data").joinpath(_CATALOG_FILE)
    raw = strict_json_loads(resource.read_bytes())
    if not isinstance(raw, dict):
        raise FormatError("SOVA-PLAYBOOK-CATALOG", "playbook seed catalog must be an object")
    expected = {"artifactType", "schemaVersion", "id", "version", "released", "domains"}
    if set(raw) != expected or raw.get("artifactType") != "sova.playbook-seed-catalog":
        raise FormatError("SOVA-PLAYBOOK-CATALOG", "playbook seed catalog fields are invalid")
    domains = raw.get("domains")
    if not isinstance(domains, dict) or set(domains) != {item.value for item in MethodologyDomain}:
        raise FormatError("SOVA-PLAYBOOK-CATALOG", "catalog must contain every methodology domain")
    playbooks: list[Playbook] = []
    for domain in MethodologyDomain:
        rows = domains[domain.value]
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise FormatError("SOVA-PLAYBOOK-CATALOG", "domain seeds must be object arrays")
        playbooks.extend(_expand_seed(domain, cast("dict[str, Any]", row)) for row in rows)
    library = MethodologyLibrary(
        identifier=str(raw["id"]),
        version=str(raw["version"]),
        released=str(raw["released"]),
        sources=tuple(_REFERENCE_SOURCES[key] for key in sorted(_REFERENCE_SOURCES)),
        playbooks=tuple(playbooks),
    )
    for playbook in library.playbooks:
        validate_document(playbook.to_mapping(), "sova.playbook")
    validate_document(library.to_mapping(), "sova.playbook-library")
    return library


def read_playbook(path: Path) -> Playbook:
    document = strict_json_loads(path.read_bytes())
    if not isinstance(document, dict):
        raise FormatError("SOVA-PLAYBOOK-ROOT", "playbook root must be an object")
    validate_document(document, "sova.playbook")
    return playbook_from_mapping(document)


def playbook_from_mapping(value: dict[str, Any]) -> Playbook:
    """Construct one strict playbook from an untrusted JSON mapping."""
    _require_keys(
        value,
        {
            "artifactType",
            "schemaVersion",
            "id",
            "version",
            "domain",
            "title",
            "objective",
            "targetPredicates",
            "dependsOn",
            "prerequisites",
            "discoveryInputs",
            "technique",
            "allowedEffects",
            "toolRequirements",
            "variants",
            "oracleProposal",
            "requiredEvidence",
            "stopRules",
            "cleanup",
            "mappings",
            "evidenceLimits",
            "risk",
            "tags",
            "provenance",
        },
        "playbook",
    )
    if (
        value.get("artifactType") != "sova.playbook"
        or value.get("schemaVersion") != PLAYBOOK_SCHEMA_VERSION
    ):
        raise FormatError("SOVA-PLAYBOOK-VERSION", "playbook type or version is unsupported")
    target = _mapping(value, "targetPredicates")
    technique = _mapping(value, "technique")
    oracle = _mapping(value, "oracleProposal")
    limits = _mapping(value, "evidenceLimits")
    risk = _mapping(value, "risk")
    provenance = _mapping(value, "provenance")
    prerequisites = tuple(
        Prerequisite(
            _string(row, "id"),
            _string(row, "description"),
            _string(row, "kind"),
            _boolean(row, "required"),
        )
        for row in _mapping_array(value, "prerequisites")
    )
    tools = tuple(
        ToolRequirement(
            _string(row, "capability"),
            _boolean(row, "optional"),
            tuple(_string_array(row, "candidateAdapters")),
        )
        for row in _mapping_array(value, "toolRequirements")
    )
    variants = tuple(
        PlaybookVariant(
            _string(row, "id"),
            _string(row, "condition"),
            tuple(_string_array(row, "procedureDelta")),
            tuple(EffectClass(item) for item in _string_array(row, "additionalEffects")),
        )
        for row in _mapping_array(value, "variants")
    )
    evidence = tuple(
        EvidenceRequirement(
            _string(row, "kind"),
            _integer(row, "minimum"),
            _boolean(row, "independent"),
            _boolean(row, "decisive"),
        )
        for row in _mapping_array(value, "requiredEvidence")
    )
    mappings = tuple(
        FrameworkMapping(
            _string(row, "framework"),
            _string(row, "catalogVersion"),
            _string(row, "identifier"),
            _string(row, "title"),
            _string(row, "relationship"),
            _string(row, "url"),
            _string(row, "license"),
        )
        for row in _mapping_array(value, "mappings")
    )
    return Playbook(
        identifier=_string(value, "id"),
        version=_string(value, "version"),
        domain=MethodologyDomain(_string(value, "domain")),
        title=_string(value, "title"),
        objective=_string(value, "objective"),
        target_predicate=TargetPredicate(
            tuple(ProfileTargetKind(item) for item in _string_array(target, "anyTargetKinds")),
            tuple(_string_array(target, "requiredSurfaceKinds")),
            tuple(InputKind(item) for item in _string_array(target, "requiredInputKinds")),
        ),
        depends_on=tuple(_string_array(value, "dependsOn")),
        prerequisites=prerequisites,
        discovery_inputs=tuple(InputKind(item) for item in _string_array(value, "discoveryInputs")),
        technique=Technique(
            _string(technique, "summary"),
            tuple(_string_array(technique, "procedure")),
            tuple(_string_array(technique, "safetyNotes")),
        ),
        allowed_effects=tuple(EffectClass(item) for item in _string_array(value, "allowedEffects")),
        tool_requirements=tools,
        variants=variants,
        oracle_proposal=OracleProposal(
            OracleKind(_string(oracle, "kind")),
            _string(oracle, "statement"),
            _string(oracle, "positiveSignal"),
            _string(oracle, "negativeSignal"),
            _string(oracle, "ambiguousState"),
            _string(oracle, "calibrationStatus"),
        ),
        required_evidence=evidence,
        stop_rules=tuple(
            StopRule(_string(row, "condition"), _string(row, "action"))
            for row in _mapping_array(value, "stopRules")
        ),
        cleanup=tuple(
            CleanupStep(
                _string(row, "action"),
                _string(row, "verification"),
                _boolean(row, "required"),
            )
            for row in _mapping_array(value, "cleanup")
        ),
        mappings=mappings,
        evidence_limits=EvidenceLimits(
            tuple(_string_array(limits, "limitations")),
            tuple(_string_array(limits, "falsePositiveRisks")),
            tuple(_string_array(limits, "falseNegativeRisks")),
        ),
        severity=_integer(risk, "severity"),
        likelihood=_integer(risk, "likelihood"),
        base_cost=_integer(risk, "baseCost"),
        tags=tuple(_string_array(value, "tags")),
        provenance=PlaybookProvenance(
            _string(provenance, "origin"),
            tuple(_string_array(provenance, "authors")),
            _string(provenance, "license"),
            _boolean(provenance, "thirdPartyProseCopied"),
            _boolean(provenance, "thirdPartyDatasetIncluded"),
        ),
    )


def _expand_seed(domain: MethodologyDomain, seed: dict[str, Any]) -> Playbook:
    allowed = {"slug", "title", "technique", "oracle", "risk", "tags", "mappings", "effects"}
    if set(seed) - allowed or set(seed) < allowed - {"effects"}:
        raise FormatError("SOVA-PLAYBOOK-CATALOG", "seed fields are missing or unknown")
    slug = _string(seed, "slug")
    identifier = f"sova.playbook.{domain.value}.{slug}"
    foundation = _DOMAIN_FOUNDATION[domain]
    tags = tuple(_string_array(seed, "tags"))
    effects = {EffectClass.OBSERVE, EffectClass.READ_TARGET}
    if _AUTH_TAGS.intersection(tags):
        effects.add(EffectClass.AUTHENTICATE)
    if _STATE_TAGS.intersection(tags):
        effects.add(EffectClass.MUTATE_REVERSIBLE)
    if _RESOURCE_TAGS.intersection(tags):
        effects.add(EffectClass.CONSUME_BOUNDED_RESOURCE)
    for item in seed.get("effects", []):
        effects.add(EffectClass(str(item)))
    source_tool, candidates = _TOOLS[domain]
    mappings = (
        _framework_mapping("NIST:SP800-115"),
        _framework_mapping("PTES:PTES"),
        *(_framework_mapping(item) for item in _string_array(seed, "mappings")),
    )
    oracle_kind = (
        OracleKind.METAMORPHIC
        if _METAMORPHIC_TAGS.intersection(tags)
        else OracleKind.STATE_EFFECT
        if _STATE_TAGS.intersection(tags)
        else OracleKind.DIFFERENTIAL
        if _AUTH_TAGS.intersection(tags) or "differential" in tags
        else OracleKind.SPECIFICATION
    )
    active_effects = tuple(sorted(effects - {EffectClass.OBSERVE, EffectClass.READ_TARGET}))
    return Playbook(
        identifier=identifier,
        version="0.1.0",
        domain=domain,
        title=_string(seed, "title"),
        objective=(
            f"Assess {str(seed['title']).casefold()} for the exact authorized target generation "
            "and produce independently reproducible, limitation-aware evidence."
        ),
        target_predicate=TargetPredicate(
            _TARGET_KINDS[domain],
            required_surface_kinds=_SURFACE_KINDS[domain],
        ),
        depends_on=() if identifier == foundation else (foundation,),
        prerequisites=(
            Prerequisite(
                "authorization.current",
                "Current proof of control, target authority, and effect approval are required.",
                "authority",
            ),
            Prerequisite(
                "target.generation-bound",
                "Inputs and observations must bind to one unchanged target generation.",
                "target",
            ),
            Prerequisite(
                "oracle.proposal-reviewed",
                "The proposed oracle and its ambiguity state require review before execution.",
                "evidence",
            ),
        ),
        discovery_inputs=_DISCOVERY_INPUTS[domain],
        technique=Technique(
            summary=_string(seed, "technique"),
            procedure=(
                "Bind the task to the exact target profile, generation, authorization, "
                "identities, and budget.",
                _string(seed, "technique"),
                "Collect a primary observation and an explicit negative or policy control "
                "under equivalent conditions.",
                "Reproduce any candidate from a fresh target generation before confirmation.",
            ),
            safety_notes=(
                "Operate only on owned or explicitly authorized scope through an admitted "
                "executor.",
                "Stop on target drift, unexpected effects, scope change, containment loss, "
                "or budget exhaustion.",
                "Treat scanner, model, and target-provided conclusions as untrusted observations.",
            ),
        ),
        allowed_effects=tuple(sorted(effects)),
        tool_requirements=(
            ToolRequirement(
                source_tool,
                optional=True,
                candidate_adapters=candidates,
            ),
        ),
        variants=(
            PlaybookVariant(
                "declaration-only",
                "Only supplied or static evidence is available.",
                (
                    "Map declared controls, assumptions, and evidence gaps without claiming "
                    "runtime behavior.",
                ),
            ),
            PlaybookVariant(
                "approved-active",
                "Fresh authorization, containment, reset, and reliable evidence are available.",
                (
                    "Use bounded active comparisons and preserve raw observations for "
                    "independent reproduction.",
                ),
                active_effects,
            ),
        ),
        oracle_proposal=OracleProposal(
            oracle_kind,
            _string(seed, "oracle"),
            "A controlled test violates the stated invariant and the effect reproduces from "
            "fresh state.",
            "Equivalent positive and negative controls behave according to the stated invariant.",
            "Evidence is missing, contradictory, target state drifted, or infrastructure "
            "affected the result.",
        ),
        required_evidence=(
            EvidenceRequirement("target-binding", minimum=1, independent=True, decisive=False),
            EvidenceRequirement("primary-observation", minimum=1, independent=False, decisive=True),
            EvidenceRequirement("control-observation", minimum=1, independent=True, decisive=True),
            EvidenceRequirement("fresh-reproduction", minimum=1, independent=True, decisive=True),
        ),
        stop_rules=(
            StopRule(
                "Authorization, proof of control, target generation, or approved effect changes.",
                "Stop, mark inconclusive, and require a new plan generation.",
            ),
            StopRule(
                "An undeclared destination, identity, effect, cost, or containment boundary "
                "is reached.",
                "Fail closed and preserve only bounded diagnostic evidence.",
            ),
            StopRule(
                "The budget is exhausted or no reliable oracle can be established.",
                "Stop and report blocked, inconclusive, or human-review-required.",
            ),
        ),
        cleanup=(
            CleanupStep(
                "Restore disposable state and revoke test identities, tokens, and temporary "
                "resources.",
                "Compare the reset target fingerprint and declared cleanup receipts.",
                required=True,
            ),
        ),
        mappings=mappings,
        evidence_limits=EvidenceLimits(
            (
                f"The bounded procedure assesses only {str(seed['title']).casefold()} in "
                "declared and observed scope.",
                "Absence of a reproduced result is not evidence that all related "
                "vulnerabilities are absent.",
                "The oracle remains an unvalidated proposal until P4 calibration and promotion.",
            ),
            (
                "Documented policy, identity, state, caching, timing, or environmental "
                "differences may resemble a security failure.",
                "Scanner or model assertions may be incorrect and require raw evidence plus "
                "controlled reproduction.",
            ),
            (
                "Unobserved workflows, identities, states, encodings, integrations, and "
                "target drift may hide affected behavior.",
                "Finite budgets and unavailable tools or evidence can leave the result incomplete.",
            ),
        ),
        severity=_integer(seed, "risk"),
        likelihood=max(1, min(5, _integer(seed, "risk") - 1)),
        base_cost=6 + _integer(seed, "risk") * 2,
        tags=tags,
        provenance=PlaybookProvenance(
            "sova-native",
            ("SOVA OSS maintainers",),
            "Apache-2.0",
        ),
    )


def _framework_mapping(value: str) -> FrameworkMapping:
    match = _MAPPING_KEY.fullmatch(value)
    if match is None or match.group("source") not in _REFERENCE_SOURCES:
        raise FormatError("SOVA-PLAYBOOK-MAPPING", "seed mapping source is unsupported")
    source = _REFERENCE_SOURCES[match.group("source")]
    identifier = match.group("identifier")
    url = source.url
    if source.key == "CWE" and identifier.startswith("CWE-"):
        url = f"https://cwe.mitre.org/data/definitions/{identifier.removeprefix('CWE-')}.html"
    elif source.key == "CAPEC" and identifier.startswith("CAPEC-"):
        url = f"https://capec.mitre.org/data/definitions/{identifier.removeprefix('CAPEC-')}.html"
    elif source.key == "ATLAS" and identifier.startswith("AML."):
        url = f"https://atlas.mitre.org/techniques/{identifier}/"
    return FrameworkMapping(
        source.framework,
        source.catalog_version,
        identifier,
        f"{source.framework} {identifier}",
        "related",
        url,
        source.license_expression,
    )


def _validate_acyclic(playbooks: tuple[Playbook, ...]) -> None:
    graph = {item.identifier: set(item.depends_on) for item in playbooks}
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(identifier: str) -> None:
        if identifier in visiting:
            raise FormatError("SOVA-PLAYBOOK-DEPENDENCY-CYCLE", "playbook graph has a cycle")
        if identifier in visited:
            return
        visiting.add(identifier)
        for dependency in sorted(graph[identifier]):
            visit(dependency)
        visiting.remove(identifier)
        visited.add(identifier)

    for identifier in sorted(graph):
        visit(identifier)


def _require_keys(value: dict[str, Any], keys: set[str], role: str) -> None:
    if set(value) != keys:
        raise FormatError("SOVA-PLAYBOOK-FIELDS", f"{role} fields are missing or unknown")


def _string(value: dict[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str):
        raise FormatError("SOVA-PLAYBOOK-FIELDS", f"{key} must be a string")
    return item


def _integer(value: dict[str, Any], key: str) -> int:
    item = value.get(key)
    if not isinstance(item, int) or isinstance(item, bool):
        raise FormatError("SOVA-PLAYBOOK-FIELDS", f"{key} must be an integer")
    return item


def _boolean(value: dict[str, Any], key: str) -> bool:
    item = value.get(key)
    if not isinstance(item, bool):
        raise FormatError("SOVA-PLAYBOOK-FIELDS", f"{key} must be a boolean")
    return item


def _mapping(value: dict[str, Any], key: str) -> dict[str, Any]:
    item = value.get(key)
    if not isinstance(item, dict):
        raise FormatError("SOVA-PLAYBOOK-FIELDS", f"{key} must be an object")
    return item


def _string_array(value: dict[str, Any], key: str) -> list[str]:
    item = value.get(key)
    if not isinstance(item, list) or any(not isinstance(child, str) for child in item):
        raise FormatError("SOVA-PLAYBOOK-FIELDS", f"{key} must be a string array")
    return item


def _mapping_array(value: dict[str, Any], key: str) -> list[dict[str, Any]]:
    item = value.get(key)
    if not isinstance(item, list) or any(not isinstance(child, dict) for child in item):
        raise FormatError("SOVA-PLAYBOOK-FIELDS", f"{key} must be an object array")
    return cast("list[dict[str, Any]]", item)


__all__ = [
    "MethodologyLibrary",
    "ReferenceSource",
    "load_builtin_library",
    "playbook_from_mapping",
    "read_playbook",
]
