# SPDX-License-Identifier: Apache-2.0
"""Bounded, fail-closed normalizers for promoted security adapters."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Mapping
from typing import Any

from sova.adapters.security_contracts import (
    AdapterDescriptor,
    AdapterInvocation,
    ExternalToolEnvelope,
    NormalizedObservation,
    ObservationState,
    RawArtifact,
    semantic_fingerprint,
)
from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError

_XML_FORBIDDEN = re.compile(rb"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)
_MAX_XML_BYTES = 16 * 1024 * 1024
_MAX_XML_NODES = 100_000
_MAX_JSONL_LINES = 100_000
_SAFE_SEVERITIES = {"unknown", "info", "low", "medium", "high", "critical"}
_SEVERITY_ALIASES = {
    "informational": "info",
    "warning": "medium",
    "error": "high",
    "0": "info",
    "1": "low",
    "2": "medium",
    "3": "high",
    "4": "critical",
}
_CONFIDENCE = {"unknown", "low", "medium", "high"}


def _string(value: Any, default: str = "unknown", *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value:
        return default
    return value[:maximum]


def _severity(value: Any) -> str:
    rendered = _string(value).casefold().split()[0]
    rendered = _SEVERITY_ALIASES.get(rendered, rendered)
    return rendered if rendered in _SAFE_SEVERITIES else "unknown"


def _confidence(value: Any) -> str:
    rendered = _string(value).casefold().split()[0]
    return rendered if rendered in _CONFIDENCE else "unknown"


def _mapping_list(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _json(raw: bytes) -> Any:
    return strict_json_loads(raw)


def _jsonl(raw: bytes) -> list[Mapping[str, Any]]:
    records: list[Mapping[str, Any]] = []
    for line_number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        if line_number > _MAX_JSONL_LINES:
            raise FormatError("SOVA-ADAPTER-JSONL-LIMIT", "JSONL record limit exceeded")
        value = strict_json_loads(line)
        if not isinstance(value, Mapping):
            raise FormatError(
                "SOVA-ADAPTER-JSONL-ROOT",
                "each JSONL record must be an object",
                details={"line": line_number},
            )
        records.append(value)
    return records


def _xml(raw: bytes) -> ET.Element:
    if len(raw) > _MAX_XML_BYTES:
        raise FormatError("SOVA-ADAPTER-XML-LIMIT", "XML output exceeds the byte limit")
    if _XML_FORBIDDEN.search(raw):
        raise FormatError("SOVA-ADAPTER-XML-ENTITY", "DTD and entity declarations are forbidden")
    try:
        root = ET.fromstring(raw)  # noqa: S314 - DTD/entities rejected before bounded parse
    except ET.ParseError as error:
        raise FormatError("SOVA-ADAPTER-XML", "external tool returned invalid XML") from error
    if sum(1 for _node in root.iter()) > _MAX_XML_NODES:
        raise FormatError("SOVA-ADAPTER-XML-LIMIT", "XML output exceeds the node limit")
    return root


def _record(  # noqa: PLR0913 - normalized assertion fields remain explicit
    rule_id: Any,
    title: Any,
    *,
    severity: Any = "unknown",
    confidence: Any = "unknown",
    location: Any = None,
    state: ObservationState = ObservationState.TOOL_ASSERTED_FAILURE,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    safe_metadata = {
        _string(key, maximum=128): value
        for key, value in (metadata or {}).items()
        if isinstance(value, (bool, int, str)) and not isinstance(value, float)
    }
    return {
        "rule_id": _string(rule_id),
        "title": _string(title),
        "severity": _severity(severity),
        "confidence": _confidence(confidence),
        "location": _string(location, default="", maximum=2048) or None,
        "state": state,
        "metadata": safe_metadata,
    }


def _zap(raw: bytes) -> list[dict[str, Any]]:
    document = _json(raw)
    if not isinstance(document, Mapping):
        raise FormatError("SOVA-ADAPTER-ZAP", "ZAP JSON root must be an object")
    records: list[dict[str, Any]] = []
    for site in _mapping_list(document.get("site")):
        for alert in _mapping_list(site.get("alerts")):
            instances = _mapping_list(alert.get("instances"))
            location = instances[0].get("uri") if instances else site.get("@name")
            records.append(
                _record(
                    alert.get("pluginid", alert.get("alertRef")),
                    alert.get("alert", alert.get("name")),
                    severity=alert.get("riskdesc", alert.get("riskcode")),
                    confidence=alert.get("confidence"),
                    location=location,
                    metadata={"cwe": _string(alert.get("cweid"))},
                )
            )
    return records


def _nuclei(raw: bytes) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for item in _jsonl(raw):
        candidate_info = item.get("info")
        info: Mapping[str, Any] = candidate_info if isinstance(candidate_info, Mapping) else {}
        records.append(
            _record(
                item.get("template-id", item.get("templateID")),
                info.get("name", item.get("template-id")),
                severity=info.get("severity"),
                confidence="medium",
                location=item.get("matched-at", item.get("host")),
                metadata={"type": _string(item.get("type"))},
            )
        )
    return records


def _schemathesis(raw: bytes) -> list[dict[str, Any]]:
    root = _xml(raw)
    records: list[dict[str, Any]] = []
    total = 0
    for testcase in root.iter("testcase"):
        total += 1
        failure = testcase.find("failure")
        error = testcase.find("error")
        cause = failure if failure is not None else error
        if cause is None:
            continue
        records.append(
            _record(
                testcase.attrib.get("name"),
                cause.attrib.get("message", testcase.attrib.get("name")),
                severity="medium" if failure is not None else "high",
                confidence="high",
                location=testcase.attrib.get("classname"),
            )
        )
    if not records:
        records.append(
            _record(
                "schemathesis.summary",
                "No failing generated API case was asserted",
                severity="info",
                confidence="medium",
                state=ObservationState.TOOL_ASSERTED_PASS,
                metadata={"testcases": total},
            )
        )
    return records


def _pyrit(raw: bytes) -> list[dict[str, Any]]:
    document = _json(raw)
    if not isinstance(document, Mapping) or document.get("exportSchema") != "sova-pyrit/0.1.0":
        raise FormatError(
            "SOVA-ADAPTER-PYRIT",
            "PyRIT output must use the pinned SOVA export seam",
        )
    records: list[dict[str, Any]] = []
    for item in _mapping_list(document.get("results")):
        outcome = _string(item.get("outcome")).casefold()
        state = (
            ObservationState.TOOL_ASSERTED_FAILURE
            if outcome in {"failure", "unsafe", "attack-succeeded"}
            else ObservationState.TOOL_ASSERTED_PASS
            if outcome in {"pass", "safe", "attack-failed"}
            else ObservationState.INCONCLUSIVE
        )
        records.append(
            _record(
                item.get("id"),
                item.get("title"),
                severity=item.get("severity"),
                confidence=item.get("confidence"),
                location=item.get("target"),
                state=state,
                metadata={"category": _string(item.get("category"))},
            )
        )
    return records


def _garak(raw: bytes) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for item in _jsonl(raw):
        if _string(item.get("entry_type")).casefold() not in {"eval", "attempt", "detector"}:
            continue
        passed = item.get("passed")
        score = item.get("score")
        if isinstance(passed, bool):
            state = (
                ObservationState.TOOL_ASSERTED_PASS
                if passed
                else ObservationState.TOOL_ASSERTED_FAILURE
            )
        elif isinstance(score, (int, float)):
            state = (
                ObservationState.TOOL_ASSERTED_FAILURE
                if score > 0
                else ObservationState.TOOL_ASSERTED_PASS
            )
        else:
            state = ObservationState.INCONCLUSIVE
        records.append(
            _record(
                item.get("detector", item.get("probe")),
                item.get("detector", item.get("probe")),
                severity="medium",
                confidence="low",
                state=state,
                metadata={"entryType": _string(item.get("entry_type"))},
            )
        )
    return records


def _promptfoo(raw: bytes) -> list[dict[str, Any]]:
    document = _json(raw)
    if not isinstance(document, Mapping):
        raise FormatError("SOVA-ADAPTER-PROMPTFOO", "promptfoo JSON root must be an object")
    outer = document.get("results")
    if isinstance(outer, Mapping):
        values = _mapping_list(outer.get("results"))
    else:
        values = _mapping_list(outer)
    records: list[dict[str, Any]] = []
    for item in values:
        success = item.get("success")
        state = (
            ObservationState.TOOL_ASSERTED_PASS
            if success is True
            else ObservationState.TOOL_ASSERTED_FAILURE
            if success is False
            else ObservationState.INCONCLUSIVE
        )
        grading = item.get("gradingResult")
        grading_map = grading if isinstance(grading, Mapping) else {}
        records.append(
            _record(
                item.get("testIdx", grading_map.get("componentResults", "promptfoo.result")),
                grading_map.get("reason", item.get("description", "promptfoo assertion")),
                severity="medium",
                confidence="medium",
                state=state,
                metadata={"provider": _string(item.get("provider"))},
            )
        )
    return records


def _trivy(raw: bytes) -> list[dict[str, Any]]:
    document = _json(raw)
    if not isinstance(document, Mapping):
        raise FormatError("SOVA-ADAPTER-TRIVY", "Trivy JSON root must be an object")
    records: list[dict[str, Any]] = []
    for result in _mapping_list(document.get("Results")):
        location = result.get("Target")
        collections = (
            ("Vulnerabilities", "VulnerabilityID"),
            ("Misconfigurations", "ID"),
            ("Secrets", "RuleID"),
        )
        for key, id_key in collections:
            records.extend(
                (
                    _record(
                        item.get(id_key),
                        item.get("Title", item.get("RuleTitle", item.get(id_key))),
                        severity=item.get("Severity"),
                        confidence="medium",
                        location=location,
                        metadata={"class": key},
                    )
                )
                for item in _mapping_list(result.get(key))
            )
    return records


def _syft(raw: bytes) -> list[dict[str, Any]]:
    document = _json(raw)
    if not isinstance(document, Mapping):
        raise FormatError("SOVA-ADAPTER-SYFT", "Syft JSON root must be an object")
    return [
        _record(
            item.get("id", item.get("purl", item.get("name"))),
            item.get("name", "SBOM package"),
            severity="info",
            confidence="high",
            location=item.get("purl"),
            state=ObservationState.INFORMATIONAL,
            metadata={
                "version": _string(item.get("version")),
                "type": _string(item.get("type")),
            },
        )
        for item in _mapping_list(document.get("artifacts"))
    ]


def _grype(raw: bytes) -> list[dict[str, Any]]:
    document = _json(raw)
    if not isinstance(document, Mapping):
        raise FormatError("SOVA-ADAPTER-GRYPE", "Grype JSON root must be an object")
    records: list[dict[str, Any]] = []
    for match in _mapping_list(document.get("matches")):
        vulnerability = match.get("vulnerability")
        artifact = match.get("artifact")
        vuln = vulnerability if isinstance(vulnerability, Mapping) else {}
        package = artifact if isinstance(artifact, Mapping) else {}
        records.append(
            _record(
                vuln.get("id"),
                vuln.get("description", vuln.get("id")),
                severity=vuln.get("severity"),
                confidence="medium",
                location=package.get("purl", package.get("name")),
                metadata={"packageVersion": _string(package.get("version"))},
            )
        )
    return records


def _osv(raw: bytes) -> list[dict[str, Any]]:
    document = _json(raw)
    if not isinstance(document, Mapping):
        raise FormatError("SOVA-ADAPTER-OSV", "OSV-Scanner JSON root must be an object")
    records: list[dict[str, Any]] = []
    for result in _mapping_list(document.get("results")):
        for package_result in _mapping_list(result.get("packages")):
            package = package_result.get("package")
            package_map = package if isinstance(package, Mapping) else {}
            for group in _mapping_list(package_result.get("groups")):
                ids = group.get("ids") if isinstance(group.get("ids"), list) else []
                vulnerabilities = _mapping_list(group.get("aliases")) + _mapping_list(
                    group.get("vulnerabilities")
                )
                records.extend(
                    (
                        _record(
                            vulnerability.get("id", ids[0] if ids else None),
                            vulnerability.get("summary", vulnerability.get("id")),
                            severity="unknown",
                            confidence="medium",
                            location=package_map.get("name"),
                        )
                    )
                    for vulnerability in vulnerabilities
                )
                if not group.get("vulnerabilities") and ids:
                    records.extend(
                        (
                            _record(
                                identifier,
                                identifier,
                                confidence="medium",
                                location=package_map.get("name"),
                            )
                        )
                        for identifier in ids
                    )
    return records


def _gitleaks(raw: bytes) -> list[dict[str, Any]]:
    document = _json(raw)
    if not isinstance(document, list):
        raise FormatError("SOVA-ADAPTER-GITLEAKS", "Gitleaks JSON root must be an array")
    values = document
    records: list[dict[str, Any]] = []
    for item in values:
        if not isinstance(item, Mapping):
            continue
        records.append(
            _record(
                item.get("RuleID"),
                item.get("Description", item.get("RuleID")),
                severity="high",
                confidence="medium",
                location=item.get("File"),
                metadata={"startLine": item.get("StartLine", 0)},
            )
        )
    return records


def _semgrep(raw: bytes) -> list[dict[str, Any]]:
    document = _json(raw)
    if not isinstance(document, Mapping):
        raise FormatError("SOVA-ADAPTER-SEMGREP", "Semgrep JSON root must be an object")
    records: list[dict[str, Any]] = []
    for item in _mapping_list(document.get("results")):
        extra = item.get("extra")
        extra_map = extra if isinstance(extra, Mapping) else {}
        start = item.get("start")
        start_map = start if isinstance(start, Mapping) else {}
        records.append(
            _record(
                item.get("check_id"),
                extra_map.get("message", item.get("check_id")),
                severity=extra_map.get("severity"),
                confidence="medium",
                location=item.get("path"),
                metadata={"startLine": start_map.get("line", 0)},
            )
        )
    return records


_PARSERS = {
    "sova.parser.zap-json": _zap,
    "sova.parser.nuclei-jsonl": _nuclei,
    "sova.parser.schemathesis-junit": _schemathesis,
    "sova.parser.pyrit-export-json": _pyrit,
    "sova.parser.garak-jsonl": _garak,
    "sova.parser.promptfoo-json": _promptfoo,
    "sova.parser.trivy-json": _trivy,
    "sova.parser.syft-json": _syft,
    "sova.parser.grype-json": _grype,
    "sova.parser.osv-json": _osv,
    "sova.parser.gitleaks-json": _gitleaks,
    "sova.parser.semgrep-json": _semgrep,
}


def normalize_security_output(  # noqa: PLR0913 - evidence bindings stay explicit
    descriptor: AdapterDescriptor,
    invocation: AdapterInvocation,
    *,
    executable_digest: str,
    raw: bytes,
    media_type: str,
    complete: bool = True,
) -> tuple[NormalizedObservation, ...]:
    """Normalize promoted output while retaining an immutable raw binding."""
    if invocation.descriptor_id != descriptor.identifier:
        raise FormatError("SOVA-ADAPTER-BINDING", "invocation and descriptor do not match")
    if media_type not in descriptor.output_media_types:
        raise FormatError("SOVA-ADAPTER-MEDIA", "output media type is not admitted")
    if not complete:
        raise FormatError("SOVA-ADAPTER-PARTIAL", "partial output must not be parsed")
    if len(raw) > descriptor.bounds.max_output_bytes:
        raise FormatError("SOVA-ADAPTER-OUTPUT-LIMIT", "raw output exceeds descriptor bounds")
    try:
        parser = _PARSERS[descriptor.parser_id]
    except KeyError as error:
        raise FormatError(
            "SOVA-ADAPTER-PARSER-UNSUPPORTED",
            "descriptor parser is not implemented as a promoted normalizer",
        ) from error
    parsed = parser(raw)
    if len(parsed) > descriptor.bounds.max_findings:
        raise FormatError("SOVA-ADAPTER-FINDING-LIMIT", "normalized assertion limit exceeded")
    raw_artifact = RawArtifact(
        digest=sha256_digest(raw),
        media_type=media_type,
        size=len(raw),
        complete=True,
        source=descriptor.output_source,
    )
    observations: list[NormalizedObservation] = []
    for item in parsed:
        state = item["state"]
        fingerprint = semantic_fingerprint(
            adapter_id=descriptor.identifier,
            target_id=invocation.target_id,
            rule_id=item["rule_id"],
            state=state,
            location=item["location"],
        )
        observations.append(
            NormalizedObservation(
                identifier=f"sova:observation:{fingerprint[7:31]}",
                adapter_id=descriptor.identifier,
                adapter_digest=descriptor.digest,
                tool_version=descriptor.tool_version,
                executable_digest=executable_digest,
                parser_id=descriptor.parser_id,
                parser_version=descriptor.parser_version,
                target_id=invocation.target_id,
                target_profile_digest=invocation.target_profile_digest,
                target_generation=invocation.target_generation,
                raw=raw_artifact,
                state=state,
                rule_id=item["rule_id"],
                title=item["title"],
                severity=item["severity"],
                confidence=item["confidence"],
                location=item["location"],
                stable_fingerprint=fingerprint,
                metadata=item["metadata"],
                config_digest=invocation.config_digest,
                ruleset_digest=invocation.ruleset_digest,
            )
        )
    return tuple(observations)


def infrastructure_failure_observation(
    descriptor: AdapterDescriptor,
    invocation: AdapterInvocation,
    *,
    executable_digest: str,
    status: str,
    raw: RawArtifact,
) -> NormalizedObservation:
    """Represent execution failure without parsing or inventing a target finding."""
    fingerprint = semantic_fingerprint(
        adapter_id=descriptor.identifier,
        target_id=invocation.target_id,
        rule_id=f"infrastructure.{status}",
        state=ObservationState.INFRASTRUCTURE_FAILURE,
        location=None,
    )
    return NormalizedObservation(
        identifier=f"sova:observation:{fingerprint[7:31]}",
        adapter_id=descriptor.identifier,
        adapter_digest=descriptor.digest,
        tool_version=descriptor.tool_version,
        executable_digest=executable_digest,
        parser_id=descriptor.parser_id,
        parser_version=descriptor.parser_version,
        target_id=invocation.target_id,
        target_profile_digest=invocation.target_profile_digest,
        target_generation=invocation.target_generation,
        raw=raw,
        state=ObservationState.INFRASTRUCTURE_FAILURE,
        rule_id=f"infrastructure.{status}",
        title=f"Adapter infrastructure ended with {status}",
        severity="unknown",
        confidence="high",
        location=None,
        stable_fingerprint=fingerprint,
        metadata={"outcomeStatus": status},
        config_digest=invocation.config_digest,
        ruleset_digest=invocation.ruleset_digest,
    )


def normalize_external_envelope(envelope: ExternalToolEnvelope) -> dict[str, Any]:
    """Detach a generic MCP/stdio/HTTP producer result without granting trust."""
    return {
        "artifactType": "sova.external-tool-envelope",
        "schemaVersion": "0.1.0",
        "transport": envelope.transport.value,
        "producer": envelope.producer,
        "rawDigest": envelope.raw_digest,
        "schemaDigest": (
            sha256_digest(canonical_json_bytes(envelope.schema))
            if envelope.schema is not None
            else None
        ),
        "summaryPresent": envelope.summary is not None,
        "evidenceReferenceCount": len(envelope.evidence_references),
        "trust": {
            "schema": envelope.schema_trust.value,
            "summary": envelope.summary_trust.value,
            "evidence": envelope.evidence_trust.value,
        },
        "findingConfirmed": False,
    }


def compare_reproduction(
    first: Iterable[NormalizedObservation],
    second: Iterable[NormalizedObservation],
) -> dict[str, Any]:
    """Compare semantic assertion sets without trusting either run's verdict."""
    left = {item.stable_fingerprint for item in first}
    right = {item.stable_fingerprint for item in second}
    return {
        "matched": left == right,
        "independentlyReproduced": left == right and bool(left),
        "firstOnly": sorted(left - right),
        "secondOnly": sorted(right - left),
        "comparisonDigest": sha256_digest(
            canonical_json_bytes({"first": sorted(left), "second": sorted(right)})
        ),
    }


__all__ = [
    "compare_reproduction",
    "infrastructure_failure_observation",
    "normalize_external_envelope",
    "normalize_security_output",
]
