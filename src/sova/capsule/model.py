# SPDX-License-Identifier: Apache-2.0
"""Authoring, linting, rendering, and packaging helpers for `.sova`."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from sova import __version__
from sova.contracts.identifiers import IdentifierKind, new_stable_identifier
from sova.formats import (
    PackageReader,
    PackageWriter,
    ValidationIssue,
    sha256_digest,
    strict_json_loads,
    validate_document,
    validation_issues,
)
from sova.formats.errors import FormatError
from sova.trace import TraceReader
from sova.trace.redaction import Redactor

if TYPE_CHECKING:
    from pathlib import Path


class DomainProfile(StrEnum):
    """Extensible domain profiles sharing one capsule core."""

    SECURITY = "security"
    EVALUATION = "evaluation"
    AGENT_TRAJECTORY = "agent-trajectory"
    BEHAVIORAL_INTERPRETABILITY = "behavioral-interpretability"
    INCIDENT_FORENSICS = "incident-forensics"
    RESEARCH_PUBLICATION = "research-publication"


_OPAQUE_SECRET_REFERENCE = re.compile(r"^sova-secret:[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_ATTACHMENT_MEDIA_TYPES = {
    ".json": "application/json",
    ".mp4": "video/mp4",
    ".png": "image/png",
    ".txt": "text/plain",
    ".webm": "video/webm",
}
_MIN_MP4_SIGNATURE_BYTES = 12


def _attachment_role_and_media_type(logical_name: str) -> tuple[str, str]:
    lower = logical_name.casefold()
    suffix = next((item for item in _ATTACHMENT_MEDIA_TYPES if lower.endswith(item)), "")
    media_type = _ATTACHMENT_MEDIA_TYPES.get(suffix, "application/octet-stream")
    role = (
        "replay-cues"
        if lower == "replay-cues.json"
        else "visual-replay"
        if media_type.startswith("video/")
        else "attachment"
    )
    return role, media_type


def _validate_visual_attachment(media_type: str, data: bytes) -> None:
    if media_type == "video/webm" and not data.startswith(b"\x1a\x45\xdf\xa3"):
        raise FormatError(
            "SOVA-CAPSULE-VISUAL-MEDIA",
            "WebM visual replay does not contain the EBML signature",
        )
    if media_type == "video/mp4" and (len(data) < _MIN_MP4_SIGNATURE_BYTES or data[4:8] != b"ftyp"):
        raise FormatError(
            "SOVA-CAPSULE-VISUAL-MEDIA",
            "MP4 visual replay does not contain an ISO base media file signature",
        )


def _allowed_secret_reference_paths(value: Any, path: str = "$") -> set[str]:
    """Validate inert secret references while rejecting embedded secret values."""
    allowed: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if key == "secretEnv":
                if (
                    not isinstance(child, dict)
                    or not child
                    or not all(
                        isinstance(name, str)
                        and name
                        and isinstance(reference, str)
                        and _OPAQUE_SECRET_REFERENCE.fullmatch(reference)
                        for name, reference in child.items()
                    )
                ):
                    raise FormatError(
                        "SOVA-CAPSULE-SECRET-REFERENCE",
                        "secretEnv must contain only non-empty sova-secret: references",
                        path=child_path,
                    )
                allowed.update(f"{child_path}.{name}" for name in child)
                continue
            allowed.update(_allowed_secret_reference_paths(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            allowed.update(_allowed_secret_reference_paths(child, f"{path}[{index}]"))
    return allowed


class CaptureProfile(StrEnum):
    """Recording-volume and sensitivity profiles."""

    LITE = "lite"
    STANDARD = "standard"
    FORENSIC = "forensic"
    INTERPRETABILITY = "interpretability"


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def capsule_manifest_template(
    *,
    title: str,
    summary: str,
    author: str,
    domain_profile: DomainProfile = DomainProfile.EVALUATION,
    capture_profile: CaptureProfile = CaptureProfile.LITE,
) -> dict[str, Any]:
    """Create a conservative, valid experimental manifest template."""
    return {
        "artifactType": "sova.capsule",
        "schemaVersion": "0.1.0",
        "id": str(new_stable_identifier(IdentifierKind.CAPSULE)),
        "version": "0.1.0",
        "title": title,
        "summary": summary,
        "domainProfile": domain_profile.value,
        "captureProfile": capture_profile.value,
        "lifecycle": "draft",
        "createdAt": _now(),
        "authors": [{"name": author}],
        "citation": {
            "preferred": f"{author}. {title}. SOVA behavior capsule, version 0.1.0.",
            "identifiers": [],
        },
        "provenance": {
            "createdBy": author,
            "createdWith": f"sova-oss/{__version__}",
            "sourceDigests": [],
            "transformations": [],
        },
        "methodology": {"id": "SOVA-CORE", "version": "0.1.0", "digest": None},
        "taxonomy": {"id": "sova.attack", "version": "0.1.0", "digest": None},
        "compatibility": {
            "runtime": "sova-runtime>=0.1.0a0",
            "models": [],
            "tools": [],
            "platforms": [],
        },
        "authorization": {
            "reexecutionRequiresFreshAuthorization": True,
            "scopeStatement": "Inspect freely; obtain fresh authority before any re-execution.",
        },
        "safety": {
            "impact": "unknown",
            "forbiddenEffects": ["undeclared external side effects"],
            "cleanupRequired": True,
        },
        "disclosure": {
            "classification": "private",
            "sharing": "Review locally before sharing.",
        },
        "license": "NOASSERTION",
        "limitations": ["Experimental 0.x schema; exact reproduction is not guaranteed."],
        "relationships": [],
        "requiredFeatures": [],
        "optionalFeatures": [],
        "extensions": {},
    }


def scenario_template(*, title: str, purpose: str) -> dict[str, Any]:
    """Create a safe inert scenario authoring template."""
    return {
        "artifactType": "sova.scenario",
        "schemaVersion": "0.1.0",
        "id": str(new_stable_identifier(IdentifierKind.SCENARIO)),
        "version": "0.1.0",
        "title": title,
        "purpose": purpose,
        "parameters": {},
        "preconditions": [],
        "sequences": [],
        "procedure": {
            "steps": [
                {
                    "id": "observe",
                    "action": "sova.observe.fixture",
                    "inputs": {"fixture": "replace-with-content-addressed-fixture"},
                    "onFailure": "inconclusive",
                    "requires": ["fixture.read/0.1"],
                }
            ]
        },
        "triggers": [],
        "mutations": [],
        "expectedEffects": [],
        "oracles": [],
        "evidenceRequirements": ["run.lifecycle", "action.outcome"],
        "safety": {
            "budgets": {"maxSteps": 1},
            "forbiddenEffects": ["network.egress", "host.write"],
            "stopConditions": [],
        },
        "cleanup": [],
        "limitations": ["Template contains no live target or executable payload."],
        "extensions": {},
    }


def build_capsule(
    destination: Path,
    manifest: dict[str, Any],
    *,
    scenario: dict[str, Any] | None = None,
    attachments: dict[str, bytes] | None = None,
    traces: list[Path] | None = None,
) -> str:
    """Build one deterministic `.sova` package and return its SHA-256 digest."""
    writer = PackageWriter(manifest)
    if scenario is not None:
        allowed_secret_paths = _allowed_secret_reference_paths(scenario)
        _redacted, secret_records = Redactor().redact(scenario)
        unsafe_records = [
            record for record in secret_records if record["path"] not in allowed_secret_paths
        ]
        if unsafe_records:
            raise FormatError(
                "SOVA-CAPSULE-SECRET-MATERIAL",
                "scenario contains secret-shaped material; use a fixture or secret reference",
                details={"paths": [record["path"] for record in unsafe_records]},
            )
        writer.add_json(
            role="scenario",
            path="objects/scenario.json",
            artifact_type="sova.scenario",
            document=scenario,
        )
    seen_attachments: set[str] = set()
    for logical_name, data in sorted((attachments or {}).items()):
        digest = sha256_digest(data)
        if digest in seen_attachments:
            continue
        seen_attachments.add(digest)
        role, media_type = _attachment_role_and_media_type(logical_name)
        if role == "visual-replay":
            _validate_visual_attachment(media_type, data)
        writer.add_bytes(
            role=role,
            path=f"blobs/sha256/{digest[7:]}",
            media_type=media_type,
            data=data,
        )
    for trace_path in sorted(traces or [], key=lambda item: item.name):
        TraceReader(trace_path).verify()
        writer.add_bytes(
            role="trace",
            path=f"traces/{trace_path.name}",
            media_type="application/vnd.sova.trace+zip",
            data=trace_path.read_bytes(),
        )
    return writer.write(destination)


def lint_capsule(path: Path) -> list[ValidationIssue]:
    """Return semantic warnings after strict structural and integrity checks."""
    reader = PackageReader(path)
    descriptors = reader.verify("sova.capsule")
    manifest = reader.manifest("sova.capsule")
    issues: list[ValidationIssue] = []
    if manifest["safety"]["impact"] == "unknown":
        issues.append(
            ValidationIssue(
                "SOVA-LINT-UNKNOWN-IMPACT",
                "safety impact is unknown; live re-execution should remain blocked",
                "$.safety.impact",
            )
        )
    if manifest["license"] == "NOASSERTION":
        issues.append(
            ValidationIssue(
                "SOVA-LINT-NO-LICENSE",
                "no redistribution licence has been asserted",
                "$.license",
            )
        )
    if not any(descriptor.role == "scenario" for descriptor in descriptors):
        issues.append(
            ValidationIssue(
                "SOVA-LINT-NO-SCENARIO",
                "capsule is inspectable but has no scenario/replay recipe",
                "$.objects",
            )
        )
    else:
        scenario_descriptor = next(
            descriptor for descriptor in descriptors if descriptor.role == "scenario"
        )
        scenario = strict_json_loads(reader.read_object(scenario_descriptor))
        if not isinstance(scenario, dict):
            raise FormatError(
                "SOVA-CAPSULE-SCENARIO-TYPE",
                "scenario object root must be an object",
            )
        issues.extend(lint_scenario(scenario))
    required = set(manifest["requiredFeatures"])
    supported = {
        "capsule.core/0.1",
        "scenario.core/0.1",
        "trace.core/0.1",
        "detonation.synthetic/0.1",
        "arena.chamber/0.1",
    }
    issues.extend(
        (
            ValidationIssue(
                "SOVA-LINT-UNSUPPORTED-REQUIRED-FEATURE",
                f"required feature is not supported: {feature}",
                "$.requiredFeatures",
            )
        )
        for feature in sorted(required - supported)
    )
    return issues


def lint_scenario(document: dict[str, Any]) -> list[ValidationIssue]:
    """Report semantic safety, composition, and portability issues."""
    validate_document(document, "sova.scenario")
    issues: list[ValidationIssue] = []
    sequence_ids = [sequence["id"] for sequence in document["sequences"]]
    if len(set(sequence_ids)) != len(sequence_ids):
        issues.append(
            ValidationIssue(
                "SOVA-LINT-DUPLICATE-SEQUENCE",
                "reusable sequence identifiers must be unique",
                "$.sequences",
            )
        )
    known_sequences = set(sequence_ids)
    all_steps = [
        *document["procedure"]["steps"],
        *(step for sequence in document["sequences"] for step in sequence["steps"]),
    ]
    step_ids = [step["id"] for step in all_steps]
    if len(set(step_ids)) != len(step_ids):
        issues.append(
            ValidationIssue(
                "SOVA-LINT-DUPLICATE-STEP",
                "step identifiers must be unique across the scenario",
                "$.procedure",
            )
        )
    for index, step in enumerate(document["procedure"]["steps"]):
        if step["action"] == "sova.sequence.call":
            target = step["inputs"].get("sequence")
            if not isinstance(target, str) or target not in known_sequences:
                issues.append(
                    ValidationIssue(
                        "SOVA-LINT-MISSING-SEQUENCE",
                        "sequence call must reference a declared reusable sequence",
                        f"$.procedure.steps[{index}].inputs.sequence",
                    )
                )
        required = step.get("requires", [])
        if any("/" not in capability for capability in required):
            issues.append(
                ValidationIssue(
                    "SOVA-LINT-UNVERSIONED-CAPABILITY",
                    "portable required capabilities should include a version",
                    f"$.procedure.steps[{index}].requires",
                )
            )
    known_parameters = set(document["parameters"])
    for index, trigger in enumerate(document["triggers"]):
        parameter = trigger.get("parameter")
        if parameter is not None and parameter not in known_parameters:
            issues.append(
                ValidationIssue(
                    "SOVA-LINT-MISSING-PARAMETER",
                    "trigger references an undeclared parameter",
                    f"$.triggers[{index}].parameter",
                )
            )
    return issues


def render_capsule(path: Path) -> str:
    """Render a bounded inert Markdown summary without rendering active content."""
    reader = PackageReader(path)
    descriptors = reader.verify("sova.capsule")
    manifest = reader.manifest("sova.capsule")
    escaped_title = str(manifest["title"]).replace("<", "&lt;").replace(">", "&gt;")
    lines = [
        f"# {escaped_title}",
        "",
        f"- Capsule: `{manifest['id']}`",
        f"- Schema: `{manifest['schemaVersion']}`",
        f"- Profile: `{manifest['domainProfile']}` / `{manifest['captureProfile']}`",
        f"- Lifecycle: `{manifest['lifecycle']}`",
        f"- Disclosure: `{manifest['disclosure']['classification']}`",
        f"- Objects: {len(descriptors)}",
        "",
        "## Summary",
        "",
        str(manifest["summary"]).replace("<", "&lt;").replace(">", "&gt;"),
        "",
        "## Objects",
        "",
    ]
    lines.extend(
        f"- `{descriptor.role}` | `{descriptor.path}` | `{descriptor.mediaType}` | "
        f"{descriptor.size} bytes | "
        f"`{descriptor.digest}`"
        for descriptor in descriptors
    )
    lines.extend(["", "> Rendering is inert. No capsule content was executed.", ""])
    return "\n".join(lines)


def authoring_issues(document: Any, artifact_type: str) -> list[ValidationIssue]:
    """Expose schema issues to editor and CLI integrations."""
    return validation_issues(document, artifact_type)


__all__ = [
    "CaptureProfile",
    "DomainProfile",
    "authoring_issues",
    "build_capsule",
    "capsule_manifest_template",
    "lint_capsule",
    "lint_scenario",
    "render_capsule",
    "scenario_template",
]
