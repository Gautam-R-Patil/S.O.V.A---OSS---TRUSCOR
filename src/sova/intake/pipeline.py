# SPDX-License-Identifier: Apache-2.0
"""Fail-closed universal target intake orchestration and evidence packaging."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sova import __version__
from sova.capsule import CaptureProfile, DomainProfile, build_capsule, capsule_manifest_template
from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads, validate_document
from sova.formats.errors import FormatError
from sova.intake.contracts import SourceClass, TargetProfile, target_profile_from_mapping
from sova.intake.frontends import IntakeDiscovery, discover_material
from sova.intake.materials import (
    finalize_material_fingerprints,
    load_profile_materials,
)
from sova.intake.model import (
    CoverageState,
    GenerationState,
    IntakeGraph,
    UniversalIntakeReport,
    WorkflowNodeKind,
    intake_provenance,
)
from sova.mapping import EvidenceClass
from sova.trace import TraceReader, TraceWriter

if TYPE_CHECKING:
    from pathlib import Path

    from sova.intake.model import IntakeProvenance, MaterialFingerprint


@dataclass(frozen=True, slots=True)
class IntakeArtifacts:
    """Paths and stable report identity produced by one intake run."""

    destination: Path
    profile: Path
    report: Path
    trace: Path
    capsule: Path
    status: str
    report_digest: str

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.intake-artifacts",
            "schemaVersion": "0.1.0",
            "destination": str(self.destination),
            "profile": str(self.profile),
            "report": str(self.report),
            "trace": str(self.trace),
            "capsule": str(self.capsule),
            "status": self.status,
            "reportDigest": self.report_digest,
        }


def read_target_profile(path: Path) -> TargetProfile:
    """Read and validate one portable target profile."""
    document = strict_json_loads(path.read_bytes())
    if not isinstance(document, dict):
        raise FormatError("SOVA-INTAKE-PROFILE-ROOT", "target profile root must be an object")
    validate_document(document, "sova.target-profile")
    return target_profile_from_mapping(document)


def validate_intake_report(document: dict[str, Any]) -> None:
    """Validate report structure, content identity, topology, and fail-closed claims."""
    validate_document(document, "sova.intake-report")
    supplied_digest = document["contentDigest"]
    digest_body = dict(document)
    digest_body.pop("contentDigest")
    actual_digest = sha256_digest(canonical_json_bytes(digest_body))
    if supplied_digest != actual_digest:
        raise FormatError("SOVA-INTAKE-REPORT-DIGEST", "intake report digest does not match")
    for graph_name in ("workflowGraph", "attackSurfaceGraph"):
        graph = document[graph_name]
        node_ids = [item["id"] for item in graph["nodes"]]
        edge_ids = [item["id"] for item in graph["edges"]]
        if len(node_ids) != len(set(node_ids)) or len(edge_ids) != len(set(edge_ids)):
            raise FormatError("SOVA-INTAKE-GRAPH-IDENTITY", "graph identifiers must be unique")
        known = set(node_ids)
        if any(
            edge["source"] not in known or edge["target"] not in known for edge in graph["edges"]
        ):
            raise FormatError("SOVA-INTAKE-DANGLING-EDGE", "report graph contains a dangling edge")
    if any(document["claims"].values()):
        raise FormatError("SOVA-INTAKE-CLAIMS", "intake reports cannot assert completion or safety")


def read_intake_report(path: Path) -> dict[str, Any]:
    """Read and semantically validate an intake report."""
    document = strict_json_loads(path.read_bytes())
    if not isinstance(document, dict):
        raise FormatError("SOVA-INTAKE-REPORT-ROOT", "intake report root must be an object")
    validate_intake_report(document)
    return document


def run_universal_intake(
    profile: TargetProfile,
    bindings: dict[str, Path],
    destination: Path,
    *,
    active_observations_authorized: bool = False,
) -> IntakeArtifacts:
    """Discover supplied target representations without executing target code."""
    validate_document(profile.to_mapping(), "sova.target-profile")
    final = destination.resolve()
    if final.exists():
        raise FormatError("SOVA-INTAKE-DESTINATION", "intake destination already exists")
    final.parent.mkdir(parents=True, exist_ok=True)
    staging = final.with_name(f".{final.name}.partial")
    if staging.exists():
        raise FormatError("SOVA-INTAKE-STAGING", "intake staging destination already exists")
    staging.mkdir()
    try:
        artifacts = _run_into_staging(
            profile,
            bindings,
            staging,
            active_observations_authorized=active_observations_authorized,
        )
        staging.replace(final)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    return IntakeArtifacts(
        destination=final,
        profile=final / artifacts.profile.name,
        report=final / artifacts.report.name,
        trace=final / artifacts.trace.name,
        capsule=final / artifacts.capsule.name,
        status=artifacts.status,
        report_digest=artifacts.report_digest,
    )


def _run_into_staging(
    profile: TargetProfile,
    bindings: dict[str, Path],
    staging: Path,
    *,
    active_observations_authorized: bool,
) -> IntakeArtifacts:
    discovery = IntakeDiscovery(profile)
    discovery.seed_profile()
    loaded = load_profile_materials(
        profile,
        bindings,
        active_observations_authorized=active_observations_authorized,
    )
    errors = list(loaded.errors)
    parse_error_ids: set[str] = set()
    for material in loaded.materials:
        try:
            discover_material(discovery, material)
        except (FormatError, ValueError, TypeError) as error:
            code = error.issue.code if isinstance(error, FormatError) else "SOVA-INTAKE-PARSE"
            message = (
                error.issue.message if isinstance(error, FormatError) else type(error).__name__
            )
            errors.append({"inputId": material.descriptor.id, "code": code, "message": message})
            parse_error_ids.add(material.descriptor.id)
            failure_provenance = intake_provenance(
                material.descriptor.id,
                "$/discovery-error",
                material.descriptor.source_class,
                EvidenceClass.REFUTED,
                {"code": code},
            )
            discovery.workflow.add_node(
                WorkflowNodeKind.UNKNOWN,
                f"discovery-failure:{material.descriptor.id}:{code}",
                "input discovery failure",
                attributes={"code": code, "targetCodeExecuted": False},
                evidence_class=EvidenceClass.REFUTED,
                confidence=1.0,
                provenance=failure_provenance,
            )
            discovery.cover(
                material.descriptor.id,
                "input",
                CoverageState.BLOCKED,
                code,
                material.start_digest,
            )
    fingerprints = finalize_material_fingerprints(loaded)
    inputs = _input_records(profile, discovery, errors, parse_error_ids, fingerprints)
    _add_graph_coverage(discovery, discovery.workflow, "workflow")
    _add_graph_coverage(discovery, discovery.surface, "attack-surface")
    coverage = discovery.coverage_contract()
    status = _intake_status(
        profile,
        errors,
        fingerprints,
        coverage_partial=coverage.to_mapping()["partial"],
    )
    if any(item.state != GenerationState.MATCH for item in fingerprints):
        discovery.limitations.append("One or more declared materials were missing or changed.")
    report = UniversalIntakeReport(
        profile=profile,
        status=status,
        workflow_graph=discovery.workflow,
        attack_surface_graph=discovery.surface,
        coverage=coverage,
        fingerprints=fingerprints,
        inputs=inputs,
        limitations=tuple(discovery.limitations),
        errors=tuple(sorted(errors, key=lambda item: (item["inputId"], item["code"]))),
    ).to_mapping()
    validate_intake_report(report)

    profile_path = staging / "target-profile.json"
    report_path = staging / "intake-report.json"
    trace_path = staging / "intake.sova-trace"
    capsule_path = staging / "intake.sova"
    profile_bytes = canonical_json_bytes(profile.to_mapping()) + b"\n"
    report_bytes = canonical_json_bytes(report) + b"\n"
    profile_path.write_bytes(profile_bytes)
    report_path.write_bytes(report_bytes)
    _write_trace(
        profile,
        report,
        inputs,
        errors,
        trace_path,
        active_observations_authorized=active_observations_authorized,
    )
    _write_capsule(profile, report, profile_bytes, report_bytes, trace_path, capsule_path)
    TraceReader(trace_path).verify()
    return IntakeArtifacts(
        destination=staging,
        profile=profile_path,
        report=report_path,
        trace=trace_path,
        capsule=capsule_path,
        status=status,
        report_digest=report["contentDigest"],
    )


def _input_records(
    profile: TargetProfile,
    discovery: IntakeDiscovery,
    errors: list[dict[str, str]],
    parse_error_ids: set[str],
    fingerprints: tuple[MaterialFingerprint, ...],
) -> tuple[dict[str, Any], ...]:
    parsed = {item["id"]: item for item in discovery.processed_inputs}
    errors_by_input = {item["inputId"]: item["code"] for item in errors}
    fingerprint_by_input = {item.input_id: item for item in fingerprints}
    records: list[dict[str, Any]] = []
    for descriptor in profile.inputs:
        if descriptor.id in parsed and descriptor.id not in parse_error_ids:
            records.append(parsed[descriptor.id])
            continue
        code = errors_by_input.get(descriptor.id, "SOVA-INTAKE-NOT-PROCESSED")
        fingerprint = fingerprint_by_input[descriptor.id]
        status = (
            "parse-error"
            if descriptor.id in parse_error_ids
            else "drift"
            if fingerprint.state == GenerationState.DRIFT
            else "blocked"
            if code == "SOVA-INTAKE-ACTIVE-AUTHORIZATION"
            else "missing"
            if code == "SOVA-INTAKE-MATERIAL-MISSING"
            else "load-error"
        )
        records.append(
            {
                "id": descriptor.id,
                "kind": descriptor.kind.value,
                "sourceClass": descriptor.source_class.value,
                "digest": fingerprint.start_digest,
                "status": status,
                "targetCodeExecuted": False,
            }
        )
        discovery.cover(descriptor.id, "input", CoverageState.BLOCKED, code)
    return tuple(records)


def _add_graph_coverage(
    discovery: IntakeDiscovery,
    graph: IntakeGraph,
    dimension_prefix: str,
) -> None:
    for node in graph.nodes.values():
        discovery.cover(
            node.id,
            f"{dimension_prefix}-node",
            _evidence_state(node.evidence_class, node.provenance),
            f"{node.evidence_class.value}-node",
            *(item.projection_digest for item in node.provenance),
        )
    for edge in graph.edges.values():
        discovery.cover(
            edge.id,
            f"{dimension_prefix}-edge",
            _evidence_state(edge.evidence_class, edge.provenance),
            f"{edge.evidence_class.value}-edge",
            *(item.projection_digest for item in edge.provenance),
        )


def _evidence_state(
    evidence_class: EvidenceClass, provenance: tuple[IntakeProvenance, ...]
) -> CoverageState:
    if any(item.source_class == SourceClass.ACTIVE for item in provenance):
        return CoverageState.EXERCISED
    if evidence_class == EvidenceClass.DECLARED:
        return CoverageState.DECLARED
    return CoverageState.DISCOVERED


def _intake_status(
    profile: TargetProfile,
    errors: list[dict[str, str]],
    fingerprints: tuple[MaterialFingerprint, ...],
    *,
    coverage_partial: bool,
) -> str:
    required = {item.id for item in profile.inputs if item.required}
    if any(item.state == GenerationState.DRIFT for item in fingerprints):
        return "inconclusive"
    if any(item["inputId"] in required for item in errors):
        return "inconclusive"
    if errors or coverage_partial:
        return "partial"
    return "complete"


def _write_trace(  # noqa: PLR0913 - evidence inputs remain explicit
    profile: TargetProfile,
    report: dict[str, Any],
    inputs: tuple[dict[str, Any], ...],
    errors: list[dict[str, str]],
    destination: Path,
    *,
    active_observations_authorized: bool,
) -> None:
    absent = {
        "value": None,
        "status": "not-recorded",
        "method": "not-recorded",
        "source": "sova-intake",
        "version": "0.1.0",
    }
    fingerprints = {
        name: dict(absent)
        for name in ("environment", "target", "code", "dependencies", "registry", "model")
    }
    fingerprints["target"] = {
        "value": profile.digest,
        "status": "recorded",
        "method": "canonical-target-profile-sha256",
        "source": "sova-intake",
        "version": "0.1.0",
    }
    writer = TraceWriter(
        destination,
        capture_profile="standard",
        authorization={
            "decision": "allowed" if active_observations_authorized else "not-required",
            "scopeDigest": sha256_digest(profile.authorization_scope.encode()),
            "decidedBy": "operator-active-import-flag"
            if active_observations_authorized
            else "static-intake-policy",
        },
        executor={
            "id": "sova:executor:universal-intake",
            "name": "SOVA universal target intake",
            "version": __version__,
            "capabilityDigest": None,
        },
        fingerprints=fingerprints,
    )
    start = writer.append(
        "run.started",
        {"operation": "universal-target-intake", "profileDigest": profile.digest},
    )
    for item in inputs:
        writer.append("artifact.observed", item, parents=[start] if start else [])
    for item in errors:
        writer.append(
            "error.material",
            {"inputId": item["inputId"], "code": item["code"]},
            parents=[start] if start else [],
        )
    writer.append(
        "artifact.created",
        {
            "artifactType": "sova.intake-report",
            "contentDigest": report["contentDigest"],
            "status": report["status"],
        },
        parents=[start] if start else [],
    )
    writer.finalize()


def _write_capsule(  # noqa: PLR0913, PLR0917 - package inputs remain explicit
    profile: TargetProfile,
    report: dict[str, Any],
    profile_bytes: bytes,
    report_bytes: bytes,
    trace_path: Path,
    destination: Path,
) -> None:
    manifest = capsule_manifest_template(
        title=f"Universal intake: {profile.title}",
        summary="Content-bound target profile, discovery graphs, coverage contract, and trace.",
        author="SOVA OSS universal intake",
        domain_profile=DomainProfile.SECURITY,
        capture_profile=CaptureProfile.STANDARD,
    )
    manifest["provenance"]["sourceDigests"] = [profile.digest, report["contentDigest"]]
    manifest["provenance"]["transformations"] = ["sova.universal-intake/0.1"]
    manifest["requiredFeatures"] = ["intake.report/0.1", "intake.target-profile/0.1"]
    manifest["limitations"] = list(report["limitations"]) or [
        "Intake evidence does not prove that every workflow or attack surface was discovered."
    ]
    manifest["extensions"]["x-sova-universal-intake"] = {
        "profileDigest": profile.digest,
        "reportDigest": report["contentDigest"],
        "status": report["status"],
        "targetCodeExecuted": False,
        "allVulnerabilitiesFound": False,
    }
    build_capsule(
        destination,
        manifest,
        attachments={
            "target-profile.json": profile_bytes,
            "intake-report.json": report_bytes,
        },
        named_traces={"intake.sova-trace": trace_path},
    )


__all__ = [
    "IntakeArtifacts",
    "read_intake_report",
    "read_target_profile",
    "run_universal_intake",
    "validate_intake_report",
]
