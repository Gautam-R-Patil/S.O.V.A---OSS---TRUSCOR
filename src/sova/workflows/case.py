# SPDX-License-Identifier: Apache-2.0
"""Build one offline, review-first case workspace from verified SOVA evidence."""

from __future__ import annotations

import shutil
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sova.community import ReplayClipSpec, ReplayFrame, render_replay_clip
from sova.evidence import build_evidence_bundle, evidence_to_sarif, render_evidence_report
from sova.forensics import reconstruct_trace
from sova.formats import PackageReader, canonical_json_bytes, sha256_digest, validate_document
from sova.formats.errors import FormatError
from sova.monitoring import build_behavior_snapshot
from sova.registry import preview_contribution
from sova.replay import VerificationState, render_timeline_html, verify_artifact
from sova.trace import TraceReader

_FINDING_CLASSES = frozenset({"simulation", "bundled-target", "real-disclosed-finding"})
_REPORT_AUDIENCES = ("technical", "executive", "reproduction", "methodology")
_MAX_TITLE_LENGTH = 240
_MAX_REPLAY_EVENTS = 12


@dataclass(frozen=True, slots=True)
class CaseWorkspaceArtifacts:
    """Paths and bounded state for one completed local case workspace."""

    root: Path
    index: Path
    trace: Path
    capsule: Path
    reconstruction: Path
    timeline: Path
    replay_clip: Path
    evidence: Path
    snapshot: Path
    contribution_preview: Path
    trace_id: str
    capsule_id: str
    event_count: int
    classification: str

    def to_mapping(self) -> dict[str, Any]:
        return {
            "status": "built",
            "mode": "offline-case-workspace",
            "root": str(self.root),
            "index": str(self.index),
            "trace": str(self.trace),
            "capsule": str(self.capsule),
            "reconstruction": str(self.reconstruction),
            "timeline": str(self.timeline),
            "replayClip": str(self.replay_clip),
            "evidence": str(self.evidence),
            "snapshot": str(self.snapshot),
            "contributionPreview": str(self.contribution_preview),
            "traceId": self.trace_id,
            "capsuleId": self.capsule_id,
            "eventCount": self.event_count,
            "classification": self.classification,
            "targetExecuted": False,
            "networkUsed": False,
            "publicationPerformed": False,
        }


def _write_json(path: Path, document: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(document) + b"\n")


def _validate_input(path: Path, *, role: str, suffix: str) -> Path:
    if path.is_symlink() or not path.is_file() or not path.name.endswith(suffix):
        raise FormatError(
            "SOVA-CASE-INPUT",
            f"{role} must be a regular {suffix} file and not a symbolic link",
        )
    return path.resolve()


def _validate_metadata(  # noqa: PLR0913 - independent disclosure gates remain explicit
    *,
    title: str,
    classification: str,
    component: str,
    component_version: str,
    disclosure_cleared: bool,
    reviewed_for_export: bool,
    trace_reviewed_for_export: bool,
) -> None:
    if not title.strip() or len(title) > _MAX_TITLE_LENGTH:
        raise FormatError("SOVA-CASE-TITLE", "case title must contain 1 to 240 characters")
    if classification not in _FINDING_CLASSES:
        raise FormatError("SOVA-CASE-CLASS", "unsupported case classification")
    if not component.strip() or not component_version.strip():
        raise FormatError("SOVA-CASE-COMPONENT", "component name and version are required")
    if classification == "real-disclosed-finding" and not (
        disclosure_cleared and reviewed_for_export and trace_reviewed_for_export
    ):
        raise FormatError(
            "SOVA-CASE-DISCLOSURE",
            "a real disclosed finding requires disclosure clearance, explicit export review, "
            "and a trace recorded as reviewed for export",
        )


def _verify_linked_artifacts(trace: Path, capsule: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    trace_verification = verify_artifact(trace, require_signature=True)
    if trace_verification.state != VerificationState.VERIFIED:
        raise FormatError(
            "SOVA-CASE-TRACE-VERIFY",
            "case construction requires a complete, signed, fully verified trace",
            details={"state": trace_verification.state.value},
        )
    capsule_verification = verify_artifact(capsule)
    if capsule_verification.state != VerificationState.VERIFIED:
        raise FormatError(
            "SOVA-CASE-CAPSULE-VERIFY",
            "case construction requires a fully verified capsule",
            details={"state": capsule_verification.state.value},
        )
    trace_digest = sha256_digest(trace.read_bytes())
    capsule_reader = PackageReader(capsule)
    descriptors = capsule_reader.verify("sova.capsule")
    if not any(item.role == "trace" and item.digest == trace_digest for item in descriptors):
        raise FormatError(
            "SOVA-CASE-TRACE-LINK",
            "the capsule does not contain the exact supplied trace bytes",
        )
    trace_reader = TraceReader(trace)
    trace_report = trace_reader.verify(require_signature=True)
    trace_manifest = trace_reader.manifest()
    if (
        trace_report.completion != "completed"
        or trace_manifest["capturePolicy"]["droppedEventCount"]
    ):
        raise FormatError(
            "SOVA-CASE-INCOMPLETE",
            "default case construction refuses incomplete or lossy traces",
        )
    return trace_manifest, capsule_reader.manifest("sova.capsule")


def _sample_replay_frames(events: list[dict[str, Any]]) -> tuple[ReplayFrame, ...]:
    if not events:
        raise FormatError("SOVA-CASE-EMPTY", "case trace contains no observable events")
    if len(events) <= _MAX_REPLAY_EVENTS:
        selected = events
    else:
        indexes = sorted(
            {
                round(index * (len(events) - 1) / (_MAX_REPLAY_EVENTS - 1))
                for index in range(_MAX_REPLAY_EVENTS)
            }
        )
        selected = [events[index] for index in indexes]
    return tuple(
        ReplayFrame(str(event["kind"]), f"SEQUENCE {int(event['sequence']):06d}")
        for event in selected
    )


def _snapshot_document(
    *,
    trace_manifest: dict[str, Any],
    capsule_manifest: dict[str, Any],
    events: list[dict[str, Any]],
    trace_reference: str,
    classification: str,
) -> dict[str, Any]:
    fingerprints = trace_manifest["fingerprints"]
    event_counts = dict(sorted(Counter(str(event["kind"]) for event in events).items()))
    authorization = trace_manifest["authorization"]
    executor = trace_manifest["executor"]
    snapshot = build_behavior_snapshot(
        {
            "id": f"sova:case-snapshot:{trace_manifest['id'].split(':')[-1]}",
            "traceReference": trace_reference,
            "target": fingerprints["target"],
            "model": fingerprints["model"],
            "toolSchemas": {"executorCapabilityDigest": executor["capabilityDigest"]},
            "permissions": {
                "decision": authorization["decision"],
                "scopeDigest": authorization["scopeDigest"],
            },
            "dependencies": fingerprints["dependencies"],
            "environment": fingerprints["environment"],
            "registrySnapshot": fingerprints["registry"],
            "approvalSurface": {"decidedBy": authorization["decidedBy"]},
            "observedEffects": {
                "eventCount": len(events),
                "eventKindCounts": event_counts,
                "completion": trace_manifest["completion"],
                "chainRoot": trace_manifest["chainRoot"],
            },
            "reproductionRates": {"status": "not-assessed-in-case-workspace"},
            "findings": {"classification": classification, "verdict": "not-inferred"},
            "methodology": capsule_manifest["methodology"],
            "captureProfile": {"name": trace_manifest["captureProfile"]},
            "taxonomy": capsule_manifest["taxonomy"],
        }
    )
    return snapshot.to_mapping()


def _evidence_document(  # noqa: PLR0913 - evidence provenance is intentionally explicit
    *,
    trace_manifest: dict[str, Any],
    capsule_manifest: dict[str, Any],
    trace_digest: str,
    capsule_digest: str,
    title: str,
    component: str,
    component_version: str,
    event_count: int,
) -> tuple[Any, dict[str, Any]]:
    methodology = capsule_manifest["methodology"]
    bundle = build_evidence_bundle(
        {
            "finding": {
                "id": f"SOVA-CASE-{trace_manifest['id'].split(':')[-1]}",
                "title": title.strip(),
                "summary": (
                    "A local SOVA case workspace records and indexes one declared observable "
                    "AI-system behavior without inferring universal safety or hidden reasoning."
                ),
                "affected": {
                    "component": component.strip(),
                    "version": component_version.strip(),
                    "identifiers": [capsule_manifest["id"], trace_manifest["id"]],
                },
                "technicalSeverity": "informational",
                "harmCategory": "behavioral-observation",
            },
            "evidence": [
                {
                    "role": "capsule",
                    "uri": "artifacts/evidence.sova",
                    "digest": capsule_digest,
                    "mediaType": "application/vnd.sova.capsule+zip",
                    "verified": True,
                },
                {
                    "role": "trace",
                    "uri": "artifacts/run.sova-trace",
                    "digest": trace_digest,
                    "mediaType": "application/vnd.sova.trace+zip",
                    "verified": True,
                },
            ],
            "conditionsTested": [
                "The attached capsule declares the tested procedure and environment references."
            ],
            "coverage": {
                "testedCount": event_count,
                "denominator": None,
                "detectionFloor": (
                    "One recorded run was indexed; unobserved behavior is outside this claim."
                ),
            },
            "reproduction": {
                "status": "not-assessed-in-case-workspace",
                "tracePlaybackAvailable": True,
                "controlledReexecutionPerformed": False,
                "semanticReproductionPerformed": False,
            },
            "taxonomyMappings": [],
            "methodology": {
                "id": str(methodology["id"]),
                "version": str(methodology["version"]),
                "digest": str(methodology["digest"]),
            },
            "suggestedMitigations": [],
            "regressionEvidence": [],
            "attachments": [],
            "limitations": [
                "This workspace is self-generated evidence, not independent attestation.",
                "Playback visualizes recorded observations and never re-executes actions.",
                "The recorder may be incomplete or dishonest despite valid integrity checks.",
                "No claim is made about private chain-of-thought or unobserved system state.",
            ],
            "lifecycle": {"state": "draft", "supersedes": None},
        }
    )
    document = bundle.to_mapping()
    validate_document(document, "sova.evidence")
    return bundle, document


def _artifact_entry(root: Path, path: Path, media_type: str) -> dict[str, Any]:
    return {
        "path": path.relative_to(root).as_posix(),
        "mediaType": media_type,
        "digest": sha256_digest(path.read_bytes()),
        "size": path.stat().st_size,
    }


def _require_verified_copy(path: Path, expected_digest: str) -> None:
    if sha256_digest(path.read_bytes()) != expected_digest:
        raise FormatError("SOVA-CASE-COPY", "artifact copy verification failed")


def _require_blocked_preview(preview: dict[str, Any]) -> None:
    if preview["acceptedForLocalStaging"] or preview["uploadPerformed"]:
        raise FormatError("SOVA-CASE-CONTRIBUTE", "review-first contribution gate failed")


def build_case_workspace(  # noqa: PLR0913, PLR0915
    trace: Path,
    capsule: Path,
    destination: Path,
    *,
    title: str = "SOVA behavior case",
    classification: str = "bundled-target",
    component: str = "operator-controlled target",
    component_version: str = "not-recorded",
    disclosure_cleared: bool = False,
    reviewed_for_export: bool = False,
) -> CaseWorkspaceArtifacts:
    """Create a complete offline case workspace without target execution or publication."""
    trace = _validate_input(trace, role="trace", suffix=".sova-trace")
    capsule = _validate_input(capsule, role="capsule", suffix=".sova")
    destination = destination.resolve()
    if destination.exists() or destination.is_symlink():
        raise FormatError("SOVA-CASE-DESTINATION", "case destination must not already exist")
    destination.parent.mkdir(parents=True, exist_ok=True)

    trace_manifest, capsule_manifest = _verify_linked_artifacts(trace, capsule)
    _validate_metadata(
        title=title,
        classification=classification,
        component=component,
        component_version=component_version,
        disclosure_cleared=disclosure_cleared,
        reviewed_for_export=reviewed_for_export,
        trace_reviewed_for_export=bool(trace_manifest["redactionPolicy"]["reviewedForExport"]),
    )
    trace_reader = TraceReader(trace)
    events = trace_reader.events()
    trace_digest = sha256_digest(trace.read_bytes())
    capsule_digest = sha256_digest(capsule.read_bytes())

    temporary = Path(tempfile.mkdtemp(prefix=".sova-case-", dir=destination.parent))
    try:
        artifact_dir = temporary / "artifacts"
        forensic_dir = temporary / "forensics"
        replay_dir = temporary / "replay"
        evidence_dir = temporary / "evidence"
        monitoring_dir = temporary / "monitoring"
        community_dir = temporary / "community"
        for directory in (
            artifact_dir,
            forensic_dir,
            replay_dir,
            evidence_dir,
            monitoring_dir,
            community_dir,
        ):
            directory.mkdir(parents=True)

        trace_copy = artifact_dir / "run.sova-trace"
        capsule_copy = artifact_dir / "evidence.sova"
        trace_copy.write_bytes(trace.read_bytes())
        capsule_copy.write_bytes(capsule.read_bytes())
        _require_verified_copy(trace_copy, trace_digest)
        _require_verified_copy(capsule_copy, capsule_digest)

        verification_path = artifact_dir / "verification.json"
        _write_json(
            verification_path,
            {
                "artifactType": "sova.case-verification",
                "schemaVersion": "0.1.0",
                "trace": verify_artifact(trace_copy, require_signature=True).to_mapping(),
                "capsule": verify_artifact(capsule_copy).to_mapping(),
                "exactTraceEmbeddedInCapsule": True,
                "offline": True,
            },
        )
        disclosure_path = artifact_dir / "selective-disclosure.json"
        _write_json(
            disclosure_path,
            trace_reader.disclosure_view(include_payload=False),
        )

        reconstruction_path = forensic_dir / "reconstruction.json"
        reconstruction = reconstruct_trace(trace_copy).to_mapping()
        validate_document(reconstruction, "sova.forensic-reconstruction")
        _write_json(reconstruction_path, reconstruction)

        timeline_path = replay_dir / "timeline.html"
        render_timeline_html(trace_copy, timeline_path)
        replay_path = replay_dir / "replay.y4m"
        render_replay_clip(
            ReplayClipSpec(
                classification,
                "../artifacts/evidence.sova",
                "../artifacts/verification.json",
                _sample_replay_frames(events),
                component_name=component.strip() if disclosure_cleared else None,
                disclosure_cleared=disclosure_cleared,
            ),
            replay_path,
        )

        evidence_path = evidence_dir / "evidence.json"
        bundle, evidence_document = _evidence_document(
            trace_manifest=trace_manifest,
            capsule_manifest=capsule_manifest,
            trace_digest=trace_digest,
            capsule_digest=capsule_digest,
            title=title,
            component=component,
            component_version=component_version,
            event_count=len(events),
        )
        _write_json(evidence_path, evidence_document)
        _write_json(evidence_dir / "evidence.sarif.json", evidence_to_sarif(bundle))
        for audience in _REPORT_AUDIENCES:
            (evidence_dir / f"{audience}.md").write_text(
                render_evidence_report(bundle, audience=audience),
                encoding="utf-8",
                newline="\n",
            )

        snapshot_path = monitoring_dir / "behavior-snapshot.json"
        _write_json(
            snapshot_path,
            _snapshot_document(
                trace_manifest=trace_manifest,
                capsule_manifest=capsule_manifest,
                events=events,
                trace_reference="../artifacts/run.sova-trace",
                classification=classification,
            ),
        )

        contribution_template = {
            "items": ["artifacts/evidence.sova", "evidence/evidence.json"],
            "contributor": {"name": "REVIEW REQUIRED", "identity": "REVIEW REQUIRED"},
            "license": "Apache-2.0",
            "gates": {
                "humanReviewed": False,
                "publicDisclosureAllowed": False,
                "authorizationRedacted": False,
                "provenanceComplete": False,
                "separateCorpusReuseConsent": False,
            },
        }
        contribution_template_path = community_dir / "contribution-template.json"
        _write_json(contribution_template_path, contribution_template)
        contribution_preview_path = community_dir / "contribution-preview.json"
        preview_spec = {
            **contribution_template,
            "items": [str(capsule_copy), str(evidence_path)],
        }
        preview = preview_contribution(preview_spec)
        _require_blocked_preview(preview)
        _write_json(contribution_preview_path, preview)

        artifact_paths = (
            (trace_copy, "application/vnd.sova.trace+zip"),
            (capsule_copy, "application/vnd.sova.capsule+zip"),
            (verification_path, "application/json"),
            (disclosure_path, "application/json"),
            (reconstruction_path, "application/json"),
            (timeline_path, "text/html"),
            (replay_path, "video/x-yuv4mpeg"),
            (replay_path.with_suffix(".y4m.json"), "application/json"),
            (evidence_path, "application/json"),
            (evidence_dir / "evidence.sarif.json", "application/sarif+json"),
            *((evidence_dir / f"{audience}.md", "text/markdown") for audience in _REPORT_AUDIENCES),
            (snapshot_path, "application/json"),
            (contribution_template_path, "application/json"),
            (contribution_preview_path, "application/json"),
        )
        index_path = temporary / "case.json"
        _write_json(
            index_path,
            {
                "artifactType": "sova.case-workspace",
                "schemaVersion": "0.1.0",
                "id": f"sova:case:{trace_digest[7:23]}",
                "title": title.strip(),
                "classification": classification,
                "source": {
                    "traceId": trace_manifest["id"],
                    "traceDigest": trace_digest,
                    "capsuleId": capsule_manifest["id"],
                    "capsuleDigest": capsule_digest,
                    "exactTraceEmbeddedInCapsule": True,
                },
                "review": {
                    "traceRecordedAsReviewedForExport": trace_manifest["redactionPolicy"][
                        "reviewedForExport"
                    ],
                    "operatorDeclaredExportReview": reviewed_for_export,
                    "disclosureCleared": disclosure_cleared,
                    "contributionGatesAutomaticallyCleared": False,
                },
                "operations": {
                    "tracePlayback": True,
                    "controlledReexecution": False,
                    "semanticReproduction": False,
                    "targetExecuted": False,
                    "networkUsed": False,
                    "uploadPerformed": False,
                },
                "artifacts": [
                    _artifact_entry(temporary, path, media_type)
                    for path, media_type in artifact_paths
                ],
                "limitations": [
                    "This is a local review workspace, not certification or attestation.",
                    (
                        "The HTML timeline contains already-redacted recorded payloads and "
                        "remains local-only."
                    ),
                    "The Y4M clip contains metadata captions only and no event payloads.",
                    (
                        "Contribution remains blocked until a separate human review completes "
                        "every gate."
                    ),
                    (
                        "No action was re-executed and no network was used while building this "
                        "workspace."
                    ),
                ],
            },
        )
        temporary.replace(destination)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise

    return CaseWorkspaceArtifacts(
        destination,
        destination / "case.json",
        destination / "artifacts" / "run.sova-trace",
        destination / "artifacts" / "evidence.sova",
        destination / "forensics" / "reconstruction.json",
        destination / "replay" / "timeline.html",
        destination / "replay" / "replay.y4m",
        destination / "evidence" / "evidence.json",
        destination / "monitoring" / "behavior-snapshot.json",
        destination / "community" / "contribution-preview.json",
        str(trace_manifest["id"]),
        str(capsule_manifest["id"]),
        len(events),
        classification,
    )


__all__ = ["CaseWorkspaceArtifacts", "build_case_workspace"]
