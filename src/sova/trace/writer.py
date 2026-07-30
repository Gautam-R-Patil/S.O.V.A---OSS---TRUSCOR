# SPDX-License-Identifier: Apache-2.0
"""Streaming, chunked, crash-explicit `.sova-trace` writer."""

from __future__ import annotations

import os
import platform
import shutil
from contextlib import suppress
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic_ns
from typing import IO, TYPE_CHECKING, Any, Self

from sova import __version__
from sova.contracts.identifiers import IdentifierKind, new_stable_identifier
from sova.formats import (
    ContentDescriptor,
    PackageWriter,
    canonical_json_bytes,
    sha256_digest,
    strict_json_loads,
    validate_document,
)
from sova.formats.errors import FormatError
from sova.trace.integrity import (
    Ed25519Keypair,
    event_hash,
    sign_trace_manifest,
    unsigned_manifest_digest,
)
from sova.trace.kinds import EVENT_REGISTRY_VERSION, event_registry_digest, validate_event_kind
from sova.trace.redaction import RedactionPolicy, Redactor

if TYPE_CHECKING:
    from pathlib import Path
    from types import TracebackType

_COMPLETIONS = {"completed", "failed", "cancelled", "timeout", "crashed", "partial", "recovered"}
_CONTENT_CAPTURE = {"full", "metadata-only"}
_DURABILITY = {"lite", "standard", "forensic"}
_MIN_SEGMENT_BYTES = 1024
_MAX_SEGMENT_BYTES = 64 * 1024 * 1024
_PROFILE_ALLOWED_PREFIXES = {
    "lite": {
        "run.",
        "attempt.",
        "prompt.",
        "model.",
        "tool.",
        "approval.",
        "oracle.",
        "authorization.",
        "safety.",
        "blocked.",
        "stop.",
        "artifact.",
        "error.",
    },
    "standard": None,
    "forensic": None,
    "interpretability": None,
}


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class TraceWriter:
    """Write events durably before creating a final immutable trace package."""

    def __init__(  # noqa: PLR0913 - explicit capture policy is safer than hidden globals
        self,
        destination: Path,
        *,
        run_id: str | None = None,
        capture_profile: str = "standard",
        segment_events: int = 1000,
        segment_bytes: int = 4 * 1024 * 1024,
        content_capture: str = "full",
        durability: str = "standard",
        redaction_policy: RedactionPolicy | None = None,
        signing_key: Ed25519Keypair | None = None,
        verification_material: dict[str, Any] | None = None,
        authorization: dict[str, Any] | None = None,
        environment: dict[str, Any] | None = None,
        executor: dict[str, Any] | None = None,
        fingerprints: dict[str, Any] | None = None,
        retention: dict[str, Any] | None = None,
        reviewed_for_export: bool = False,
    ) -> None:
        if capture_profile not in _PROFILE_ALLOWED_PREFIXES:
            raise FormatError("SOVA-TRACE-PROFILE", "unsupported capture profile")
        if segment_events < 1:
            raise FormatError("SOVA-TRACE-SEGMENT-SIZE", "segment_events must be positive")
        if not _MIN_SEGMENT_BYTES <= segment_bytes <= _MAX_SEGMENT_BYTES:
            raise FormatError(
                "SOVA-TRACE-SEGMENT-BYTES",
                "segment_bytes must be between 1 KiB and 64 MiB",
            )
        if content_capture not in _CONTENT_CAPTURE:
            raise FormatError("SOVA-TRACE-CONTENT-CAPTURE", "unsupported content-capture mode")
        if durability not in _DURABILITY:
            raise FormatError("SOVA-TRACE-DURABILITY", "unsupported durability mode")
        self.destination = destination.resolve()
        self.run_id = run_id or str(new_stable_identifier(IdentifierKind.RUN))
        self.trace_id = str(new_stable_identifier(IdentifierKind.TRACE))
        self.capture_profile = capture_profile
        self.segment_events = segment_events
        self.segment_bytes = segment_bytes
        self.content_capture = content_capture
        self.durability = durability
        self.redactor = Redactor(redaction_policy, context_id=self.trace_id)
        self.signing_key = signing_key
        if verification_material is not None and signing_key is None:
            raise FormatError(
                "SOVA-INTEGRITY-VERIFICATION-MATERIAL",
                "timestamp or transparency material requires a bound signature",
            )
        self.verification_material = verification_material
        self.reviewed_for_export = reviewed_for_export
        self.authorization = authorization or {
            "decision": "unknown",
            "scopeDigest": None,
            "decidedBy": "not-recorded",
        }
        self.environment = environment or {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "codeDigest": None,
            "model": None,
            "dependencies": [],
        }
        self.executor = executor or {
            "id": "sova:executor:unknown",
            "name": "not-recorded",
            "version": "unknown",
            "capabilityDigest": None,
        }
        absent_fingerprint = {
            "value": None,
            "status": "not-recorded",
            "method": "not-recorded",
            "source": "recorder",
            "version": "0.1.0",
        }
        self.fingerprints = fingerprints or {
            name: dict(absent_fingerprint)
            for name in (
                "environment",
                "target",
                "code",
                "dependencies",
                "registry",
                "model",
            )
        }
        self.retention = retention or {
            "policy": "operator-controlled",
            "expiresAt": None,
            "autoDelete": False,
        }
        self.created_at = _now()
        self._sequence = 0
        self._dropped_event_count = 0
        self._previous_hash: str | None = None
        self._segment_paths: list[Path] = []
        self._blob_paths: dict[str, Path] = {}
        self._handle: IO[bytes] | None = None
        self._segment_bytes_written = 0
        self._closed = False
        self._staging = self.destination.with_name(f".{self.destination.name}.partial")
        if self._staging.exists():
            raise FormatError(
                "SOVA-TRACE-STAGING-EXISTS",
                "trace staging directory already exists; recover or remove it explicitly",
            )
        (self._staging / "events").mkdir(parents=True)
        (self._staging / "blobs" / "sha256").mkdir(parents=True)
        self._write_session_metadata()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        _exception: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        if self._closed:
            return
        completion = "crashed" if exception_type is not None else "completed"
        with suppress(Exception):
            self.finalize(completion=completion)

    @property
    def event_count(self) -> int:
        """Return the number of persisted events."""
        return self._sequence

    def _should_capture(self, kind: str) -> bool:
        allowed = _PROFILE_ALLOWED_PREFIXES[self.capture_profile]
        return allowed is None or any(kind.startswith(prefix) for prefix in allowed)

    def _write_session_metadata(self) -> None:
        metadata = {
            "artifactType": "sova.trace-recovery-session",
            "schemaVersion": "0.1.0",
            "traceId": self.trace_id,
            "runId": self.run_id,
            "createdAt": self.created_at,
            "captureProfile": self.capture_profile,
            "contentCapture": self.content_capture,
            "durability": self.durability,
            "authorization": self.authorization,
            "environment": self.environment,
            "executor": self.executor,
            "fingerprints": self.fingerprints,
            "retention": self.retention,
            "redactionPolicy": {
                "name": self.redactor.policy.name,
                "version": self.redactor.policy.version,
                "rawEnvironmentCaptured": False,
                "reviewedForExport": self.reviewed_for_export,
            },
        }
        destination = self._staging / "session.json"
        temporary = self._staging / ".session.json.tmp"
        with temporary.open("wb") as handle:
            handle.write(canonical_json_bytes(metadata))
            handle.flush()
            if self.durability in {"standard", "forensic"}:
                os.fsync(handle.fileno())
        temporary.replace(destination)

    def _open_segment(self) -> None:
        if self._handle is not None:
            self._handle.flush()
            if self.durability in {"standard", "forensic"}:
                os.fsync(self._handle.fileno())
            self._handle.close()
        path = self._staging / "events" / f"{len(self._segment_paths):06d}.jsonl"
        self._segment_paths.append(path)
        self._handle = path.open("xb")
        self._segment_bytes_written = 0

    def append(  # noqa: PLR0913 - event context must be explicit
        self,
        kind: str,
        payload: dict[str, Any],
        *,
        phase: str = "run",
        actor: dict[str, str] | None = None,
        target: dict[str, str] | None = None,
        parents: list[str] | None = None,
        attempt: str | None = None,
        wall_time: str | None = None,
        monotonic_time_ns: int | None = None,
        clock_skew_estimate_ns: int | None = None,
        observed_time: str | None = None,
        clock_domain: str = "local-recorder",
        producer: dict[str, str] | None = None,
        links: list[dict[str, Any]] | None = None,
    ) -> str | None:
        """Redact, hash-chain, validate, and durably append one event."""
        if self._closed:
            raise FormatError("SOVA-TRACE-CLOSED", "cannot append to a finalized trace")
        validate_event_kind(kind)
        if not self._should_capture(kind):
            self._dropped_event_count += 1
            return None
        if self.content_capture == "metadata-only":
            redacted_payload = {
                "$redacted": {
                    "class": "event-content",
                    "method": "omitted",
                    "present": True,
                    "encoding": "sova-canonical-json/0.1",
                }
            }
            redactions = [
                {"path": "$", "class": "event-content", "method": "omitted"}
            ]
        else:
            redacted_payload, redactions = self.redactor.redact(payload)
        event: dict[str, Any] = {
            "artifactType": "sova.event",
            "schemaVersion": "0.1.0",
            "id": str(new_stable_identifier(IdentifierKind.EVENT)),
            "runId": self.run_id,
            "sequence": self._sequence,
            "kind": kind,
            "phase": phase,
            "actor": actor or {"id": "sova:actor:recorder", "kind": "recorder", "name": "SOVA"},
            "target": target or {"id": "sova:target:unknown", "kind": "target", "name": "unknown"},
            "producer": producer
            or {"id": "sova:actor:recorder", "kind": "recorder", "name": "SOVA"},
            "wallTime": wall_time or _now(),
            "observedTime": observed_time,
            "monotonicNs": monotonic_time_ns if monotonic_time_ns is not None else monotonic_ns(),
            "clock": {
                "source": "system",
                "precision": "nanosecond-reported",
                "skewEstimateNs": clock_skew_estimate_ns,
                "trusted": False,
            },
            "clockDomain": clock_domain,
            "parents": parents or [],
            "links": links or [],
            "attempt": attempt,
            "payload": redacted_payload,
            "redactions": redactions,
            "previousHash": self._previous_hash,
        }
        event["eventHash"] = event_hash(event)
        validate_document(event, "sova.event")
        encoded = canonical_json_bytes(event) + b"\n"
        if (
            self._handle is None
            or self._sequence % self.segment_events == 0
            or (
                self._segment_bytes_written > 0
                and self._segment_bytes_written + len(encoded) > self.segment_bytes
            )
        ):
            self._open_segment()
        if self._handle is None:
            raise FormatError("SOVA-TRACE-SEGMENT", "event segment is not open")
        self._handle.write(encoded)
        self._segment_bytes_written += len(encoded)
        if self.durability in {"standard", "forensic"}:
            self._handle.flush()
        if self.durability == "forensic":
            os.fsync(self._handle.fileno())
        self._previous_hash = event["eventHash"]
        self._sequence += 1
        return str(event["id"])

    def add_blob(self, data: bytes) -> ContentDescriptor:
        """Persist one content-addressed opaque blob, deduplicating exact bytes."""
        if self._closed:
            raise FormatError("SOVA-TRACE-CLOSED", "cannot add a blob to a finalized trace")
        digest = sha256_digest(data)
        hex_digest = digest[7:]
        path = self._staging / "blobs" / "sha256" / hex_digest
        if digest not in self._blob_paths:
            with path.open("xb") as handle:
                handle.write(data)
                if self.durability in {"standard", "forensic"}:
                    handle.flush()
                    os.fsync(handle.fileno())
            self._blob_paths[digest] = path
        return ContentDescriptor(
            role="blob",
            path=f"blobs/sha256/{hex_digest}",
            mediaType="application/octet-stream",
            digest=digest,
            size=len(data),
        )

    def _close_segment(self) -> None:
        if self._handle is not None:
            self._handle.flush()
            if self.durability in {"standard", "forensic"}:
                os.fsync(self._handle.fileno())
            self._handle.close()
            self._handle = None

    def finalize(self, *, completion: str = "completed") -> str:
        """Seal the trace package, preserving non-success terminal states."""
        if self._closed:
            raise FormatError("SOVA-TRACE-CLOSED", "trace is already finalized")
        if completion not in _COMPLETIONS:
            raise FormatError("SOVA-TRACE-COMPLETION", "unsupported completion state")
        self._close_segment()
        object_data: list[tuple[ContentDescriptor, bytes]] = []
        segment_descriptors: list[ContentDescriptor] = []
        for path in self._segment_paths:
            data = path.read_bytes()
            descriptor = ContentDescriptor(
                role="event-segment",
                path=f"events/{path.name}",
                mediaType="application/vnd.sova.events+jsonl",
                digest=sha256_digest(data),
                size=len(data),
            )
            segment_descriptors.append(descriptor)
            object_data.append((descriptor, data))
        for digest, path in sorted(self._blob_paths.items()):
            data = path.read_bytes()
            descriptor = ContentDescriptor(
                role="blob",
                path=f"blobs/sha256/{digest[7:]}",
                mediaType="application/octet-stream",
                digest=digest,
                size=len(data),
            )
            object_data.append((descriptor, data))
        manifest: dict[str, Any] = {
            "artifactType": "sova.trace",
            "schemaVersion": "0.1.0",
            "id": self.trace_id,
            "runId": self.run_id,
            "createdAt": self.created_at,
            "completedAt": _now(),
            "completion": completion,
            "captureProfile": self.capture_profile,
            "contentCapture": self.content_capture,
            "durability": self.durability,
            "capturePolicy": {
                "includedFamilies": (
                    ["*"]
                    if _PROFILE_ALLOWED_PREFIXES[self.capture_profile] is None
                    else sorted(_PROFILE_ALLOWED_PREFIXES[self.capture_profile] or set())
                ),
                "omittedFamilies": (
                    []
                    if _PROFILE_ALLOWED_PREFIXES[self.capture_profile] is None
                    else ["all-unlisted-families"]
                ),
                "sampling": "none",
                "truncation": "bounded-segments-and-package-limits",
                "droppedEventCount": self._dropped_event_count,
                "dropReasons": (
                    []
                    if self._dropped_event_count == 0
                    else ["capture-profile-filter"]
                ),
            },
            "eventCount": self._sequence,
            "chainRoot": self._previous_hash,
            "segments": [asdict(item) for item in segment_descriptors],
            "environment": self.environment,
            "fingerprints": self.fingerprints,
            "eventRegistry": {
                "id": "sova.event-families",
                "version": EVENT_REGISTRY_VERSION,
                "digest": event_registry_digest(),
            },
            "recorder": {"name": "sova-oss", "version": __version__},
            "executor": self.executor,
            "redactionPolicy": {
                "name": self.redactor.policy.name,
                "version": self.redactor.policy.version,
                "rawEnvironmentCaptured": False,
                "reviewedForExport": self.reviewed_for_export,
            },
            "retention": self.retention,
            "authorization": self.authorization,
            "integrity": {
                "manifestDigest": None,
                "eventHashChain": "sha256-prev-v1",
                "signature": None,
            },
            "requiredFeatures": ["trace.core/0.1"],
            "optionalFeatures": [
                *([] if self.content_capture == "full" else ["trace.metadata-only/0.1"]),
                *([] if self.signing_key is None else ["trace.dsse/0.1"]),
                *(
                    []
                    if self.verification_material is None
                    else ["trace.external-verification-material/0.1"]
                ),
            ],
            "extensions": {},
        }
        initial_writer = PackageWriter(manifest)
        for descriptor, data in object_data:
            initial_writer.add_bytes(
                role=descriptor.role,
                path=descriptor.path,
                media_type=descriptor.mediaType,
                data=data,
            )
        complete_manifest = initial_writer.finalized_manifest()
        complete_manifest["integrity"]["manifestDigest"] = unsigned_manifest_digest(
            complete_manifest
        )
        if self.signing_key is not None:
            complete_manifest["integrity"]["signature"] = sign_trace_manifest(
                complete_manifest,
                self.signing_key,
                verification_material=self.verification_material,
            )
        complete_manifest.pop("objects")
        final_writer = PackageWriter(complete_manifest)
        for descriptor, data in object_data:
            final_writer.add_bytes(
                role=descriptor.role,
                path=descriptor.path,
                media_type=descriptor.mediaType,
                data=data,
            )
        digest = final_writer.write(self.destination)
        self._closed = True
        if self._staging.parent == self.destination.parent and self._staging.name.startswith("."):
            shutil.rmtree(self._staging)
        return digest


def recover_trace(  # noqa: PLR0912, PLR0915
    destination: Path,
    *,
    signing_key: Ed25519Keypair | None = None,
) -> str:
    """Recover complete durable records from a force-interrupted writer.

    Only a non-newline-terminated final record is discarded. Any other
    corruption fails visibly. The staging directory is retained for review.
    """
    destination = destination.resolve()
    if destination.exists():
        raise FormatError(
            "SOVA-TRACE-RECOVERY-DESTINATION",
            "recovery will not overwrite an existing trace",
        )
    staging = destination.with_name(f".{destination.name}.partial")
    session_path = staging / "session.json"
    if not session_path.is_file():
        raise FormatError(
            "SOVA-TRACE-RECOVERY-SESSION",
            "trace recovery session metadata is missing",
        )
    session = strict_json_loads(session_path.read_bytes())
    if not isinstance(session, dict) or session.get("artifactType") != (
        "sova.trace-recovery-session"
    ):
        raise FormatError(
            "SOVA-TRACE-RECOVERY-SESSION",
            "trace recovery session metadata is invalid",
        )
    event_count = 0
    previous_hash: str | None = None
    discarded_tail_bytes = 0
    object_data: list[tuple[ContentDescriptor, bytes]] = []
    segment_descriptors: list[ContentDescriptor] = []
    for path in sorted((staging / "events").glob("*.jsonl")):
        raw = path.read_bytes()
        complete_length = raw.rfind(b"\n") + 1
        if complete_length < len(raw):
            discarded_tail_bytes += len(raw) - complete_length
        data = raw[:complete_length]
        if not data:
            continue
        for raw_line in data.splitlines():
            event = strict_json_loads(raw_line)
            if not isinstance(event, dict):
                raise FormatError(
                    "SOVA-TRACE-RECOVERY-EVENT",
                    "recovered event root must be an object",
                )
            validate_document(event, "sova.event")
            if event["sequence"] != event_count or event["previousHash"] != previous_hash:
                raise FormatError(
                    "SOVA-TRACE-RECOVERY-CHAIN",
                    "recovered event order or chain link is invalid",
                )
            if event_hash(event) != event["eventHash"]:
                raise FormatError(
                    "SOVA-TRACE-RECOVERY-HASH",
                    "recovered event content does not match its hash",
                )
            event_count += 1
            previous_hash = event["eventHash"]
        descriptor = ContentDescriptor(
            role="event-segment",
            path=f"events/{path.name}",
            mediaType="application/vnd.sova.events+jsonl",
            digest=sha256_digest(data),
            size=len(data),
        )
        segment_descriptors.append(descriptor)
        object_data.append((descriptor, data))
    for path in sorted((staging / "blobs" / "sha256").glob("*")):
        if not path.is_file():
            continue
        data = path.read_bytes()
        digest = sha256_digest(data)
        if path.name != digest[7:]:
            raise FormatError(
                "SOVA-TRACE-RECOVERY-BLOB",
                "recovery blob name does not match its content digest",
            )
        object_data.append(
            (
                ContentDescriptor(
                    role="blob",
                    path=f"blobs/sha256/{path.name}",
                    mediaType="application/octet-stream",
                    digest=digest,
                    size=len(data),
                ),
                data,
            )
        )
    capture_profile = str(session["captureProfile"])
    allowed = _PROFILE_ALLOWED_PREFIXES.get(capture_profile)
    manifest: dict[str, Any] = {
        "artifactType": "sova.trace",
        "schemaVersion": "0.1.0",
        "id": session["traceId"],
        "runId": session["runId"],
        "createdAt": session["createdAt"],
        "completedAt": _now(),
        "completion": "recovered",
        "captureProfile": capture_profile,
        "contentCapture": session["contentCapture"],
        "durability": session["durability"],
        "capturePolicy": {
            "includedFamilies": ["*"] if allowed is None else sorted(allowed or set()),
            "omittedFamilies": [] if allowed is None else ["all-unlisted-families"],
            "sampling": "none",
            "truncation": "force-interruption-recovery",
            "droppedEventCount": 1 if discarded_tail_bytes else 0,
            "dropReasons": (
                [] if discarded_tail_bytes == 0 else ["incomplete-final-record"]
            ),
        },
        "eventCount": event_count,
        "chainRoot": previous_hash,
        "segments": [asdict(item) for item in segment_descriptors],
        "environment": session["environment"],
        "fingerprints": session["fingerprints"],
        "eventRegistry": {
            "id": "sova.event-families",
            "version": EVENT_REGISTRY_VERSION,
            "digest": event_registry_digest(),
        },
        "recorder": {"name": "sova-oss-recovery", "version": __version__},
        "executor": session["executor"],
        "redactionPolicy": session["redactionPolicy"],
        "retention": session["retention"],
        "authorization": session["authorization"],
        "integrity": {
            "manifestDigest": None,
            "eventHashChain": "sha256-prev-v1",
            "signature": None,
        },
        "requiredFeatures": ["trace.core/0.1"],
        "optionalFeatures": [
            "trace.recovery/0.1",
            *([] if signing_key is None else ["trace.dsse/0.1"]),
        ],
        "extensions": {
            "x-sova-recovery": {
                "discardedTailBytes": discarded_tail_bytes,
                "stagingRetained": True,
                "completenessClaim": "partial-observable-prefix-only",
            }
        },
    }
    initial_writer = PackageWriter(manifest)
    for descriptor, data in object_data:
        initial_writer.add_bytes(
            role=descriptor.role,
            path=descriptor.path,
            media_type=descriptor.mediaType,
            data=data,
        )
    complete_manifest = initial_writer.finalized_manifest()
    complete_manifest["integrity"]["manifestDigest"] = unsigned_manifest_digest(
        complete_manifest
    )
    if signing_key is not None:
        complete_manifest["integrity"]["signature"] = sign_trace_manifest(
            complete_manifest,
            signing_key,
        )
    complete_manifest.pop("objects")
    final_writer = PackageWriter(complete_manifest)
    for descriptor, data in object_data:
        final_writer.add_bytes(
            role=descriptor.role,
            path=descriptor.path,
            media_type=descriptor.mediaType,
            data=data,
        )
    return final_writer.write(destination)


__all__ = ["TraceWriter", "recover_trace"]
