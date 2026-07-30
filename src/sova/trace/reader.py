# SPDX-License-Identifier: Apache-2.0
"""Offline inspection, indexed query, playback, and integrity verification."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sova.formats import PackageReader, strict_json_loads, validate_document
from sova.formats.errors import FormatError
from sova.trace.integrity import event_hash, unsigned_manifest_digest, verify_trace_signature
from sova.trace.redaction import RedactionVerifier

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


@dataclass(frozen=True, slots=True)
class VerificationReport:
    """Bounded offline verification result."""

    trace_id: str
    event_count: int
    completion: str
    package_integrity: bool
    event_chain_integrity: bool
    manifest_integrity: bool
    redaction_integrity: bool
    signature_present: bool
    signature_valid: bool
    verification_material_present: bool
    verification_material_verified: bool
    trust_policy: str
    limitations: tuple[str, ...]


class TraceReader:
    """Read a trace without executing recorded content or contacting a service."""

    def __init__(self, source: Path) -> None:
        self.package = PackageReader(source)
        self._events: list[dict[str, Any]] | None = None
        self._kind_index: dict[str, list[int]] = {}
        self._actor_index: dict[str, list[int]] = {}
        self._id_index: dict[str, int] = {}

    def manifest(self) -> dict[str, Any]:
        """Return the validated trace manifest."""
        return self.package.manifest("sova.trace")

    def events(self) -> list[dict[str, Any]]:
        """Load, validate, and index events in canonical local order."""
        if self._events is not None:
            return self._events
        descriptors = self.package.verify("sova.trace")
        self._kind_index.clear()
        self._actor_index.clear()
        self._id_index.clear()
        segments = sorted(
            (item for item in descriptors if item.role == "event-segment"),
            key=lambda item: item.path,
        )
        events: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        previous_hash: str | None = None
        for descriptor in segments:
            data = self.package.read_object(descriptor)
            for raw_line in data.splitlines():
                if not raw_line:
                    continue
                event = strict_json_loads(raw_line, max_bytes=8 * 1024 * 1024)
                if not isinstance(event, dict):
                    raise FormatError("SOVA-TRACE-EVENT-TYPE", "trace event must be an object")
                validate_document(event, "sova.event")
                if event["sequence"] != len(events):
                    raise FormatError(
                        "SOVA-TRACE-SEQUENCE",
                        "event sequence is missing, duplicated, or reordered",
                    )
                if event["id"] in seen_ids:
                    raise FormatError("SOVA-TRACE-DUPLICATE-ID", "event id is duplicated")
                if event["previousHash"] != previous_hash:
                    raise FormatError(
                        "SOVA-TRACE-CHAIN-LINK",
                        "event previousHash does not match the prior event",
                    )
                for parent in event["parents"]:
                    if parent not in seen_ids:
                        raise FormatError(
                            "SOVA-TRACE-CAUSAL-PARENT",
                            "event parent must reference an earlier event in this trace",
                        )
                if event_hash(event) != event["eventHash"]:
                    raise FormatError(
                        "SOVA-TRACE-EVENT-HASH",
                        "event content does not match its eventHash",
                    )
                RedactionVerifier().verify(event["payload"], event["redactions"])
                seen_ids.add(event["id"])
                previous_hash = event["eventHash"]
                self._kind_index.setdefault(event["kind"], []).append(len(events))
                self._actor_index.setdefault(event["actor"]["id"], []).append(len(events))
                self._id_index[event["id"]] = len(events)
                events.append(event)
        manifest = self.manifest()
        if manifest["eventCount"] != len(events) or manifest["chainRoot"] != previous_hash:
            raise FormatError(
                "SOVA-TRACE-MANIFEST-CHAIN",
                "manifest event count or chain root does not match the event stream",
            )
        self._events = events
        return events

    def verify(
        self,
        *,
        require_signature: bool = False,
        required_key_id: str | None = None,
    ) -> VerificationReport:
        """Verify package, event chain, manifest digest, and optional signature offline."""
        self.package.verify("sova.trace")
        events = self.events()
        manifest = self.manifest()
        expected_manifest_digest = unsigned_manifest_digest(manifest)
        if manifest["integrity"]["manifestDigest"] != expected_manifest_digest:
            raise FormatError(
                "SOVA-TRACE-MANIFEST-DIGEST",
                "trace manifest digest verification failed",
            )
        signature = manifest["integrity"]["signature"]
        if signature is None:
            if require_signature:
                raise FormatError(
                    "SOVA-INTEGRITY-SIGNATURE-REQUIRED",
                    "trust policy requires a signature but the trace is unsigned",
                )
            signature_valid = False
            trust_policy = "unsigned"
        else:
            trust_policy = verify_trace_signature(manifest)
            signature_valid = True
            if required_key_id is not None:
                actual = signature["publicKey"]["keyid"]
                if actual != required_key_id:
                    raise FormatError(
                        "SOVA-INTEGRITY-UNTRUSTED-SIGNER",
                        "signature is valid but does not match the required key",
                    )
                trust_policy = "required-key"
        verification_material_present = bool(
            isinstance(signature, dict) and signature.get("verificationMaterial") is not None
        )
        return VerificationReport(
            trace_id=manifest["id"],
            event_count=len(events),
            completion=manifest["completion"],
            package_integrity=True,
            event_chain_integrity=True,
            manifest_integrity=True,
            redaction_integrity=True,
            signature_present=signature is not None,
            signature_valid=signature_valid,
            verification_material_present=verification_material_present,
            verification_material_verified=False,
            trust_policy=trust_policy,
            limitations=(
                "Integrity does not prove that the recorder or observed system was honest.",
                (
                    "A valid included-key signature proves no external identity "
                    "without a trust policy."
                ),
                (
                    "Carried timestamp or transparency material is digest-bound but "
                    "requires an external pinned-root verifier."
                ),
                "The event chain is tamper-evident, not non-repudiable proof.",
            ),
        )

    def query(
        self,
        *,
        kind_prefix: str | None = None,
        actor_id: str | None = None,
        start_sequence: int = 0,
        stop_sequence: int | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Yield matching events using the in-memory sequence index."""
        events = self.events()
        stop = len(events) if stop_sequence is None else min(stop_sequence, len(events))
        candidates = set(range(max(0, start_sequence), max(0, stop)))
        if kind_prefix is not None:
            candidates &= {
                sequence
                for kind, sequences in self._kind_index.items()
                if kind.startswith(kind_prefix)
                for sequence in sequences
            }
        if actor_id is not None:
            candidates &= set(self._actor_index.get(actor_id, []))
        for sequence in sorted(candidates):
            yield events[sequence]

    def event(self, event_id: str) -> dict[str, Any] | None:
        """Return one event by stable identifier using the in-memory ID index."""
        events = self.events()
        sequence = self._id_index.get(event_id)
        return None if sequence is None else events[sequence]

    def playback(self) -> list[str]:
        """Produce an inert deterministic timeline; no action is re-executed."""
        return [
            f"{event['sequence']:06d} {event['wallTime']} {event['kind']} "
            f"{event['actor']['name']} -> {event['target']['name']}"
            for event in self.events()
        ]

    def disclosure_view(
        self,
        *,
        sequences: set[int] | None = None,
        include_payload: bool = False,
    ) -> dict[str, Any]:
        """Create an unsigned selective view with explicit omissions.

        This is a review artifact, not a cryptographic selective-disclosure
        proof and not a replacement for the source trace.
        """
        manifest = self.manifest()
        selected = [
            event
            for event in self.events()
            if sequences is None or event["sequence"] in sequences
        ]
        rendered_events: list[dict[str, Any]] = []
        for event in selected:
            value: dict[str, Any] = {
                "id": event["id"],
                "sequence": event["sequence"],
                "kind": event["kind"],
                "phase": event["phase"],
                "actor": event["actor"],
                "target": event["target"],
                "wallTime": event["wallTime"],
                "eventHash": event["eventHash"],
                "redactions": event["redactions"],
            }
            if include_payload:
                value["payload"] = event["payload"]
            else:
                value["payloadOmitted"] = True
            rendered_events.append(value)
        return {
            "artifactType": "sova.trace-disclosure-view",
            "sourceTraceId": manifest["id"],
            "sourceManifestDigest": manifest["integrity"]["manifestDigest"],
            "selectedEventCount": len(rendered_events),
            "omittedEventCount": manifest["eventCount"] - len(rendered_events),
            "payloadsIncluded": include_payload,
            "cryptographicSelectiveDisclosure": False,
            "events": rendered_events,
            "limitations": [
                "This unsigned view must be checked against the source trace.",
                "Omitted events may change interpretation.",
            ],
        }


__all__ = ["TraceReader", "VerificationReport"]
