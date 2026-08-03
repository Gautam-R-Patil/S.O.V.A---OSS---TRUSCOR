# SPDX-License-Identifier: Apache-2.0
"""Uncertainty-aware reconstruction over native or normalized external events."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from heapq import heappop, heappush
from typing import TYPE_CHECKING, Any

from sova.forensics.model import ReconstructionReport, TimelineEntry
from sova.formats import sha256_digest
from sova.formats.errors import FormatError
from sova.trace import TraceReader

if TYPE_CHECKING:
    from pathlib import Path

_MAX_EVENTS = 100_000
_DECISION_PREFIXES = (
    "tool.request",
    "approval.",
    "authorization.",
    "model.response",
    "judge.",
    "oracle.",
    "inter-agent.",
    "memory.write",
    "retrieval.",
)


def _text(value: Any, *, fallback: str) -> str:
    return value if isinstance(value, str) and value else fallback


def _entity_name(value: Any, *, fallback: str) -> str:
    if isinstance(value, Mapping):
        return _text(value.get("name"), fallback=fallback)
    return fallback


def _redacted(event: Mapping[str, Any]) -> bool:
    payload = event.get("payload")
    return (
        bool(event.get("redactions"))
        or (isinstance(payload, Mapping) and "$redacted" in payload)
        or bool(event.get("payloadOmitted"))
    )


def _normalize_event(raw: Mapping[str, Any], index: int) -> dict[str, Any]:
    event_id = _text(raw.get("id"), fallback=f"external:event:{index:08d}")
    parents = raw.get("parents", ())
    if not isinstance(parents, Sequence) or isinstance(parents, (str, bytes)):
        raise FormatError("SOVA-FORENSICS-PARENTS", "event parents must be an array")
    sequence = raw.get("sequence", index)
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
        raise FormatError(
            "SOVA-FORENSICS-SEQUENCE", "event sequence must be a non-negative integer"
        )
    clock = raw.get("clock")
    trusted = clock.get("trusted") is True if isinstance(clock, Mapping) else False
    skew = clock.get("skewEstimateNs") if isinstance(clock, Mapping) else None
    monotonic = raw.get("monotonicNs")
    return {
        "id": event_id,
        "sequence": sequence,
        "kind": _text(raw.get("kind"), fallback="x.external.unknown"),
        "phase": _text(raw.get("phase"), fallback="unknown"),
        "actor": _entity_name(raw.get("actor"), fallback="unknown actor"),
        "target": _entity_name(raw.get("target"), fallback="unknown target"),
        "wallTime": raw.get("wallTime") if isinstance(raw.get("wallTime"), str) else None,
        "clockDomain": _text(raw.get("clockDomain"), fallback="external-unknown"),
        "clockTrusted": trusted,
        "clockSkew": skew if isinstance(skew, int) and not isinstance(skew, bool) else None,
        "monotonicNs": monotonic if isinstance(monotonic, int) and monotonic >= 0 else None,
        "parents": tuple(_text(parent, fallback="") for parent in parents if parent),
        "eventHash": raw.get("eventHash") if isinstance(raw.get("eventHash"), str) else None,
        "redacted": _redacted(raw),
    }


def reconstruct_events(  # noqa: PLR0912, PLR0913, PLR0915
    events: Sequence[Mapping[str, Any]],
    *,
    source_type: str,
    source_id: str,
    source_digest: str | None = None,
    integrity_state: str = "not-independently-verified",
    dropped_event_count: int = 0,
) -> ReconstructionReport:
    """Build a deterministic causal timeline while preserving order uncertainty."""
    if len(events) > _MAX_EVENTS:
        raise FormatError("SOVA-FORENSICS-EVENT-LIMIT", "forensic event limit exceeded")
    normalized = [_normalize_event(event, index) for index, event in enumerate(events)]
    by_id: dict[str, dict[str, Any]] = {}
    for event in normalized:
        if event["id"] in by_id:
            raise FormatError("SOVA-FORENSICS-DUPLICATE-ID", "event identity is duplicated")
        by_id[event["id"]] = event

    indegree = dict.fromkeys(by_id, 0)
    children: dict[str, list[str]] = defaultdict(list)
    missing_markers: list[str] = []
    causal_edges: list[tuple[str, str]] = []
    for event in normalized:
        for parent in event["parents"]:
            if parent not in by_id:
                missing_markers.append(f"missing causal parent {parent} for {event['id']}")
                continue
            indegree[event["id"]] += 1
            children[parent].append(event["id"])
            causal_edges.append((parent, event["id"]))

    ready: list[tuple[int, str]] = []
    for event_id, degree in indegree.items():
        if degree == 0:
            heappush(ready, (int(by_id[event_id]["sequence"]), event_id))
    ordered: list[dict[str, Any]] = []
    while ready:
        _sequence, event_id = heappop(ready)
        ordered.append(by_id[event_id])
        for child in sorted(children[event_id]):
            indegree[child] -= 1
            if indegree[child] == 0:
                heappush(ready, (int(by_id[child]["sequence"]), child))
    if len(ordered) != len(normalized):
        raise FormatError("SOVA-FORENSICS-CAUSAL-CYCLE", "event parent graph contains a cycle")

    entries: list[TimelineEntry] = []
    uncertain_pairs: list[tuple[str, str]] = []
    for index, event in enumerate(ordered):
        previous = ordered[index - 1] if index else None
        known_parents = tuple(parent for parent in event["parents"] if parent in by_id)
        if known_parents:
            order_basis = "declared-causal-link"
        elif event["parents"]:
            order_basis = "missing-causal-parent"
        elif (
            previous is not None
            and event["clockDomain"] == previous["clockDomain"]
            and event["monotonicNs"] is not None
            and previous["monotonicNs"] is not None
        ):
            order_basis = "local-monotonic-clock"
        elif previous is None:
            order_basis = "source-start"
        else:
            order_basis = "uncertain-cross-clock"
            uncertain_pairs.append((previous["id"], event["id"]))
        if not event["clockTrusted"] or event["clockSkew"] is None:
            missing_markers.append(f"untrusted or unbounded clock for {event['id']}")
        if event["redacted"]:
            missing_markers.append(f"redacted or omitted content for {event['id']}")
        statement = (
            f"Observed {event['kind']} by {event['actor']} targeting {event['target']} "
            f"during {event['phase']}."
        )
        entries.append(
            TimelineEntry(
                event_id=event["id"],
                sequence=int(event["sequence"]),
                kind=event["kind"],
                phase=event["phase"],
                actor=event["actor"],
                target=event["target"],
                wall_time=event["wallTime"],
                clock_domain=event["clockDomain"],
                order_basis=order_basis,
                decision_point=event["kind"].startswith(_DECISION_PREFIXES),
                missing_or_redacted=bool(event["redacted"]),
                parents=tuple(event["parents"]),
                evidence_digest=event["eventHash"],
                statement=statement,
            )
        )
    if dropped_event_count:
        missing_markers.append(f"recorder reported {dropped_event_count} dropped event(s)")
    return ReconstructionReport(
        source_type=source_type,
        source_id=source_id,
        source_digest=source_digest,
        integrity_state=integrity_state,
        entries=tuple(entries),
        causal_edges=tuple(sorted(causal_edges)),
        uncertain_order_pairs=tuple(uncertain_pairs),
        missing_sensor_markers=tuple(dict.fromkeys(missing_markers)),
        limitations=(
            "Reconstruction orders recorded observations; it does not recover hidden model "
            "reasoning.",
            "Cross-clock order remains uncertain without trusted synchronization or causal links.",
            "Missing or compromised sensors can change the interpretation.",
            "Evidence-linked statements are observations, not legal or organizational blame.",
        ),
    )


def reconstruct_trace(path: Path) -> ReconstructionReport:
    """Verify and reconstruct one native `.sova-trace` without executing it."""
    reader = TraceReader(path)
    verification = reader.verify()
    manifest = reader.manifest()
    return reconstruct_events(
        reader.events(),
        source_type="sova.trace",
        source_id=verification.trace_id,
        source_digest=sha256_digest(path.read_bytes()),
        integrity_state="verified-within-declared-trust-policy",
        dropped_event_count=int(manifest["capturePolicy"]["droppedEventCount"]),
    )


__all__ = ["reconstruct_events", "reconstruct_trace"]
