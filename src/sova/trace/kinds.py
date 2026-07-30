# SPDX-License-Identifier: Apache-2.0
"""Versioned registry for the stable SOVA event-family vocabulary."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

EVENT_REGISTRY_VERSION = "0.1.0"


@dataclass(frozen=True, slots=True)
class EventFamily:
    """Privacy and interoperability policy shared by one event prefix."""

    prefix: str
    privacy_class: str
    lifecycle: str
    otel_projection: str
    lite: bool


_FAMILY_ROWS = (
    ("run.", "operational", "run", "span", True),
    ("phase.", "operational", "phase", "span", False),
    ("attempt.", "operational", "attempt", "span", True),
    ("actor.", "identity", "actor", "event", False),
    ("prompt.", "model-content", "request-response", "llm-span", True),
    ("model.", "model-content", "request-response", "llm-span", True),
    ("tool.", "tool-content", "request-approval-result", "tool-span", True),
    ("approval.", "authorization", "decision", "event", True),
    ("memory.", "sensitive-state", "read-write", "memory-span", False),
    ("retrieval.", "retrieved-content", "request-result", "retriever-span", False),
    ("mcp.", "tool-content", "request-response", "span", False),
    ("inter-agent.", "model-content", "send-receive", "agent-span", False),
    ("filesystem.", "host-state", "action-observation", "span", False),
    ("process.", "host-state", "action-observation", "span", False),
    ("environment.", "host-state", "observation", "event", False),
    ("database.", "data-content", "request-result", "span", False),
    ("api.", "network-content", "request-response", "span", False),
    ("network.", "network-content", "action-observation", "span", False),
    ("browser.", "screen-and-web-content", "action-observation", "span", False),
    ("computer.", "screen-and-input-content", "action-observation", "span", False),
    ("oracle.", "evaluation", "request-result", "span", True),
    ("judge.", "evaluation", "request-result", "span", False),
    ("finding.", "finding", "lifecycle", "event", False),
    ("attribution.", "evaluation", "analysis", "event", False),
    ("authorization.", "authorization", "decision", "event", True),
    ("safety.", "authorization", "decision", "event", True),
    ("blocked.", "authorization", "decision", "event", True),
    ("stop.", "authorization", "decision", "event", True),
    ("artifact.", "artifact-metadata", "lifecycle", "event", True),
    ("redaction.", "privacy-metadata", "lifecycle", "event", False),
    ("signature.", "integrity-metadata", "lifecycle", "event", False),
    ("verification.", "integrity-metadata", "lifecycle", "event", False),
    ("export.", "privacy-metadata", "lifecycle", "event", True),
    ("error.", "error-content", "failure", "event", True),
    ("recovery.", "integrity-metadata", "lifecycle", "event", False),
)

EVENT_FAMILIES = {
    row[0]: EventFamily(*row)
    for row in _FAMILY_ROWS
}


def event_registry_digest() -> str:
    """Return the digest of the serialized normative registry rows."""
    return sha256_digest(
        canonical_json_bytes(
            {
                "version": EVENT_REGISTRY_VERSION,
                "families": [asdict(EVENT_FAMILIES[prefix]) for prefix in EVENT_FAMILIES],
            }
        )
    )


def event_family(kind: str) -> EventFamily | None:
    """Resolve one kind to a registered family or an explicit extension."""
    if kind.startswith("x."):
        return None
    return next(
        (family for prefix, family in EVENT_FAMILIES.items() if kind.startswith(prefix)),
        None,
    )


def validate_event_kind(kind: str) -> None:
    """Reject unregistered native prefixes while allowing namespaced extensions."""
    if event_family(kind) is None and not kind.startswith("x."):
        raise FormatError(
            "SOVA-TRACE-EVENT-FAMILY",
            "native event kind does not belong to the pinned event-family registry",
            details={"kind": kind, "registryVersion": EVENT_REGISTRY_VERSION},
        )


__all__ = [
    "EVENT_FAMILIES",
    "EVENT_REGISTRY_VERSION",
    "EventFamily",
    "event_family",
    "event_registry_digest",
    "validate_event_kind",
]
