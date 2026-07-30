# SPDX-License-Identifier: Apache-2.0
"""Pinned OpenTelemetry/OpenInference mapping with explicit fidelity loss."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

OTEL_SEMCONV_VERSION = "1.43.0"
OPENINFERENCE_SEMCONV_VERSION = "0.1.30"
OTEL_CORE_COMMIT = "89aae438b3b3b0a8dd33003c9d70592baf7dbd0d"
OTEL_GENAI_EXPERIMENTAL_COMMIT = "434c91dcc34ed038e3048c07720ddfed2c6bddfc"
W3C_TRACE_CONTEXT_VERSION = "00"

_KIND_TO_SPAN = {
    "prompt.": "LLM",
    "model.": "LLM",
    "tool.": "TOOL",
    "retrieval.": "RETRIEVER",
    "memory.": "MEMORY",
    "inter-agent.": "AGENT",
}


@dataclass(frozen=True, slots=True)
class FidelityReport:
    """Fields preserved, approximated, omitted, and unavailable in a mapping."""

    source: str
    source_version: str
    preserved: tuple[str, ...]
    approximated: tuple[str, ...]
    omitted: tuple[str, ...]
    unavailable: tuple[str, ...]

    @property
    def lossless(self) -> bool:
        return not self.approximated and not self.omitted and not self.unavailable


def _otel_identifier(value: str, *, length: int, domain: str) -> str:
    rendered = hashlib.sha256(f"sova-otel:{domain}:{value}".encode()).hexdigest()[:length]
    return rendered if int(rendered, 16) != 0 else ("0" * (length - 1) + "1")


def export_event(event: dict[str, Any]) -> tuple[dict[str, Any], FidelityReport]:
    """Export one SOVA event to a valid-ID OTel span projection."""
    span_kind = next(
        (value for prefix, value in _KIND_TO_SPAN.items() if event["kind"].startswith(prefix)),
        "CHAIN",
    )
    parents = list(event["parents"])
    exported: dict[str, Any] = {
        "name": event["kind"],
        "trace_id": _otel_identifier(event["runId"], length=32, domain="trace"),
        "span_id": _otel_identifier(event["id"], length=16, domain="span"),
        "parent_span_id": (
            _otel_identifier(parents[0], length=16, domain="span") if parents else None
        ),
        "links": [
            {
                "trace_id": _otel_identifier(event["runId"], length=32, domain="trace"),
                "span_id": _otel_identifier(parent, length=16, domain="span"),
                "attributes": {
                    "sova.causal_relation": "recorded-parent",
                    "sova.event.id": parent,
                },
            }
            for parent in parents[1:]
        ],
        "start_time": event["wallTime"],
        "attributes": {
            "openinference.span.kind": span_kind,
            "sova.event.id": event["id"],
            "sova.run.id": event["runId"],
            "sova.parent_event_ids": parents,
            "sova.schema_version": event["schemaVersion"],
            "sova.sequence": event["sequence"],
            "sova.phase": event["phase"],
            "sova.actor.id": event["actor"]["id"],
            "sova.target.id": event["target"]["id"],
            "sova.event_hash": event["eventHash"],
            "sova.payload": event["payload"],
        },
    }
    return exported, FidelityReport(
        source="sova.event",
        source_version=event["schemaVersion"],
        preserved=(
            "kind",
            "runId",
            "id",
            "parents",
            "wallTime",
            "sequence",
            "phase",
            "actor.id",
            "target.id",
            "payload",
            "eventHash",
        ),
        approximated=("causal parents mapped to span links/parents",),
        omitted=("monotonicNs", "clock", "redactions", "attempt", "previousHash"),
        unavailable=(),
    )


def import_span(span: dict[str, Any]) -> tuple[dict[str, Any], FidelityReport]:
    """Convert an OTel/OpenInference span into arguments for TraceWriter.append."""
    attributes = span.get("attributes", {})
    name = str(span.get("name", "x.otel.span"))
    if "." not in name:
        name = f"x.otel.{name.lower().replace(' ', '-')}"
    draft = {
        "kind": name,
        "phase": str(attributes.get("sova.phase", "import")),
        "payload": {
            "otel": {
                "name": span.get("name"),
                "status": span.get("status"),
                "attributes": attributes,
                "events": span.get("events", []),
            }
        },
        "actor": {
            "id": str(attributes.get("sova.actor.id", "external:otel:unknown")),
            "kind": "imported",
            "name": str(attributes.get("service.name", "OpenTelemetry producer")),
        },
        "target": {
            "id": str(attributes.get("sova.target.id", "external:target:unknown")),
            "kind": "target",
            "name": str(attributes.get("gen_ai.request.model", "unknown")),
        },
    }
    return draft, FidelityReport(
        source="opentelemetry.span",
        source_version=OTEL_SEMCONV_VERSION,
        preserved=("name", "status", "attributes", "events"),
        approximated=("actor", "target", "phase", "event kind"),
        omitted=(),
        unavailable=(
            "SOVA authorization decision",
            "SOVA safety policy",
            "monotonic ordering when absent",
            "capture-time redaction proof",
            "event hash chain",
        ),
    )


__all__ = [
    "OPENINFERENCE_SEMCONV_VERSION",
    "OTEL_CORE_COMMIT",
    "OTEL_GENAI_EXPERIMENTAL_COMMIT",
    "OTEL_SEMCONV_VERSION",
    "W3C_TRACE_CONTEXT_VERSION",
    "FidelityReport",
    "export_event",
    "import_span",
]
