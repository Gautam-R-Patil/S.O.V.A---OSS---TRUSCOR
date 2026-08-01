# SPDX-License-Identifier: Apache-2.0
"""Pinned OpenTelemetry/OpenInference mapping with explicit fidelity loss."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Literal

from sova.formats import strict_json_loads
from sova.formats.errors import FormatError
from sova.trace.kinds import event_family

OTEL_SEMCONV_VERSION = "1.43.0"
OPENINFERENCE_SEMCONV_VERSION = "0.1.30"
OPENINFERENCE_CORE_COMMIT = "789d41974c08a9a13147977f28ef4142a07e2106"
OTEL_CORE_COMMIT = "89aae438b3b3b0a8dd33003c9d70592baf7dbd0d"
OTEL_GENAI_EXPERIMENTAL_COMMIT = "434c91dcc34ed038e3048c07720ddfed2c6bddfc"
W3C_TRACE_CONTEXT_VERSION = "00"

_KIND_TO_SPAN = {
    "prompt.": "PROMPT",
    "model.": "LLM",
    "tool.": "TOOL",
    "retrieval.": "RETRIEVER",
    "inter-agent.": "AGENT",
    "oracle.": "EVALUATOR",
    "judge.": "EVALUATOR",
    "safety.": "GUARDRAIL",
    "mcp.": "TOOL",
    "filesystem.": "TOOL",
    "process.": "TOOL",
    "database.": "TOOL",
    "api.": "TOOL",
    "network.": "TOOL",
    "browser.": "TOOL",
    "computer.": "TOOL",
}

_OPENINFERENCE_KIND_TO_EVENT = {
    "LLM": "model.interaction",
    "EMBEDDING": "model.embedding",
    "CHAIN": "x.openinference.chain",
    "RETRIEVER": "retrieval.interaction",
    "RERANKER": "retrieval.reranking",
    "TOOL": "tool.interaction",
    "AGENT": "inter-agent.operation",
    "GUARDRAIL": "safety.guardrail",
    "EVALUATOR": "judge.evaluation",
    "PROMPT": "prompt.rendered",
    "UNKNOWN": "x.openinference.unknown",
}
_OPENINFERENCE_SPAN_KINDS = frozenset(_OPENINFERENCE_KIND_TO_EVENT)
_OPENINFERENCE_STRUCTURAL_FIELDS = (
    "trace_id",
    "traceId",
    "span_id",
    "spanId",
    "parent_span_id",
    "parentSpanId",
    "start_time",
    "startTimeUnixNano",
    "end_time",
    "endTimeUnixNano",
    "flags",
    "kind",
    "links",
)
_OPENINFERENCE_SENSITIVE_EXACT = frozenset(
    {
        "input.value",
        "output.value",
        "llm.invocation_parameters",
        "llm.input_messages",
        "llm.output_messages",
        "llm.prompts",
        "llm.choices",
        "llm.tools",
        "llm.prompt_template.template",
        "llm.prompt_template.variables",
        "metadata",
        "tool.description",
        "tool.json_schema",
        "tool.parameters",
        "embedding.invocation_parameters",
        "embedding.embeddings",
        "retrieval.documents",
        "sova.payload",
    }
)
_OPENINFERENCE_SENSITIVE_PREFIXES = (
    "llm.input_messages.",
    "llm.output_messages.",
    "llm.prompts.",
    "llm.choices.",
    "llm.tools.",
    "embedding.embeddings.",
    "retrieval.documents.",
    "reranker.input_documents.",
    "reranker.output_documents.",
    "exception.",
)


@dataclass(frozen=True, slots=True)
class FidelityReport:
    """Fields preserved, approximated, omitted, and unavailable in a mapping."""

    source: str
    source_version: str
    preserved: tuple[str, ...]
    approximated: tuple[str, ...]
    omitted: tuple[str, ...]
    unavailable: tuple[str, ...]
    sensitive: tuple[str, ...] = ()

    @property
    def lossless(self) -> bool:
        return not self.approximated and not self.omitted and not self.unavailable


def _otel_identifier(value: str, *, length: int, domain: str) -> str:
    rendered = hashlib.sha256(f"sova-otel:{domain}:{value}".encode()).hexdigest()[:length]
    return rendered if int(rendered, 16) != 0 else ("0" * (length - 1) + "1")


def _bounded_json_object(value: object, *, code: str) -> dict[str, Any]:
    """Return a bounded plain JSON object or fail with a stable error."""
    if not isinstance(value, dict):
        raise FormatError(code, "span must be a JSON object")
    pending: list[object] = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            if not all(isinstance(key, str) for key in current):
                raise FormatError(code, "span JSON object member names must be strings")
            pending.extend(current.values())
        elif isinstance(current, (list, tuple)):
            pending.extend(current)
    try:
        raw = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise FormatError(code, "span must contain only finite JSON values") from error
    parsed = strict_json_loads(raw)
    if not isinstance(parsed, dict):  # pragma: no cover - guarded by the input check
        raise FormatError(code, "span must be a JSON object")
    return parsed


def _attributes(value: object, *, path: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise FormatError(
            "SOVA-OTEL-ATTRIBUTES-TYPE",
            "span and resource attributes must be JSON objects with string keys",
            path=path,
        )
    return value


def _resource_attributes(span: dict[str, Any]) -> dict[str, Any]:
    resource = span.get("resource", {})
    if resource is None:
        return {}
    if not isinstance(resource, dict):
        raise FormatError(
            "SOVA-OTEL-RESOURCE-TYPE",
            "span resource must be a JSON object",
            path="$.resource",
        )
    return _attributes(resource.get("attributes", resource), path="$.resource.attributes")


def _span_name(span: dict[str, Any], *, code: str) -> str:
    name = span.get("name")
    if not isinstance(name, str) or not name.strip():
        raise FormatError(code, "span name must be a non-empty string", path="$.name")
    return name


def _is_openinference_sensitive(key: str) -> bool:
    return key in _OPENINFERENCE_SENSITIVE_EXACT or key.startswith(
        _OPENINFERENCE_SENSITIVE_PREFIXES
    )


def _native_or_openinference_kind(name: object, span_kind: str) -> tuple[str, bool]:
    if isinstance(name, str) and (event_family(name) is not None or name.startswith("x.")):
        return name, True
    return _OPENINFERENCE_KIND_TO_EVENT.get(span_kind, "x.openinference.unknown"), False


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
    span = _bounded_json_object(span, code="SOVA-OTEL-SPAN-TYPE")
    attributes = _attributes(span.get("attributes", {}), path="$.attributes")
    resource_attributes = _resource_attributes(span)
    events = span.get("events", [])
    if not isinstance(events, list) or not all(isinstance(event, dict) for event in events):
        raise FormatError(
            "SOVA-OTEL-EVENTS-TYPE",
            "span events must be an array of JSON objects",
            path="$.events",
        )
    name = _span_name(span, code="SOVA-OTEL-SPAN-NAME")
    if "." not in name:
        name = f"x.otel.{name.lower().replace(' ', '-')}"
    source = {
        "name": name,
        "status": span.get("status"),
        "attributes": attributes,
        "events": events,
        "resourceAttributes": resource_attributes,
    }
    for field in _OPENINFERENCE_STRUCTURAL_FIELDS:
        if field in span:
            source[field] = span[field]
    unknown_fields = tuple(
        sorted(
            set(span)
            - {
                "name",
                "status",
                "attributes",
                "resource",
                "events",
                *_OPENINFERENCE_STRUCTURAL_FIELDS,
            }
        )
    )
    draft = {
        "kind": name,
        "phase": str(attributes.get("sova.phase", "import")),
        "payload": {"otel": source},
        "actor": {
            "id": str(attributes.get("sova.actor.id", "external:otel:unknown")),
            "kind": "imported",
            "name": str(
                attributes.get(
                    "service.name",
                    resource_attributes.get("service.name", "OpenTelemetry producer"),
                )
            ),
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
        preserved=("name", "status", "attributes", "events", "structural identifiers"),
        approximated=("actor", "target", "phase", "event kind"),
        omitted=tuple(f"$.{field}" for field in unknown_fields),
        unavailable=(
            "SOVA authorization decision",
            "SOVA safety policy",
            "monotonic ordering when absent",
            "capture-time redaction proof",
            "event hash chain",
        ),
    )


def import_openinference_span(
    span: dict[str, Any],
    *,
    content_policy: Literal["omit", "preserve"] = "omit",
) -> tuple[dict[str, Any], FidelityReport]:
    """Map an OpenInference 0.1.30 JSON span without inventing SOVA evidence.

    The default omits content-bearing attributes and span events. Callers must
    opt in to ``preserve`` after applying their own authorization, privacy, and
    retention policy. Either result is still passed through SOVA capture-time
    redaction when appended to a :class:`TraceWriter`.
    """
    if content_policy not in {"omit", "preserve"}:
        raise FormatError(
            "SOVA-OPENINFERENCE-CONTENT-POLICY",
            "content_policy must be 'omit' or 'preserve'",
        )
    span = _bounded_json_object(span, code="SOVA-OPENINFERENCE-SPAN-TYPE")
    attributes = _attributes(span.get("attributes", {}), path="$.attributes")
    resource_attributes = _resource_attributes(span)
    events = span.get("events", [])
    if not isinstance(events, list) or not all(isinstance(event, dict) for event in events):
        raise FormatError(
            "SOVA-OPENINFERENCE-EVENTS-TYPE",
            "span events must be an array of JSON objects",
            path="$.events",
        )
    name = _span_name(span, code="SOVA-OPENINFERENCE-SPAN-NAME")
    raw_kind = attributes.get("openinference.span.kind", "UNKNOWN")
    span_kind = str(raw_kind).upper()
    unsupported_kind = span_kind not in _OPENINFERENCE_SPAN_KINDS
    if unsupported_kind:
        span_kind = "UNKNOWN"

    sensitive_keys = tuple(sorted(key for key in attributes if _is_openinference_sensitive(key)))
    if content_policy == "preserve":
        retained_attributes = dict(attributes)
        retained_events = events
    else:
        retained_attributes = {
            key: value for key, value in attributes.items() if key not in sensitive_keys
        }
        retained_events = []

    source: dict[str, Any] = {
        "name": name,
        "status": span.get("status"),
        "spanKind": span_kind,
        "attributes": retained_attributes,
        "resourceAttributes": resource_attributes,
        "events": retained_events,
        "privacy": {
            "contentPolicy": content_policy,
            "omittedAttributeKeys": list(sensitive_keys) if content_policy == "omit" else [],
            "omittedEventCount": (len(events) if content_policy == "omit" else 0),
        },
    }
    for field in _OPENINFERENCE_STRUCTURAL_FIELDS:
        if field in span:
            source[field] = span[field]

    event_kind, kind_preserved = _native_or_openinference_kind(name, span_kind)
    actor_id = attributes.get(
        "sova.actor.id",
        attributes.get("user.id", attributes.get("agent.name", "external:openinference:unknown")),
    )
    actor_name = attributes.get(
        "agent.name",
        attributes.get(
            "service.name",
            resource_attributes.get("service.name", "OpenInference producer"),
        ),
    )
    model_name = attributes.get(
        "llm.model_name",
        attributes.get("embedding.model_name", "unknown"),
    )
    target_id = attributes.get("sova.target.id", f"external:model:{model_name}")
    unknown_fields = tuple(
        sorted(
            set(span)
            - {
                "name",
                "status",
                "attributes",
                "resource",
                "events",
                *_OPENINFERENCE_STRUCTURAL_FIELDS,
            }
        )
    )
    omitted = list(sensitive_keys) if content_policy == "omit" else []
    if content_policy == "omit" and span.get("events"):
        omitted.append("events")
    omitted.extend(f"$.{field}" for field in unknown_fields)
    approximated = ["actor", "target", "phase"]
    if not kind_preserved:
        approximated.append("event kind from openinference.span.kind")
    if unsupported_kind:
        approximated.append(f"unsupported span kind {raw_kind!s} mapped to UNKNOWN")

    draft = {
        "kind": event_kind,
        "phase": str(attributes.get("sova.phase", "import")),
        "payload": {"openinference": source},
        "actor": {
            "id": str(actor_id),
            "kind": "imported",
            "name": str(actor_name),
        },
        "target": {
            "id": str(target_id),
            "kind": "target",
            "name": str(model_name),
        },
    }
    return draft, FidelityReport(
        source="openinference.span",
        source_version=OPENINFERENCE_SEMCONV_VERSION,
        preserved=(
            "name",
            "status",
            "structural identifiers",
            "resource attributes",
            "non-content attributes",
        ),
        approximated=tuple(approximated),
        omitted=tuple(omitted),
        unavailable=(
            "SOVA authorization decision",
            "SOVA safety policy",
            "monotonic ordering when absent",
            "capture-time redaction proof",
            "event hash chain",
            "portable replay intent",
        ),
        sensitive=sensitive_keys if content_policy == "preserve" else (),
    )


__all__ = [
    "OPENINFERENCE_CORE_COMMIT",
    "OPENINFERENCE_SEMCONV_VERSION",
    "OTEL_CORE_COMMIT",
    "OTEL_GENAI_EXPERIMENTAL_COMMIT",
    "OTEL_SEMCONV_VERSION",
    "W3C_TRACE_CONTEXT_VERSION",
    "FidelityReport",
    "export_event",
    "import_openinference_span",
    "import_span",
]
