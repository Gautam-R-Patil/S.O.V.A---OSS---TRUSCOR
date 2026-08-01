# SPDX-License-Identifier: Apache-2.0
"""Version-pinned OpenTelemetry/OpenInference mapping contracts."""

from __future__ import annotations

import json

import pytest

from sova.formats.errors import FormatError
from sova.trace.otel import (
    OPENINFERENCE_CORE_COMMIT,
    OPENINFERENCE_SEMCONV_VERSION,
    OTEL_SEMCONV_VERSION,
    export_event,
    import_openinference_span,
    import_span,
)


def test_otel_versions_are_explicitly_pinned() -> None:
    assert OTEL_SEMCONV_VERSION == "1.43.0"
    assert OPENINFERENCE_SEMCONV_VERSION == "0.1.30"
    assert OPENINFERENCE_CORE_COMMIT == "789d41974c08a9a13147977f28ef4142a07e2106"


def test_import_reports_semantics_it_cannot_invent() -> None:
    draft, fidelity = import_span(
        {
            "name": "model.response",
            "attributes": {
                "service.name": "fixture-agent",
                "gen_ai.request.model": "fixture-model",
            },
        }
    )
    assert draft["kind"] == "model.response"
    assert not fidelity.lossless
    assert "SOVA authorization decision" in fidelity.unavailable
    assert "event hash chain" in fidelity.unavailable


def test_generic_otel_import_preserves_structural_identifiers_and_reports_unknowns() -> None:
    draft, fidelity = import_span(
        {
            "name": "external",
            "trace_id": "1" * 32,
            "span_id": "2" * 16,
            "attributes": {},
            "producer_private_field": "not-reinterpreted",
        }
    )
    imported = draft["payload"]["otel"]
    assert imported["trace_id"] == "1" * 32
    assert imported["span_id"] == "2" * 16
    assert "producer_private_field" not in imported
    assert "$.producer_private_field" in fidelity.omitted


def test_generic_otel_import_accepts_explicit_null_metadata_objects() -> None:
    draft, _ = import_span(
        {
            "name": "fixture.operation",
            "attributes": None,
            "resource": None,
        }
    )
    assert draft["payload"]["otel"]["attributes"] == {}
    assert draft["payload"]["otel"]["resourceAttributes"] == {}


@pytest.mark.parametrize(
    ("span", "error_code"),
    [
        ([], "SOVA-OTEL-SPAN-TYPE"),
        ({"name": "fixture", "resource": []}, "SOVA-OTEL-RESOURCE-TYPE"),
        ({"name": "fixture", "events": ["invalid"]}, "SOVA-OTEL-EVENTS-TYPE"),
        ({"name": ""}, "SOVA-OTEL-SPAN-NAME"),
    ],
)
def test_generic_otel_import_rejects_malformed_envelopes(
    span: object,
    error_code: str,
) -> None:
    with pytest.raises(FormatError) as raised:
        import_span(span)  # type: ignore[arg-type]
    assert raised.value.issue.code == error_code


def test_export_reports_loss_instead_of_claiming_full_interoperability() -> None:
    event = {
        "schemaVersion": "0.1.0",
        "kind": "tool.completed",
        "runId": "run",
        "id": "event",
        "parents": [],
        "wallTime": "2026-07-30T00:00:00Z",
        "sequence": 0,
        "phase": "run",
        "actor": {"id": "actor"},
        "target": {"id": "target"},
        "payload": {"ok": True},
        "eventHash": "sha256:" + "0" * 64,
    }
    span, fidelity = export_event(event)
    assert span["attributes"]["openinference.span.kind"] == "TOOL"
    assert "redactions" in fidelity.omitted
    assert not fidelity.lossless
    assert len(span["trace_id"]) == 32
    assert len(span["span_id"]) == 16
    assert all(character in "0123456789abcdef" for character in span["trace_id"])
    assert span["attributes"]["sova.run.id"] == "run"
    assert span["attributes"]["sova.event.id"] == "event"


def test_multiple_causal_parents_use_one_parent_and_span_links() -> None:
    event = {
        "schemaVersion": "0.1.0",
        "kind": "model.response",
        "runId": "sova:run:fixture",
        "id": "sova:event:child",
        "parents": ["sova:event:first", "sova:event:second"],
        "wallTime": "2026-07-30T00:00:00Z",
        "sequence": 2,
        "phase": "run",
        "actor": {"id": "actor"},
        "target": {"id": "target"},
        "payload": {},
        "eventHash": "sha256:" + "0" * 64,
    }
    span, _fidelity = export_event(event)
    assert len(span["parent_span_id"]) == 16
    assert len(span["links"]) == 1
    assert span["links"][0]["attributes"]["sova.event.id"] == "sova:event:second"


def test_openinference_import_omits_content_by_default_and_accounts_for_loss() -> None:
    sensitive_fixture = "synthetic-sensitive-content-not-for-the-default-boundary"
    draft, fidelity = import_openinference_span(
        {
            "name": "ChatCompletion",
            "trace_id": "1" * 32,
            "span_id": "2" * 16,
            "attributes": {
                "openinference.span.kind": "LLM",
                "llm.model_name": "fixture-model",
                "input.value": sensitive_fixture,
                "llm.input_messages.0.message.content": sensitive_fixture,
                "tag.tags": ["safe", "synthetic"],
            },
            "resource": {"attributes": {"service.name": "fixture-agent"}},
            "events": [
                {"name": "exception", "attributes": {"exception.message": sensitive_fixture}}
            ],
        }
    )
    rendered = json.dumps(draft, sort_keys=True)
    assert sensitive_fixture not in rendered
    assert draft["kind"] == "model.interaction"
    assert draft["actor"]["name"] == "fixture-agent"
    assert draft["target"]["name"] == "fixture-model"
    imported = draft["payload"]["openinference"]
    assert imported["trace_id"] == "1" * 32
    assert imported["events"] == []
    assert imported["attributes"]["tag.tags"] == ["safe", "synthetic"]
    assert set(imported["privacy"]["omittedAttributeKeys"]) == {
        "input.value",
        "llm.input_messages.0.message.content",
    }
    assert imported["privacy"]["omittedEventCount"] == 1
    assert "events" in fidelity.omitted
    assert not fidelity.lossless


def test_openinference_content_preservation_is_explicit_and_visibly_sensitive() -> None:
    draft, fidelity = import_openinference_span(
        {
            "name": "weather",
            "attributes": {
                "openinference.span.kind": "TOOL",
                "tool.name": "weather",
                "tool.parameters": '{"city":"synthetic"}',
                "output.value": "sunny",
            },
            "events": [{"name": "completed", "attributes": {}}],
        },
        content_policy="preserve",
    )
    imported = draft["payload"]["openinference"]
    assert draft["kind"] == "tool.interaction"
    assert imported["attributes"]["output.value"] == "sunny"
    assert imported["events"][0]["name"] == "completed"
    assert set(fidelity.sensitive) == {"output.value", "tool.parameters"}
    assert "output.value" not in fidelity.omitted


@pytest.mark.parametrize(
    ("span_kind", "expected_event"),
    [
        ("LLM", "model.interaction"),
        ("EMBEDDING", "model.embedding"),
        ("CHAIN", "x.openinference.chain"),
        ("RETRIEVER", "retrieval.interaction"),
        ("RERANKER", "retrieval.reranking"),
        ("TOOL", "tool.interaction"),
        ("AGENT", "inter-agent.operation"),
        ("GUARDRAIL", "safety.guardrail"),
        ("EVALUATOR", "judge.evaluation"),
        ("PROMPT", "prompt.rendered"),
        ("UNKNOWN", "x.openinference.unknown"),
    ],
)
def test_openinference_0130_span_kinds_have_explicit_event_mappings(
    span_kind: str,
    expected_event: str,
) -> None:
    draft, fidelity = import_openinference_span(
        {
            "name": "external operation",
            "attributes": {"openinference.span.kind": span_kind},
        }
    )
    assert draft["kind"] == expected_event
    assert not fidelity.lossless


def test_openinference_round_trip_preserves_native_kind_only_with_opt_in_content() -> None:
    event = {
        "schemaVersion": "0.1.0",
        "kind": "model.response",
        "runId": "sova:run:fixture",
        "id": "sova:event:fixture",
        "parents": [],
        "wallTime": "2026-07-30T00:00:00Z",
        "sequence": 1,
        "phase": "run",
        "actor": {"id": "fixture:actor"},
        "target": {"id": "fixture:target"},
        "payload": {"text": "observable fixture response"},
        "eventHash": "sha256:" + "0" * 64,
    }
    span, _ = export_event(event)
    omitted, omitted_fidelity = import_openinference_span(span)
    preserved, preserved_fidelity = import_openinference_span(span, content_policy="preserve")
    assert omitted["kind"] == "model.response"
    assert "sova.payload" not in omitted["payload"]["openinference"]["attributes"]
    assert "sova.payload" in omitted_fidelity.omitted
    assert preserved["payload"]["openinference"]["attributes"]["sova.payload"] == event["payload"]
    assert "sova.payload" in preserved_fidelity.sensitive


def test_openinference_extension_name_and_unknown_kind_remain_visibly_degraded() -> None:
    draft, fidelity = import_openinference_span(
        {
            "name": "x.vendor.custom-operation",
            "attributes": {"openinference.span.kind": "FUTURE_KIND"},
            "resource": {"service.name": "fixture-producer"},
            "producer_private_field": "not-reinterpreted",
        }
    )
    assert draft["kind"] == "x.vendor.custom-operation"
    assert draft["actor"]["name"] == "fixture-producer"
    assert "unsupported span kind FUTURE_KIND mapped to UNKNOWN" in fidelity.approximated
    assert "$.producer_private_field" in fidelity.omitted


@pytest.mark.parametrize(
    ("span", "policy", "error_code"),
    [
        ({"attributes": []}, "omit", "SOVA-OTEL-ATTRIBUTES-TYPE"),
        ({"events": ["not-an-object"]}, "omit", "SOVA-OPENINFERENCE-EVENTS-TYPE"),
        ({"attributes": {"score": float("nan")}}, "omit", "SOVA-OPENINFERENCE-SPAN-TYPE"),
        ({"attributes": {1: "not-a-json-name"}}, "omit", "SOVA-OPENINFERENCE-SPAN-TYPE"),
        ({}, "unsafe", "SOVA-OPENINFERENCE-CONTENT-POLICY"),
    ],
)
def test_openinference_import_rejects_ambiguous_or_hostile_shapes(
    span: dict[object, object],
    policy: str,
    error_code: str,
) -> None:
    with pytest.raises(FormatError) as raised:
        import_openinference_span(span, content_policy=policy)  # type: ignore[arg-type]
    assert raised.value.issue.code == error_code


def test_export_never_emits_nonexistent_openinference_memory_span_kind() -> None:
    event = {
        "schemaVersion": "0.1.0",
        "kind": "memory.read",
        "runId": "run",
        "id": "event",
        "parents": [],
        "wallTime": "2026-07-30T00:00:00Z",
        "sequence": 0,
        "phase": "run",
        "actor": {"id": "actor"},
        "target": {"id": "target"},
        "payload": {},
        "eventHash": "sha256:" + "0" * 64,
    }
    span, _ = export_event(event)
    assert span["attributes"]["openinference.span.kind"] == "CHAIN"
