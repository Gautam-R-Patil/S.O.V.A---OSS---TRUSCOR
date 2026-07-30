# SPDX-License-Identifier: Apache-2.0
"""Version-pinned OpenTelemetry/OpenInference mapping contracts."""

from __future__ import annotations

from sova.trace.otel import (
    OPENINFERENCE_SEMCONV_VERSION,
    OTEL_SEMCONV_VERSION,
    export_event,
    import_span,
)


def test_otel_versions_are_explicitly_pinned() -> None:
    assert OTEL_SEMCONV_VERSION == "1.43.0"
    assert OPENINFERENCE_SEMCONV_VERSION == "0.1.30"


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
