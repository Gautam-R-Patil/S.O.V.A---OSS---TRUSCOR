# SPDX-License-Identifier: Apache-2.0
"""Deterministic observable-oracle tests."""

from __future__ import annotations

import pytest

from sova.formats.errors import FormatError
from sova.oracles import ObservableRecord, OracleStatus, evaluate_oracles


def _record(kind: str, value: dict[str, object], event_id: str = "event:1") -> ObservableRecord:
    return ObservableRecord(kind, event_id, value)


def test_exact_field_pass_fail_and_missing_are_distinct() -> None:
    records = [_record("model.response", {"structured": {"label": "TRIGGERED"}})]
    passed = evaluate_oracles(
        [{"kind": "exact-field", "path": "$.structured.label", "equals": "TRIGGERED"}],
        records,
    )
    failed = evaluate_oracles(
        [{"kind": "exact-field", "path": "$.structured.label", "equals": "BASELINE"}],
        records,
    )
    missing = evaluate_oracles(
        [{"kind": "exact-field", "path": "$.missing", "equals": "anything"}],
        records,
    )

    assert passed.status == OracleStatus.PASS
    assert failed.status == OracleStatus.FAIL
    assert missing.status == OracleStatus.INCONCLUSIVE
    assert passed.results[0].evidence_event_ids == ("event:1",)


def test_event_and_execution_status_oracles_use_observable_records() -> None:
    records = [
        _record("tool.requested", {"action": "artifact.read"}, "event:1"),
        _record("tool.completed", {"status": "succeeded"}, "event:2"),
    ]
    report = evaluate_oracles(
        [
            {"kind": "event-present", "event": "tool.completed"},
            {"kind": "execution-status", "equals": "succeeded"},
        ],
        records,
    )

    assert report.status == OracleStatus.PASS
    assert report.to_mapping()["method"] == "sova.deterministic-observable-oracles/0.1"


def test_field_contains_allows_declared_platform_text_variation() -> None:
    report = evaluate_oracles(
        [{"kind": "field-contains", "path": "$.stdout", "contains": "TRIGGERED"}],
        [_record("tool.completed", {"stdout": "TRIGGERED\r\n"})],
    )
    mismatch = evaluate_oracles(
        [{"kind": "field-contains", "path": "$.stdout", "contains": "TRIGGERED"}],
        [_record("tool.completed", {"stdout": "BASELINE\r\n"})],
    )

    assert report.status == OracleStatus.PASS
    assert mismatch.status == OracleStatus.FAIL


def test_unknown_oracle_and_empty_set_are_visibly_inconclusive() -> None:
    unknown = evaluate_oracles([{"kind": "extension:semantic-judge"}], [])
    empty = evaluate_oracles([], [])

    assert unknown.status == OracleStatus.INCONCLUSIVE
    assert "not implemented" in unknown.results[0].reason
    assert empty.status == OracleStatus.INCONCLUSIVE


def test_malformed_registered_oracle_refuses_evaluation() -> None:
    with pytest.raises(FormatError, match="must start"):
        evaluate_oracles(
            [{"kind": "exact-field", "path": "label", "equals": "TRIGGERED"}],
            [_record("model.response", {"label": "TRIGGERED"})],
        )

    with pytest.raises(FormatError, match="requires a string event"):
        evaluate_oracles([{"kind": "event-present", "event": 42}], [])

    with pytest.raises(FormatError, match="requires a string path"):
        evaluate_oracles([{"kind": "exact-field", "path": 42}], [])

    with pytest.raises(FormatError, match="requires a string path"):
        evaluate_oracles([{"kind": "field-contains", "path": None}], [])


def test_root_path_and_missing_event_identifier_are_supported() -> None:
    report = evaluate_oracles(
        [{"kind": "exact-field", "path": "$", "equals": {"label": "ok"}}],
        [ObservableRecord("model.response", None, {"label": "ok"})],
    )
    assert report.status == OracleStatus.PASS
    assert report.results[0].evidence_event_ids == ()


@pytest.mark.parametrize(
    ("container", "expected"),
    [
        (["alpha", "beta"], "beta"),
        (("alpha", "beta"), "alpha"),
        ({"key": "value"}, "key"),
        ({"key": "value"}, "value"),
    ],
)
def test_field_contains_supports_declared_container_types(
    container: object,
    expected: object,
) -> None:
    report = evaluate_oracles(
        [{"kind": "field-contains", "path": "$.value", "contains": expected}],
        [_record("tool.completed", {"value": container})],
    )
    assert report.status == OracleStatus.PASS


def test_field_contains_missing_and_noncontainer_are_not_equivalent() -> None:
    missing = evaluate_oracles(
        [{"kind": "field-contains", "path": "$.missing", "contains": "x"}],
        [_record("tool.completed", {"value": "x"})],
    )
    noncontainer = evaluate_oracles(
        [{"kind": "field-contains", "path": "$.value", "contains": "x"}],
        [_record("tool.completed", {"value": 42})],
    )
    assert missing.status == OracleStatus.INCONCLUSIVE
    assert noncontainer.status == OracleStatus.FAIL


def test_fixture_label_reads_direct_structured_and_text_observations() -> None:
    records = [
        _record("fixture", {"label": "direct"}),
        _record("fixture", {"structured": {"label": "structured"}}),
        _record("fixture", {"text": "text"}),
    ]
    for expected in ("direct", "structured", "text"):
        assert (
            evaluate_oracles(
                [{"kind": "fixture-label", "equals": expected}],
                records,
            ).status
            == OracleStatus.PASS
        )
    assert (
        evaluate_oracles(
            [{"kind": "fixture-label", "equals": "absent"}],
            records,
        ).status
        == OracleStatus.FAIL
    )
    assert (
        evaluate_oracles(
            [{"kind": "fixture-label", "equals": "absent"}],
            [_record("fixture", {"structured": "not-an-object"})],
        ).status
        == OracleStatus.INCONCLUSIVE
    )


def test_absent_event_and_execution_status_fail_or_remain_unknown() -> None:
    absent = evaluate_oracles(
        [{"kind": "event-present", "event": "tool.completed"}],
        [_record("tool.requested", {"action": "read"})],
    )
    mismatched = evaluate_oracles(
        [{"kind": "execution-status", "equals": "succeeded"}],
        [_record("tool.failed", {"status": "failed"})],
    )
    missing = evaluate_oracles(
        [{"kind": "execution-status", "equals": "succeeded"}],
        [_record("tool.completed", {"other": "value"})],
    )
    assert absent.status == OracleStatus.FAIL
    assert mismatched.status == OracleStatus.FAIL
    assert missing.status == OracleStatus.INCONCLUSIVE


@pytest.mark.parametrize(
    ("oracle", "record"),
    [
        (
            {"kind": "file-state", "path": "/safe.txt", "exists": True},
            _record("filesystem.stat", {"path": "/safe.txt", "exists": True}),
        ),
        (
            {"kind": "process-state", "returncode": 0},
            _record("process.completed", {"returncode": 0}),
        ),
        (
            {"kind": "network-effect", "delivered": False, "sinkOnly": True},
            _record("network.egress-attempt", {"delivered": False, "sinkOnly": True}),
        ),
        (
            {"kind": "tool-invocation", "tool": "safe-tool"},
            _record("tool.requested", {"tool": "safe-tool"}),
        ),
        (
            {"kind": "permission-bypass", "bypassed": False},
            _record("authorization.decision", {"bypassed": False}),
        ),
        (
            {"kind": "browser-state", "url": "https://example.invalid"},
            _record("browser.observed", {"url": "https://example.invalid"}),
        ),
        (
            {"kind": "database-mutation", "table": "customers", "changed": True},
            _record("database.update", {"table": "customers", "changed": True}),
        ),
        (
            {"kind": "inter-agent-handoff", "sender": "a", "recipient": "b"},
            _record("inter-agent.sent", {"sender": "a", "recipient": "b"}),
        ),
        (
            {"kind": "state-transition", "from": "dormant", "to": "triggered"},
            _record("safety.transition", {"from": "dormant", "to": "triggered"}),
        ),
        (
            {"kind": "trigger-activation", "triggered": True},
            _record("safety.trigger-activation", {"triggered": True}),
        ),
    ],
)
def test_typed_observable_oracles_pass_only_on_normalized_records(
    oracle: dict[str, object],
    record: ObservableRecord,
) -> None:
    assert evaluate_oracles([oracle], [record]).status == OracleStatus.PASS


def test_canary_and_composite_oracles_keep_failure_and_inconclusive_distinct() -> None:
    canary = evaluate_oracles(
        [{"kind": "canary-observed", "canaryId": "sova:canary:1"}],
        [_record("network.egress-attempt", {"canaryIds": ["sova:canary:1"]})],
    )
    composite = evaluate_oracles(
        [
            {
                "kind": "composite",
                "operator": "all",
                "items": [
                    {"kind": "event-present", "event": "tool.completed"},
                    {"kind": "network-effect", "delivered": False},
                ],
            }
        ],
        [
            _record("tool.completed", {"status": "succeeded"}),
            _record("network.egress-attempt", {"delivered": False}),
        ],
    )
    assert canary.status == OracleStatus.PASS
    assert composite.status == OracleStatus.PASS


def test_malformed_typed_and_composite_oracles_refuse_ambiguous_meaning() -> None:
    with pytest.raises(FormatError, match="expected field"):
        evaluate_oracles([{"kind": "network-effect"}], [])
    with pytest.raises(FormatError, match="exactly one"):
        evaluate_oracles(
            [
                {
                    "kind": "composite",
                    "operator": "not",
                    "items": [
                        {"kind": "event-present", "event": "a"},
                        {"kind": "event-present", "event": "b"},
                    ],
                }
            ],
            [],
        )
