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
