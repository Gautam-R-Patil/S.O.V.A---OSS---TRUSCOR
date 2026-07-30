# SPDX-License-Identifier: Apache-2.0
"""Deterministic observable oracles for portable scenario outcomes."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any

from sova.formats.errors import FormatError


class OracleStatus(StrEnum):
    """Bounded result of one deterministic observable oracle."""

    PASS = "pass"  # noqa: S105 - an evaluation state, not a credential
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class ObservableRecord:
    """One already-recorded observable value available to an oracle."""

    kind: str
    event_id: str | None
    value: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class OracleResult:
    """One oracle result with explicit evidence linkage and limitations."""

    index: int
    kind: str
    status: OracleStatus
    observed: Any
    expected: Any
    evidence_event_ids: tuple[str, ...]
    reason: str


@dataclass(frozen=True, slots=True)
class OracleReport:
    """Aggregate oracle report; execution completion remains a separate fact."""

    status: OracleStatus
    results: tuple[OracleResult, ...]

    def to_mapping(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "results": [
                {
                    **asdict(result),
                    "status": result.status.value,
                    "evidence_event_ids": list(result.evidence_event_ids),
                }
                for result in self.results
            ],
            "method": "sova.deterministic-observable-oracles/0.1",
            "limitations": [
                "Oracle results depend only on recorded observable values.",
                (
                    "A passing oracle does not prove trace completeness, causality, "
                    "or hidden model state."
                ),
            ],
        }


_MISSING = object()


def _json_path(value: Any, path: str) -> Any:
    if path == "$":
        return value
    if not path.startswith("$."):
        raise FormatError(
            "SOVA-ORACLE-PATH",
            "deterministic exact-field paths must start with '$.'",
        )
    current = value
    for component in path[2:].split("."):
        if not component or not isinstance(current, Mapping) or component not in current:
            return _MISSING
        current = current[component]
    return current


def _ids(records: Sequence[ObservableRecord]) -> tuple[str, ...]:
    return tuple(record.event_id for record in records if record.event_id is not None)


def _exact_field(
    index: int,
    oracle: Mapping[str, Any],
    records: Sequence[ObservableRecord],
) -> OracleResult:
    path = oracle.get("path")
    if not isinstance(path, str):
        raise FormatError("SOVA-ORACLE-PATH", "exact-field oracle requires a string path")
    expected = oracle.get("equals")
    observed = [
        value for record in records if (value := _json_path(record.value, path)) is not _MISSING
    ]
    if not observed:
        status = OracleStatus.INCONCLUSIVE
        reason = "the requested field was not present in observable records"
        rendered: Any = None
    else:
        status = (
            OracleStatus.PASS if any(value == expected for value in observed) else OracleStatus.FAIL
        )
        reason = (
            "an observable value matched" if status == OracleStatus.PASS else "no value matched"
        )
        rendered = observed
    return OracleResult(index, "exact-field", status, rendered, expected, _ids(records), reason)


def _contains(container: Any, expected: Any) -> bool:
    if isinstance(container, str) and isinstance(expected, str):
        return expected in container
    if isinstance(container, Mapping):
        return expected in container or expected in container.values()
    if isinstance(container, (list, tuple)):
        return expected in container
    return False


def _field_contains(
    index: int,
    oracle: Mapping[str, Any],
    records: Sequence[ObservableRecord],
) -> OracleResult:
    path = oracle.get("path")
    if not isinstance(path, str):
        raise FormatError(
            "SOVA-ORACLE-PATH",
            "field-contains oracle requires a string path",
        )
    expected = oracle.get("contains")
    observed = [
        value for record in records if (value := _json_path(record.value, path)) is not _MISSING
    ]
    if not observed:
        status = OracleStatus.INCONCLUSIVE
        reason = "the requested field was not present in observable records"
        rendered: Any = None
    else:
        status = (
            OracleStatus.PASS
            if any(_contains(value, expected) for value in observed)
            else OracleStatus.FAIL
        )
        reason = (
            "an observable value contained the expected value"
            if status == OracleStatus.PASS
            else "no observable value contained the expected value"
        )
        rendered = observed
    return OracleResult(
        index,
        "field-contains",
        status,
        rendered,
        expected,
        _ids(records),
        reason,
    )


def _fixture_label(
    index: int,
    oracle: Mapping[str, Any],
    records: Sequence[ObservableRecord],
) -> OracleResult:
    expected = oracle.get("equals")
    observed: list[Any] = []
    for record in records:
        if "label" in record.value:
            observed.append(record.value["label"])
        structured = record.value.get("structured")
        if isinstance(structured, Mapping) and "label" in structured:
            observed.append(structured["label"])
        if "text" in record.value:
            observed.append(record.value["text"])
    if not observed:
        status = OracleStatus.INCONCLUSIVE
        reason = "no observable label or text was available"
    else:
        status = OracleStatus.PASS if expected in observed else OracleStatus.FAIL
        reason = (
            "fixture label matched" if status == OracleStatus.PASS else "fixture label differed"
        )
    return OracleResult(index, "fixture-label", status, observed, expected, _ids(records), reason)


def _event_present(
    index: int,
    oracle: Mapping[str, Any],
    records: Sequence[ObservableRecord],
) -> OracleResult:
    expected = oracle.get("event")
    if not isinstance(expected, str):
        raise FormatError(
            "SOVA-ORACLE-EVENT",
            "event-present oracle requires a string event",
        )
    matching = [record for record in records if record.kind == expected]
    return OracleResult(
        index,
        "event-present",
        OracleStatus.PASS if matching else OracleStatus.FAIL,
        [record.kind for record in matching],
        expected,
        _ids(matching),
        "required event was observed" if matching else "required event was absent",
    )


def _execution_status(
    index: int,
    oracle: Mapping[str, Any],
    records: Sequence[ObservableRecord],
) -> OracleResult:
    expected = oracle.get("equals")
    observed = [
        record.value.get("status")
        for record in records
        if record.kind in {"execution.status", "tool.completed", "tool.failed"}
        and "status" in record.value
    ]
    if not observed:
        status = OracleStatus.INCONCLUSIVE
        reason = "no normalized execution status was available"
    else:
        status = OracleStatus.PASS if expected in observed else OracleStatus.FAIL
        reason = "execution status matched" if status == OracleStatus.PASS else "status differed"
    return OracleResult(
        index,
        "execution-status",
        status,
        observed,
        expected,
        _ids(records),
        reason,
    )


def evaluate_oracles(
    oracles: Sequence[Mapping[str, Any]],
    records: Sequence[ObservableRecord],
) -> OracleReport:
    """Evaluate only registered deterministic oracle kinds and expose unknowns."""
    results: list[OracleResult] = []
    for index, oracle in enumerate(oracles):
        kind = oracle.get("kind")
        if kind == "exact-field":
            result = _exact_field(index, oracle, records)
        elif kind == "field-contains":
            result = _field_contains(index, oracle, records)
        elif kind == "fixture-label":
            result = _fixture_label(index, oracle, records)
        elif kind == "event-present":
            result = _event_present(index, oracle, records)
        elif kind == "execution-status":
            result = _execution_status(index, oracle, records)
        else:
            result = OracleResult(
                index,
                str(kind),
                OracleStatus.INCONCLUSIVE,
                None,
                None,
                (),
                "oracle kind is not implemented by the deterministic reference evaluator",
            )
        results.append(result)
    statuses = {result.status for result in results}
    if OracleStatus.FAIL in statuses:
        aggregate = OracleStatus.FAIL
    elif OracleStatus.INCONCLUSIVE in statuses or not results:
        aggregate = OracleStatus.INCONCLUSIVE
    else:
        aggregate = OracleStatus.PASS
    return OracleReport(aggregate, tuple(results))


__all__ = [
    "ObservableRecord",
    "OracleReport",
    "OracleResult",
    "OracleStatus",
    "evaluate_oracles",
]
