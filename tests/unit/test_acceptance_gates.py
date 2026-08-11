# SPDX-License-Identifier: Apache-2.0
"""Final-mile evidence and stable-release gate tests."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from sova.acceptance import (
    AcceptanceGate,
    AcceptanceReceipt,
    GateClass,
    default_release_gates,
    evaluate_gate,
    evaluate_release_readiness,
    load_receipts,
    receipt_from_mapping,
)
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from pathlib import Path

DIGEST = "sha256:" + "a" * 64


def _receipt(  # noqa: PLR0913 - gate evidence axes remain explicit in tests
    *,
    gate_id: str = "gate",
    evidence_type: str = "evidence",
    run_id: str = "run-1",
    organization: str = "TRUSCOR Private Limited",
    environment: str = "env-1",
    labels: tuple[tuple[str, str], ...] = (),
    independent: bool = False,
    result: str = "pass",
) -> AcceptanceReceipt:
    return AcceptanceReceipt(
        gate_id,
        evidence_type,
        run_id,
        result,
        "fixture-runner",
        organization,
        environment,
        labels,
        (DIGEST,),
        independent,
        "2026-08-11T00:00:00Z",
        ("bounded fixture evidence",),
    )


def test_gate_requires_passes_environments_labels_and_independence() -> None:
    gate = AcceptanceGate(
        "gate",
        "Held-out gate",
        "evidence",
        GateClass.EXTERNAL,
        minimum_passes=2,
        minimum_environments=2,
        minimum_independent_organizations=1,
        required_labels=(("platform", ("windows", "linux")),),
    )
    partial = evaluate_gate(
        gate,
        (_receipt(labels=(("platform", "windows"),)),),
    )
    assert partial.status == "blocked"
    assert partial.reasons == (
        "requires-2-passing-receipts",
        "requires-2-distinct-environments",
        "requires-1-independent-organizations",
        "missing-platform:linux",
    )
    passed = evaluate_gate(
        gate,
        (
            _receipt(labels=(("platform", "windows"),)),
            _receipt(
                run_id="run-2",
                organization="Independent Lab",
                environment="env-2",
                labels=(("platform", "linux"),),
                independent=True,
            ),
        ),
    )
    assert passed.passed
    assert len(passed.accepted_receipts) == 2


def test_default_stable_release_is_blocked_without_external_evidence() -> None:
    gates = default_release_gates()
    report = evaluate_release_readiness(())
    assert len(gates) == 12
    assert not report.ready_for_stable_1
    document = report.to_mapping()
    assert document["status"] == "blocked"
    assert document["passedGateCount"] == 0
    assert document["claims"]["externalEvidenceSelfGenerated"] is False


def test_receipt_loader_is_strict_and_never_infers_independence(tmp_path: Path) -> None:
    receipt = _receipt()
    document = receipt.to_mapping(include_digest=False)
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    loaded = load_receipts(tmp_path)
    assert loaded == (receipt,)
    assert loaded[0].independent_of_sova_team is False

    document["unexpected"] = True
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(FormatError, match="exact"):
        load_receipts(tmp_path)


def test_receipt_rejects_invalid_results_digests_and_duplicate_labels() -> None:
    with pytest.raises(FormatError, match="result"):
        _receipt(result="excellent")
    with pytest.raises(FormatError, match="digests"):
        AcceptanceReceipt(
            gate_id="gate",
            evidence_type="evidence",
            run_id="run",
            result="pass",
            producer="producer",
            organization="organization",
            environment_id="environment",
            labels=(),
            artifact_digests=("not-a-digest",),
            independent_of_sova_team=False,
            observed_at="2026-08-11T00:00:00Z",
            limitations=(),
        )
    with pytest.raises(FormatError, match="unique"):
        _receipt(labels=(("platform", "windows"), ("platform", "linux")))


def test_receipt_and_gate_models_reject_empty_malformed_and_duplicate_inputs() -> None:
    with pytest.raises(FormatError, match="identity"):
        _receipt(run_id="")
    with pytest.raises(FormatError, match="timestamp"):
        AcceptanceReceipt(
            gate_id="gate",
            evidence_type="evidence",
            run_id="run",
            result="pass",
            producer="producer",
            organization="organization",
            environment_id="environment",
            labels=(),
            artifact_digests=(),
            independent_of_sova_team=False,
            observed_at="2026-08-11T00:00:00+05:30",
            limitations=(),
        )
    with pytest.raises(FormatError, match="cannot be empty"):
        _receipt(labels=(("platform", ""),))
    with pytest.raises(FormatError, match="identity"):
        AcceptanceGate("", "title", "evidence", GateClass.ENGINEERING)
    with pytest.raises(FormatError, match="positive"):
        AcceptanceGate("id", "title", "evidence", GateClass.ENGINEERING, minimum_passes=0)
    with pytest.raises(FormatError, match="negative"):
        AcceptanceGate(
            "id",
            "title",
            "evidence",
            GateClass.EXTERNAL,
            minimum_independent_organizations=-1,
        )
    duplicate = AcceptanceGate("same", "one", "evidence", GateClass.ENGINEERING)
    with pytest.raises(FormatError, match="unique"):
        evaluate_release_readiness((), (duplicate, duplicate))


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("artifactType", "wrong", "unsupported"),
        ("labels", [], "labels"),
        ("artifactDigests", {}, "digests"),
        ("limitations", {}, "limitations"),
        ("producer", 42, "scalar"),
        ("independentOfSovaTeam", "false", "scalar"),
    ),
)
def test_receipt_mapping_parser_rejects_each_malformed_field(
    field: str,
    value: object,
    message: str,
) -> None:
    document = _receipt().to_mapping(include_digest=False)
    document[field] = value
    with pytest.raises(FormatError, match=message):
        receipt_from_mapping(document)


def test_receipt_loader_rejects_missing_nonobject_and_oversized_files(tmp_path: Path) -> None:
    with pytest.raises(FormatError, match="does not exist"):
        load_receipts(tmp_path / "missing")
    (tmp_path / "scalar.json").write_text("[]", encoding="utf-8")
    with pytest.raises(FormatError, match="root"):
        load_receipts(tmp_path)
    (tmp_path / "scalar.json").write_bytes(b"x" * (1024 * 1024 + 1))
    with pytest.raises(FormatError, match="bounded regular"):
        load_receipts(tmp_path)


def test_gate_result_records_explicit_failure_receipts() -> None:
    gate = AcceptanceGate("gate", "Gate", "evidence", GateClass.ENGINEERING)
    result = evaluate_gate(gate, (_receipt(result="fail"),))
    assert not result.passed
    assert result.accepted_receipts == ()
    assert len(result.failed_receipts) == 1
