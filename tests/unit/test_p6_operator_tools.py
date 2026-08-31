# SPDX-License-Identifier: Apache-2.0
"""Operator-facing P6 protocol freeze and observation evaluation tests."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from scripts.compile_p6_work_orders import main as compile_work_orders
from scripts.evaluate_p6_observations import main as evaluate_observations
from scripts.freeze_p6_protocol import main as freeze_protocol
from sova.formats import canonical_json_bytes, sha256_digest, validate_document
from sova.validation import build_evaluation_work_orders
from tests.support.p6 import observations, protocol

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


def _with_digest(document: dict[str, Any]) -> dict[str, Any]:
    result = dict(document)
    result["contentDigest"] = sha256_digest(canonical_json_bytes(result))
    return result


def test_protocol_freeze_requires_ack_and_never_overwrites(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    plan = protocol()
    source = tmp_path / "protocol-input.json"
    output = tmp_path / "frozen" / "protocol.json"
    source.write_bytes(canonical_json_bytes(plan.to_mapping()))
    base = [str(source), str(output), "--expected-release-commit", plan.release_commit]
    assert freeze_protocol(base) == 2
    assert not output.exists()
    assert freeze_protocol([*base, "--ack-no-results-observed"]) == 0
    result = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert result["protocolDigest"] == plan.digest
    assert result["externalTimestampOrCustodyEstablished"] is False
    assert freeze_protocol([*base, "--ack-no-results-observed"]) == 2


def test_observation_evaluator_emits_exact_conclusive_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    plan = protocol()
    protocol_path = tmp_path / "protocol.json"
    ledger_path = tmp_path / "ledger.json"
    report_path = tmp_path / "report.json"
    protocol_path.write_bytes(canonical_json_bytes(plan.to_mapping()))
    ledger = _with_digest(
        {
            "artifactType": "sova.evaluation-observation-ledger",
            "schemaVersion": "0.1.0",
            "protocolDigest": plan.digest,
            "observations": [item.to_mapping() for item in observations(plan)],
        }
    )
    ledger_path.write_bytes(canonical_json_bytes(ledger))
    assert evaluate_observations([str(protocol_path), str(ledger_path), str(report_path)]) == 0
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["status"] == "conclusive"
    assert report["claims"]["fieldValidationEstablished"] is False
    assert capsys.readouterr().out.strip() == report["contentDigest"]


def test_work_orders_expand_every_run_without_answer_key_or_authority(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    plan = protocol()
    first = build_evaluation_work_orders(plan)
    second = build_evaluation_work_orders(plan)
    validate_document(first)
    assert first == second
    assert len(first["workOrders"]) == plan.run_count
    serialized = canonical_json_bytes(first)
    assert b"answerKeyCommitment" not in serialized
    assert b'"automaticExecutionAuthorized":false' in serialized

    protocol_path = tmp_path / "protocol.json"
    output = tmp_path / "orders.json"
    protocol_path.write_bytes(canonical_json_bytes(plan.to_mapping()))
    assert compile_work_orders([str(protocol_path), str(output)]) == 0
    assert json.loads(output.read_text(encoding="utf-8")) == first
    assert capsys.readouterr().out.strip() == first["contentDigest"]
