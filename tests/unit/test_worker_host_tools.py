# SPDX-License-Identifier: Apache-2.0
"""Safe host-check and exact-host receipt compiler command tests."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from scripts.check_worker_host import main as check_host
from scripts.compile_p5_exact_host_receipt import main as compile_receipt
from sova.worker.host_acceptance import POSITIVE_CONTROL
from sova.worker.malicious import MaliciousGuestCase
from tests.support.worker import digest

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


def _case(case_id: str) -> dict[str, object]:
    return {
        "caseId": case_id,
        "status": "passed",
        "startedAt": "2026-08-28T12:00:00Z",
        "completedAt": "2026-08-28T12:01:00Z",
        "executionReceiptDigest": digest(f"execution:{case_id}"),
        "networkReceiptDigest": digest(f"network:{case_id}"),
        "evidenceDigest": digest(f"evidence:{case_id}"),
        "cleanupComplete": True,
        "expected": "contained",
        "observed": "contained with bound evidence",
    }


def _arguments(path: Path) -> list[str]:
    return [
        str(path),
        "--release-commit",
        "a" * 40,
        "--worker-id",
        "worker:exact",
        "--measured-at",
        "2026-08-28T12:30:00Z",
        "--attestation-digest",
        digest("attestation"),
        "--preflight-receipt-digest",
        digest("preflight"),
        "--guest-kernel-digest",
        digest("kernel"),
        "--root-filesystem-digest",
        digest("rootfs"),
        "--worker-policy-digest",
        digest("policy"),
    ]


def test_exact_host_compiler_exits_one_for_missing_cases(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cases = tmp_path / "cases.json"
    cases.write_text(json.dumps([_case(POSITIVE_CONTROL)]), encoding="utf-8")
    assert compile_receipt(_arguments(cases)) == 1
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "failed"
    assert output["claims"]["productionIsolationClaimAllowed"] is False


def test_exact_host_compiler_passes_only_complete_matrix(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cases = tmp_path / "cases.json"
    case_ids = (POSITIVE_CONTROL, *(item.value for item in MaliciousGuestCase))
    cases.write_text(json.dumps([_case(case_id) for case_id in case_ids]), encoding="utf-8")
    assert compile_receipt(_arguments(cases)) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "passed"
    assert output["claims"]["exactHostMatrixPassed"] is True


def test_host_check_rejects_unconfigured_template_without_probing_host(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    template = tmp_path / "worker-policy.json"
    template.write_text(
        '{"artifactType":"sova.worker-deployment-policy","schemaVersion":"0.2.0"}',
        encoding="utf-8",
    )
    assert check_host([str(template), "--release-commit", "a" * 40]) == 2
    assert "fields must be exact" in capsys.readouterr().err
