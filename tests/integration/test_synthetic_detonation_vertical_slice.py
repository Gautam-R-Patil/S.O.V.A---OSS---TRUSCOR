# SPDX-License-Identifier: Apache-2.0
"""Safe conditional behavior -> trace -> capsule -> offline verification."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sova.capsule import lint_capsule, render_capsule
from sova.cli import main
from sova.detonation import run_sleeper_demo
from sova.formats.errors import FormatError
from sova.runtime import standard_profile
from sova.trace import TraceReader
from sova.workflows import run_complete_demo


@pytest.mark.integration
def test_synthetic_sleeper_vertical_slice_is_inspectable_and_offline_verifiable(
    tmp_path: Path,
) -> None:
    artifacts = run_sleeper_demo(tmp_path)
    assert artifacts.oracle_status == "pass"
    assert artifacts.evidence_closure == "sufficient"
    assert artifacts.cleanup_verified
    assert not lint_capsule(artifacts.capsule)
    assert "SOVA synthetic sleeper detonation" in render_capsule(artifacts.capsule)

    reader = TraceReader(artifacts.trace)
    report = reader.verify()
    assert report.package_integrity
    assert report.event_chain_integrity
    assert report.completion == "completed"
    kinds = [event["kind"] for event in reader.events()]
    assert kinds[:3] == ["authorization.decision", "safety.containment", "run.started"]
    assert kinds.count("attempt.started") == 4
    assert kinds.count("attempt.completed") == 4
    assert kinds[-6:] == [
        "tool.requested",
        "filesystem.read",
        "network.egress-attempt",
        "safety.trigger-activation",
        "oracle.completed",
        "run.completed",
    ]
    authorization = next(reader.query(kind_prefix="authorization.decision"))
    assert authorization["payload"]["decision"] == "allowed"
    assert authorization["payload"]["scopeDigest"].startswith("sha256:")
    network = next(reader.query(kind_prefix="network.egress-attempt"))
    assert network["payload"]["delivered"] is False
    assert network["payload"]["sinkOnly"] is True
    oracle = next(reader.query(kind_prefix="oracle.completed"))
    assert oracle["payload"]["status"] == "pass"
    assert oracle["payload"]["evidenceClosure"]["status"] == "sufficient"

    summary = json.loads(artifacts.summary.read_text(encoding="utf-8"))
    assert summary["cleanupVerified"] is True
    assert any("simulator" in item for item in summary["limitations"])


@pytest.mark.integration
def test_demo_cli_outputs_paths_and_refuses_overwrite(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "demo"
    assert main(["demo", "sleeper", str(destination)]) == 0
    rendered = json.loads(capsys.readouterr().out)
    assert Path(rendered["capsule"]).is_file()
    assert Path(rendered["trace"]).is_file()
    assert rendered["oracleStatus"] == "pass"
    assert rendered["reproduced"] is True
    assert Path(rendered["reproductionTrace"]).is_file()
    with pytest.raises(FormatError, match="not empty"):
        run_complete_demo(destination, profile=standard_profile())
