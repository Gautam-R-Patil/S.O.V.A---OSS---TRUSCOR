# SPDX-License-Identifier: Apache-2.0
"""The dependency-free verifier is an independent offline process/code path."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from sova.capsule import build_capsule, capsule_manifest_template, scenario_template
from sova.trace import TraceWriter

ROOT = Path(__file__).resolve().parents[2]
VERIFIER = ROOT / "scripts" / "sova_independent_verify.py"


def _run(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(VERIFIER), str(path)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


@pytest.mark.integration
def test_independent_process_validates_capsule_and_redacted_trace(tmp_path: Path) -> None:
    source = VERIFIER.read_text(encoding="utf-8")
    assert "from sova" not in source
    capsule = tmp_path / "fixture.sova"
    build_capsule(
        capsule,
        capsule_manifest_template(
            title="Independent fixture",
            summary="Independent capsule verification.",
            author="Synthetic test author",
        ),
        scenario=scenario_template(title="Fixture", purpose="Independent validation"),
    )
    capsule_result = _run(capsule)
    assert capsule_result.returncode == 0, capsule_result.stderr
    assert json.loads(capsule_result.stdout)["artifactType"] == "sova.capsule"

    trace = tmp_path / "fixture.sova-trace"
    writer = TraceWriter(trace)
    writer.append("prompt.sent", {"api_key": "synthetic-secret-value"})
    writer.finalize()
    trace_result = _run(trace)
    assert trace_result.returncode == 0, trace_result.stderr
    report = json.loads(trace_result.stdout)
    assert report["artifactType"] == "sova.trace"
    assert report["eventCount"] == 1
    assert report["signatureChecked"] is False


@pytest.mark.integration
def test_independent_process_fails_visibly_on_substitution(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.sova"
    invalid.write_bytes(b"not a package")
    result = _run(invalid)
    assert result.returncode == 2
    assert "INDEPENDENT-VERIFY-FAILED" in result.stderr
