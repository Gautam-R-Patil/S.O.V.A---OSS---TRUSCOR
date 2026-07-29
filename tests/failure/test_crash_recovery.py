# SPDX-License-Identifier: Apache-2.0
"""Self-tests for the subprocess crash-recovery harness."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from tests.support.crash_worker import CRASH_EXIT_CODE


@pytest.mark.failure
def test_crash_before_replace_preserves_original(tmp_path: Path) -> None:
    target = tmp_path / "state.txt"
    target.write_text("original", encoding="utf-8")
    worker = Path(__file__).parents[1] / "support" / "crash_worker.py"

    crashed = subprocess.run(
        [sys.executable, str(worker), str(target), "crash-before-replace"],
        check=False,
        timeout=10,
    )

    assert crashed.returncode == CRASH_EXIT_CODE
    assert target.read_text(encoding="utf-8") == "original"

    recovered = subprocess.run(
        [sys.executable, str(worker), str(target), "replace"],
        check=False,
        timeout=10,
    )

    assert recovered.returncode == 0
    assert target.read_text(encoding="utf-8") == "replacement"
