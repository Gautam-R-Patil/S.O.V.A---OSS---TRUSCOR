# SPDX-License-Identifier: Apache-2.0
"""Unit contracts for DCO message checking."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _check_message(tmp_path: Path, message: str) -> subprocess.CompletedProcess[str]:
    message_path = tmp_path / "COMMIT_EDITMSG"
    message_path.write_text(message, encoding="utf-8")
    script = Path(__file__).parents[2] / "scripts" / "check_dco.py"
    return subprocess.run(
        [sys.executable, str(script), "--commit-msg", str(message_path)],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def test_accepts_valid_sign_off(tmp_path: Path) -> None:
    result = _check_message(
        tmp_path,
        "Subject\n\nSigned-off-by: Example Person <person@example.org>\n",
    )

    assert result.returncode == 0
    assert result.stdout == "DCO_CHECK=PASS\n"


def test_rejects_missing_sign_off(tmp_path: Path) -> None:
    result = _check_message(tmp_path, "Subject only\n")

    assert result.returncode == 1
    assert "lacks a valid Signed-off-by line" in result.stdout
