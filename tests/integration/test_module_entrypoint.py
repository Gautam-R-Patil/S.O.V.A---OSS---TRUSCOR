# SPDX-License-Identifier: Apache-2.0
"""Installed-entry-point smoke tests."""

from __future__ import annotations

import subprocess
import sys

import pytest

from sova import __version__


@pytest.mark.integration
def test_python_module_entrypoint() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "sova", "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0
    assert result.stderr == ""
    assert result.stdout == f"sova {__version__}\n"
