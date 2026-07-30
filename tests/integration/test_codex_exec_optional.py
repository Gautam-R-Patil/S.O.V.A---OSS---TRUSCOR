# SPDX-License-Identifier: Apache-2.0
"""Credential-free optional official Codex preflight."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from sova.adapters import CodexExecAdapter

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.integration
def test_official_codex_login_status_when_executable_is_available(tmp_path: Path) -> None:
    fixture = tmp_path / "codex-fixture"
    fixture.mkdir()
    (fixture / ".sova-codex-fixture").write_text("synthetic\n", encoding="utf-8")
    adapter = CodexExecAdapter()
    result = adapter.preflight(fixture)
    if result.status != "authenticated":
        pytest.skip(f"optional official Codex lane unavailable: {result.reason}")
    assert result.status == "authenticated"
