# SPDX-License-Identifier: Apache-2.0
"""Registry contribution is on by default for every web-engine CLI command;
`--no-contribute` is the one opt-out. `_contribute_run_evidence` is the single
shared helper `engine run-web`, `engine swarm-web`, `engine full-web`, and
`engine stress-web` all call, so exercising it directly covers all four.
"""

from __future__ import annotations

import argparse
from typing import TYPE_CHECKING, Any

import sova.cli as cli_module
from sova.cli import _contribute_run_evidence

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


def _args(**overrides: Any) -> argparse.Namespace:
    defaults: dict[str, Any] = {
        "no_contribute": False,
        "registry_url": None,
        "registry_token": None,
        "contributor_name": "SOVA operator",
        "contributor_identity": "unknown",
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def test_contribution_is_enabled_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    def fake_auto_contribute(**kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {"artifactType": "sova.auto-contribution-result", "contributed": True}

    monkeypatch.setattr(cli_module, "auto_contribute_after_run", fake_auto_contribute)
    capsule = tmp_path / "run.sova"
    capsule.write_bytes(b"")
    trace = tmp_path / "run.sova-trace"
    trace.write_bytes(b"")

    result = _contribute_run_evidence(_args(), capsule=capsule, trace=trace, destination=tmp_path)
    assert result["contributed"] is True
    assert captured["enabled"] is True
    assert captured["registry_client"] is None


def test_no_contribute_flag_disables_contribution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    def fake_auto_contribute(**kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {"artifactType": "sova.auto-contribution-result", "contributed": False}

    monkeypatch.setattr(cli_module, "auto_contribute_after_run", fake_auto_contribute)
    capsule = tmp_path / "run.sova"
    capsule.write_bytes(b"")
    trace = tmp_path / "run.sova-trace"
    trace.write_bytes(b"")

    _contribute_run_evidence(
        _args(no_contribute=True), capsule=capsule, trace=trace, destination=tmp_path
    )
    assert captured["enabled"] is False


def test_no_capsule_short_circuits_without_calling_auto_contribute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    called = False

    def fake_auto_contribute(**_kwargs: Any) -> dict[str, Any]:
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr(cli_module, "auto_contribute_after_run", fake_auto_contribute)
    result = _contribute_run_evidence(
        _args(), capsule=None, trace=tmp_path / "run.sova-trace", destination=tmp_path
    )
    assert called is False
    assert result["contributed"] is False
    assert result["reason"] == "no-capsule-produced"


def test_registry_url_without_token_is_reported_not_raised(tmp_path: Path) -> None:
    capsule = tmp_path / "run.sova"
    capsule.write_bytes(b"")
    result = _contribute_run_evidence(
        _args(registry_url="http://127.0.0.1:8787"),
        capsule=capsule,
        trace=tmp_path / "run.sova-trace",
        destination=tmp_path,
    )
    assert result["contributed"] is False
    assert result["reason"] == "registry-url-without-token"


def test_registry_url_and_token_build_a_registry_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = {}

    def fake_auto_contribute(**kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {"artifactType": "sova.auto-contribution-result", "contributed": True}

    monkeypatch.setattr(cli_module, "auto_contribute_after_run", fake_auto_contribute)
    capsule = tmp_path / "run.sova"
    capsule.write_bytes(b"")
    _contribute_run_evidence(
        _args(
            registry_url="http://127.0.0.1:8787",
            registry_token="a-token-with-at-least-24-characters",  # noqa: S106
        ),
        capsule=capsule,
        trace=tmp_path / "run.sova-trace",
        destination=tmp_path,
    )
    assert captured["registry_client"] is not None
