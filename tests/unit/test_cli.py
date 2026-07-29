# SPDX-License-Identifier: Apache-2.0
"""Unit contracts for the placeholder CLI."""

from __future__ import annotations

import importlib
import importlib.metadata
import runpy
import sys

import pytest

import sova
from sova import __version__
from sova.cli import build_parser, main


def test_parser_is_named_sova() -> None:
    assert build_parser().prog == "sova"


def test_empty_invocation_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.startswith("usage: sova")
    assert "pre-alpha" in captured.out


def test_version_is_machine_stable(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])

    captured = capsys.readouterr()
    assert exit_info.value.code == 0
    assert captured.err == ""
    assert captured.out == f"sova {__version__}\n"


def test_module_main_returns_cli_exit(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["sova", "--version"])

    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("sova.__main__", run_name="__main__")

    captured = capsys.readouterr()
    assert exit_info.value.code == 0
    assert captured.out == f"sova {__version__}\n"


def test_source_checkout_has_version_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing_distribution(_name: str) -> str:
        raise importlib.metadata.PackageNotFoundError

    with monkeypatch.context() as context:
        context.setattr(importlib.metadata, "version", missing_distribution)
        reloaded = importlib.reload(sova)
        assert reloaded.__version__ == "0.1.0a0"

    importlib.reload(sova)
