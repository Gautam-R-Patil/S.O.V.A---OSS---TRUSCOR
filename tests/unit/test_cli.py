# SPDX-License-Identifier: Apache-2.0
"""Unit contracts for the local format CLI."""

from __future__ import annotations

import importlib
import importlib.metadata
import json
import runpy
import sys
from typing import TYPE_CHECKING

import pytest

import sova
from sova import __version__
from sova.cli import build_parser, main
from sova.trace import TraceWriter

if TYPE_CHECKING:
    from pathlib import Path


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


def test_template_pack_validate_inspect_and_hash_workflow(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    manifest = tmp_path / "manifest.json"
    scenario = tmp_path / "scenario.json"
    capsule = tmp_path / "behavior.sova"

    assert main(["template", "capsule", str(manifest), "--author", "Tester"]) == 0
    assert main(["template", "scenario", str(scenario)]) == 0
    assert main(["pack", str(manifest), str(scenario), str(capsule)]) == 0
    capsys.readouterr()

    assert main(["validate", str(capsule)]) == 0
    assert "VALID" in capsys.readouterr().out
    assert main(["inspect", str(capsule)]) == 0
    assert "Rendering is inert" in capsys.readouterr().out
    assert main(["hash", str(capsule)]) == 0
    assert "sha256:" in capsys.readouterr().out
    assert main(["hash", str(capsule), "--content"]) == 0
    assert "content:" in capsys.readouterr().out
    assert main(["compat", str(capsule)]) == 0
    assert json.loads(capsys.readouterr().out)["lossless"] is True


def test_lint_verify_format_and_json_validation_commands(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    manifest = tmp_path / "manifest.json"
    scenario = tmp_path / "scenario.json"
    capsule = tmp_path / "behavior.sova"

    assert main(["template", "capsule", str(manifest)]) == 0
    assert main(["template", "scenario", str(scenario)]) == 0
    assert main(["pack", str(manifest), str(scenario), str(capsule)]) == 0
    capfd.readouterr()

    assert main(["lint", str(capsule)]) == 1
    assert "SOVA-LINT-UNKNOWN-IMPACT" in capfd.readouterr().out
    assert main(["verify", str(capsule)]) == 0
    assert "VERIFIED capsule objects=1" in capfd.readouterr().out
    assert main(["validate", str(scenario)]) == 0
    assert capfd.readouterr().out == "VALID\n"
    assert main(["format", str(scenario)]) == 0
    formatted = capfd.readouterr().out
    assert json.loads(formatted)["artifactType"] == "sova.scenario"
    assert (
        formatted
        == json.dumps(
            json.loads(formatted),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )


def test_trace_validate_verify_and_playback_commands(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    trace = tmp_path / "run.sova-trace"
    writer = TraceWriter(
        trace,
        authorization={
            "decision": "allowed",
            "scopeDigest": None,
            "decidedBy": "tester",
        },
    )
    writer.append("run.started", {"objective": "CLI fixture"})
    writer.finalize()

    assert main(["validate", str(trace)]) == 0
    assert capsys.readouterr().out == "VALID\n"
    assert main(["verify", str(trace)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["eventCount"] == 1
    assert report["completion"] == "completed"
    assert report["signaturePresent"] is False
    assert main(["playback", str(trace)]) == 0
    assert "run.started" in capsys.readouterr().out
    assert main(["query", str(trace), "--kind-prefix", "run."]) == 0
    assert json.loads(capsys.readouterr().out)["kind"] == "run.started"
    assert main(["export", str(trace), "--format", "otel-jsonl"]) == 0
    assert "trace_id" in capsys.readouterr().out
    assert (
        main(
            [
                "export",
                str(trace),
                "--format",
                "disclosure-json",
                "--sequence",
                "0",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["selectedEventCount"] == 1


def test_cli_recovers_interrupted_trace(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    trace = tmp_path / "interrupted.sova-trace"
    writer = TraceWriter(trace, durability="forensic")
    writer.append("run.started", {})
    writer._close_segment()
    assert main(["recover-trace", str(trace)]) == 0
    assert "sha256:" in capsys.readouterr().out
    assert main(["verify", str(trace)]) == 0
    assert json.loads(capsys.readouterr().out)["completion"] == "recovered"


def test_cli_reports_format_and_io_errors(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    array = tmp_path / "array.json"
    array.write_text("[]", encoding="utf-8")
    assert main(["validate", str(array)]) == 2
    assert "SOVA-CLI-ROOT-TYPE" in capsys.readouterr().err

    missing = tmp_path / "missing.sova"
    assert main(["hash", str(missing)]) == 2
    assert "SOVA-IO-ERROR" in capsys.readouterr().err


def test_clean_lint_branch(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    manifest = tmp_path / "manifest.json"
    scenario = tmp_path / "scenario.json"
    capsule = tmp_path / "behavior.sova"
    assert main(["template", "capsule", str(manifest)]) == 0
    assert main(["template", "scenario", str(scenario)]) == 0
    document = json.loads(manifest.read_text(encoding="utf-8"))
    document["safety"]["impact"] = "none"
    document["license"] = "Apache-2.0"
    manifest.write_text(json.dumps(document), encoding="utf-8")
    assert main(["pack", str(manifest), str(scenario), str(capsule)]) == 0
    capsys.readouterr()
    assert main(["lint", str(capsule)]) == 0
    assert capsys.readouterr().out == "CLEAN\n"
