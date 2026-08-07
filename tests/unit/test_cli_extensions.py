# SPDX-License-Identifier: Apache-2.0
"""CLI coverage for import-free discovery and approved extension execution."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING

from sova import cli
from sova.extensions import (
    EXTENSION_API_VERSION,
    ExtensionApproval,
    ExtensionKind,
    ExtensionLaunch,
    ExtensionManifest,
    PinnedArgumentFile,
)
from sova.formats import canonical_json_bytes, sha256_digest

if TYPE_CHECKING:
    from _pytest.capture import CaptureFixture
    from _pytest.monkeypatch import MonkeyPatch


def _documents(tmp_path: Path) -> tuple[Path, Path]:
    manifest = ExtensionManifest(
        "example.cli-extension",
        "1.0.0",
        EXTENSION_API_VERSION,
        ExtensionKind.ORACLE,
        ("oracle.fixture",),
        ("reads.request",),
    )
    source = Path(__file__).parents[1] / "fixtures/external_extension.py"
    script = tmp_path / "extension.py"
    shutil.copyfile(source, script)
    executable = Path(sys.executable).resolve()
    launch = ExtensionLaunch(
        manifest.digest,
        "conform",
        (str(executable), str(script)),
        sha256_digest(executable.read_bytes()),
        (PinnedArgumentFile(1, sha256_digest(script.read_bytes())),),
        tmp_path,
        10,
        {},
    )
    manifest_path = tmp_path / "manifest.json"
    launch_path = tmp_path / "launch.json"
    manifest_path.write_bytes(canonical_json_bytes(manifest.to_mapping()) + b"\n")
    launch_path.write_bytes(canonical_json_bytes(launch.to_mapping()) + b"\n")
    return manifest_path, launch_path


def test_extension_discovery_is_import_free_metadata_output(
    capsys: CaptureFixture[str],
) -> None:
    assert cli.main(["extension", "discover"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["artifactType"] == "sova.extension-discovery"
    assert document["importsExtensionCode"] is False
    assert document["establishesTrust"] is False


def test_extension_run_requires_terminal_then_emits_signed_artifacts(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
    capsys: CaptureFixture[str],
) -> None:
    manifest, launch = _documents(tmp_path)
    destination = tmp_path / "output"
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: False))
    arguments = ["extension", "run", str(manifest), str(launch), str(destination)]
    assert cli.main(arguments) == 2
    assert "SOVA-EXTENSION-INTERACTIVE" in capsys.readouterr().err
    assert not destination.exists()

    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr(
        cli,
        "_extension_approval_prompt",
        lambda challenge: challenge.exact_phrase,
    )
    assert cli.main(arguments) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["status"] == "pass"
    assert Path(document["trace"]).is_file()
    assert Path(document["report"]).is_file()


def test_extension_prepare_pins_the_executable_and_script_without_running_it(
    tmp_path: Path,
    capsys: CaptureFixture[str],
) -> None:
    manifest_path, _launch = _documents(tmp_path)
    script = tmp_path / "extension.py"
    executable = Path(sys.executable).resolve()
    output = tmp_path / "prepared.json"
    assert (
        cli.main(
            [
                "extension",
                "prepare",
                str(manifest_path),
                str(output),
                "--executable",
                str(executable),
                "--working-directory",
                str(tmp_path),
                "--argument",
                str(script),
            ]
        )
        == 0
    )
    assert "sha256:" in capsys.readouterr().out
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["executableDigest"] == sha256_digest(executable.read_bytes())
    assert document["argumentFiles"] == [{"index": 1, "digest": sha256_digest(script.read_bytes())}]
    assert (
        cli.main(
            [
                "extension",
                "prepare",
                str(manifest_path),
                str(output),
                "--executable",
                str(executable),
                "--working-directory",
                str(tmp_path),
            ]
        )
        == 2
    )
    assert "SOVA-EXTENSION-OUTPUT" in capsys.readouterr().err


def test_extension_prompt_displays_full_scope_and_exact_phrase(
    monkeypatch: MonkeyPatch,
    capsys: CaptureFixture[str],
) -> None:
    challenge = ExtensionApproval(
        "sha256:" + "a" * 64,
        "AUTHORIZE SOVA EXTENSION aaaaaaaaaaaaaaaa",
        {"warning": "host process is not a security sandbox", "command": ["fixture"]},
    )
    monkeypatch.setattr("builtins.input", lambda _prompt="": challenge.exact_phrase)
    assert cli._extension_approval_prompt(challenge) == challenge.exact_phrase
    error = capsys.readouterr().err
    assert "not a security sandbox" in error
    assert challenge.exact_phrase in error
