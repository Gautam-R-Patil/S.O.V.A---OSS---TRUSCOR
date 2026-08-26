# SPDX-License-Identifier: Apache-2.0
"""Measured process-generation admission for local software targets."""

from __future__ import annotations

import os
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from sova.formats.errors import FormatError
from sova.runtime import software_target
from sova.runtime.software_target import (
    attest_software_target,
    observed_process_executable,
    wait_for_owned_window,
)


@pytest.mark.skipif(
    os.name != "nt" and not Path("/proc").is_dir(),
    reason="process identity attestation is unavailable on this platform",
)
def test_current_process_attestation_measures_and_revalidates_generation() -> None:
    measured_executable = observed_process_executable(os.getpid())
    attestation = attest_software_target(measured_executable, pid=os.getpid())
    assert attestation.executable_digest.startswith("sha256:")
    assert attestation.process_start_digest.startswith("sha256:")
    assert attestation.generation_digest.startswith("sha256:")
    assert attestation.to_mapping()["rawExecutablePathCaptured"] is False
    assert attestation.to_mapping()["codeSignatureMeasured"] is False
    attestation.assert_still_live()


@pytest.mark.skipif(
    os.name != "nt" and not Path("/proc").is_dir(),
    reason="process identity attestation is unavailable on this platform",
)
def test_running_process_rejects_substituted_executable() -> None:
    other = Path(os.__file__).resolve()
    if other == Path(sys.executable).resolve():
        pytest.skip("no distinct regular fixture file is available")
    with pytest.raises(FormatError, match="differs from the admitted executable"):
        attest_software_target(other, pid=os.getpid())


def test_attestation_rejects_invalid_pid_and_missing_executable(tmp_path: Path) -> None:
    with pytest.raises(FormatError, match="positive integer"):
        attest_software_target(Path(sys.executable), pid=0)
    with pytest.raises(FormatError, match="existing regular"):
        attest_software_target(tmp_path / "missing.exe", pid=os.getpid())


def test_executable_digest_rejects_empty_and_oversized_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    empty = tmp_path / "empty.exe"
    empty.write_bytes(b"")
    with pytest.raises(FormatError, match="size is outside"):
        software_target._file_digest(empty)
    fixture = tmp_path / "fixture.exe"
    fixture.write_bytes(b"x")
    monkeypatch.setattr(software_target, "_MAX_EXECUTABLE_BYTES", 0)
    with pytest.raises(FormatError, match="size is outside"):
        software_target._file_digest(fixture)


@pytest.mark.skipif(os.name != "nt", reason="window discovery is Windows-only")
def test_window_discovery_validates_selector_ambiguity_timeout_and_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for values in (
        {"pid": 0},
        {"pid": 1, "timeout_seconds": True},
        {"pid": 1, "timeout_seconds": 121},
        {"pid": 1, "title_contains": ""},
        {"pid": 1, "title_contains": "x" * 257},
    ):
        arguments: dict[str, Any] = {"pid": 1, "timeout_seconds": 1.0, **values}
        with pytest.raises(FormatError, match="bounded timeout"):
            wait_for_owned_window(**arguments)

    monkeypatch.setattr(
        software_target, "_windows_owned_top_level_windows", lambda *_args: (10, 11)
    )
    with pytest.raises(FormatError, match="ambiguous"):
        wait_for_owned_window(1, timeout_seconds=0.1)

    monkeypatch.setattr(software_target, "_windows_owned_top_level_windows", lambda *_args: (77,))
    assert wait_for_owned_window(1, timeout_seconds=0.1) == 77

    moments = iter((0.0, 0.0, 0.2))
    monkeypatch.setattr(time, "monotonic", lambda: next(moments))
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(software_target, "_windows_owned_top_level_windows", lambda *_args: ())
    with pytest.raises(FormatError, match="startup deadline"):
        wait_for_owned_window(1, timeout_seconds=0.1)


def test_attestation_detects_stale_generation_and_byte_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / "owned.exe"
    executable.write_bytes(b"owned")
    attestation = software_target.SoftwareTargetAttestation(
        pid=10,
        executable_name=executable.name,
        executable_digest="sha256:" + "1" * 64,
        executable_size=5,
        process_start_digest="sha256:" + "2" * 64,
        window_id=None,
        window_handle_digest=None,
        window_title_digest=None,
        method="fixture",
        code_signature_measured=False,
        _executable_path=executable,
    )
    original_attest = software_target.attest_software_target
    monkeypatch.setattr(
        software_target,
        "attest_software_target",
        lambda *_args, **_kwargs: replace(attestation, process_start_digest="sha256:" + "3" * 64),
    )
    with pytest.raises(FormatError, match="generation changed"):
        attestation.assert_still_live()
    monkeypatch.setattr(software_target, "attest_software_target", original_attest)

    calls = 0

    def digest(_path: Path) -> tuple[str, int]:
        nonlocal calls
        calls += 1
        return ("sha256:" + ("a" if calls == 1 else "b") * 64, 5)

    monkeypatch.setattr(software_target, "_file_digest", digest)
    if os.name == "nt":
        monkeypatch.setattr(
            software_target, "_windows_process_identity", lambda _pid: (executable, 123)
        )
    else:
        monkeypatch.setattr(
            software_target, "_procfs_process_identity", lambda _pid: (executable, 123)
        )
    with pytest.raises(FormatError, match="bytes changed"):
        software_target.attest_software_target(executable, pid=10)


def test_observed_process_executable_rejects_invalid_pid() -> None:
    for pid in (0, -1, True):
        with pytest.raises(FormatError, match="positive integer"):
            observed_process_executable(pid)
