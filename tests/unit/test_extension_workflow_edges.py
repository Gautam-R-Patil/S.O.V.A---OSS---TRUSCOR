# SPDX-License-Identifier: Apache-2.0
"""Refusal and hostile-input tests for the public extension workflow."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from sova.extensions import (
    EXTENSION_API_VERSION,
    ExtensionKind,
    ExtensionLaunch,
    ExtensionManifest,
    PinnedArgumentFile,
    extension_launch_from_mapping,
    prepare_extension_launch,
    run_extension_workflow,
    workflow,
)
from sova.formats import sha256_digest
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from sova.extensions import ExtensionApproval


def _bad_digest(
    _manifest: ExtensionManifest,
    executable: Path,
    script: Path,
    root: Path,
) -> ExtensionLaunch:
    return ExtensionLaunch(
        "bad", "describe", (str(executable), str(script)), "bad", (), root, 1, {}
    )


def _bad_operation(
    manifest: ExtensionManifest,
    executable: Path,
    _script: Path,
    root: Path,
) -> ExtensionLaunch:
    return ExtensionLaunch(
        manifest.digest,
        "unknown",
        (str(executable),),
        sha256_digest(executable.read_bytes()),
        (),
        root,
        1,
        {},
    )


def _empty_command(
    manifest: ExtensionManifest,
    executable: Path,
    _script: Path,
    root: Path,
) -> ExtensionLaunch:
    return ExtensionLaunch(
        manifest.digest,
        "describe",
        (),
        sha256_digest(executable.read_bytes()),
        (),
        root,
        1,
        {},
    )


def _bad_timeout(
    manifest: ExtensionManifest,
    executable: Path,
    _script: Path,
    root: Path,
) -> ExtensionLaunch:
    return ExtensionLaunch(
        manifest.digest,
        "describe",
        (str(executable),),
        sha256_digest(executable.read_bytes()),
        (),
        root,
        61,
        {},
    )


def _bad_conform_payload(
    manifest: ExtensionManifest,
    executable: Path,
    script: Path,
    root: Path,
) -> ExtensionLaunch:
    return ExtensionLaunch(
        manifest.digest,
        "conform",
        (str(executable), str(script)),
        sha256_digest(executable.read_bytes()),
        (PinnedArgumentFile(1, sha256_digest(script.read_bytes())),),
        root,
        1,
        {"not": "empty"},
    )


def _manifest() -> ExtensionManifest:
    return ExtensionManifest(
        "example.edge",
        "1",
        EXTENSION_API_VERSION,
        ExtensionKind.ORACLE,
        (),
        (),
    )


def _script(tmp_path: Path, body: str = "pass\n") -> Path:
    script = tmp_path / "extension.py"
    script.write_text(body, encoding="utf-8")
    return script


def _launch(manifest: ExtensionManifest, script: Path, tmp_path: Path) -> ExtensionLaunch:
    executable = Path(sys.executable).resolve()
    return ExtensionLaunch(
        manifest.digest,
        "describe",
        (str(executable), str(script)),
        sha256_digest(executable.read_bytes()),
        (PinnedArgumentFile(1, sha256_digest(script.read_bytes())),),
        tmp_path,
        5,
        {},
    )


def _approve(challenge: ExtensionApproval) -> str:
    return challenge.exact_phrase


@pytest.mark.parametrize(
    "mutation",
    [
        {"schemaVersion": "9"},
        {"command": "bad"},
        {"argumentFiles": {}},
        {"timeoutSeconds": True},
        {"operation": 7},
    ],
)
def test_extension_launch_parser_rejects_malformed_fields(
    tmp_path: Path,
    mutation: dict[str, Any],
) -> None:
    manifest = _manifest()
    value = _launch(manifest, _script(tmp_path), tmp_path).to_mapping()
    value.update(mutation)
    with pytest.raises(FormatError):
        extension_launch_from_mapping(value)


@pytest.mark.parametrize(
    "constructor",
    [
        _bad_digest,
        _bad_operation,
        _empty_command,
        _bad_timeout,
        _bad_conform_payload,
    ],
)
def test_extension_launch_constructor_rejects_invalid_contracts(
    tmp_path: Path,
    constructor: Any,
) -> None:
    manifest = _manifest()
    executable = Path(sys.executable).resolve()
    script = _script(tmp_path)
    with pytest.raises(FormatError):
        constructor(manifest, executable, script, tmp_path)


def test_extension_workflow_rejects_substitution_digest_and_argument_pins(
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    script = _script(tmp_path)
    launch = _launch(manifest, script, tmp_path)
    other = ExtensionManifest(
        "example.other", "1", EXTENSION_API_VERSION, ExtensionKind.ORACLE, (), ()
    )
    with pytest.raises(FormatError, match="manifest digest does not match"):
        run_extension_workflow(
            other,
            launch,
            tmp_path / "substitution",
            approval_prompt=_approve,
        )

    missing_pin = ExtensionLaunch(
        launch.manifest_digest,
        launch.operation,
        launch.command,
        launch.executable_digest,
        (),
        launch.working_directory,
        launch.timeout_seconds,
        launch.payload,
    )
    with pytest.raises(FormatError, match="requires an exact digest pin"):
        run_extension_workflow(
            manifest,
            missing_pin,
            tmp_path / "missing-pin",
            approval_prompt=_approve,
        )


def test_extension_workflow_rejects_executable_drift_and_inline_code(tmp_path: Path) -> None:
    manifest = _manifest()
    script = _script(tmp_path)
    launch = _launch(manifest, script, tmp_path)
    bad_executable = ExtensionLaunch(
        launch.manifest_digest,
        launch.operation,
        launch.command,
        "sha256:" + "0" * 64,
        launch.argument_files,
        launch.working_directory,
        launch.timeout_seconds,
        launch.payload,
    )
    with pytest.raises(FormatError, match="executable digest changed"):
        run_extension_workflow(
            manifest,
            bad_executable,
            tmp_path / "bad-executable",
            approval_prompt=_approve,
        )

    executable = Path(sys.executable).resolve()
    inline = ExtensionLaunch(
        manifest.digest,
        "describe",
        (str(executable), "-c", "print('unsafe')"),
        sha256_digest(executable.read_bytes()),
        (),
        tmp_path,
        1,
        {},
    )
    with pytest.raises(FormatError, match="inline interpreter code"):
        run_extension_workflow(
            manifest,
            inline,
            tmp_path / "inline",
            approval_prompt=_approve,
        )


@pytest.mark.parametrize(
    ("name", "expected"),
    (
        ("python3.11", frozenset({"-c", "-m"})),
        ("pypy3.10", frozenset({"-c", "-m"})),
        ("node20", frozenset({"-e", "--eval"})),
        ("bash", frozenset({"-c"})),
        ("safe-oracle", frozenset()),
    ),
)
def test_inline_interpreter_detection_is_portable(
    name: str,
    expected: frozenset[str],
) -> None:
    assert workflow._inline_flags_for_executable(Path("/usr/bin") / name) == expected


def test_extension_payload_rejects_secret_shaped_content(tmp_path: Path) -> None:
    manifest = _manifest()
    script = _script(tmp_path)
    launch = _launch(manifest, script, tmp_path)
    with pytest.raises(FormatError, match="credential-shaped"):
        ExtensionLaunch(
            launch.manifest_digest,
            "invoke",
            launch.command,
            launch.executable_digest,
            launch.argument_files,
            launch.working_directory,
            launch.timeout_seconds,
            {"authorization_token": "secret-value-123456"},
        )


def test_extension_workflow_rejects_occupied_destination(tmp_path: Path) -> None:
    manifest = _manifest()
    script = _script(tmp_path)
    destination = tmp_path / "occupied"
    destination.mkdir()
    (destination / "file").write_text("occupied", encoding="utf-8")
    with pytest.raises(FormatError, match="destination is not empty"):
        run_extension_workflow(
            manifest,
            _launch(manifest, script, tmp_path),
            destination,
            approval_prompt=_approve,
        )

    unsafe = tmp_path / "not-a-directory"
    unsafe.write_text("unsafe", encoding="utf-8")
    with pytest.raises(FormatError, match="not a safe directory"):
        run_extension_workflow(
            manifest,
            _launch(manifest, script, tmp_path),
            unsafe,
            approval_prompt=_approve,
        )


def test_extension_launch_requires_absolute_executable_and_working_directory(
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    executable = Path(sys.executable).resolve()
    digest = sha256_digest(executable.read_bytes())
    with pytest.raises(FormatError, match="executable path must be absolute"):
        ExtensionLaunch(manifest.digest, "describe", ("python",), digest, (), tmp_path, 1, {})
    with pytest.raises(FormatError, match="working directory must be absolute"):
        ExtensionLaunch(manifest.digest, "describe", (str(executable),), digest, (), Path(), 1, {})


@pytest.mark.parametrize(
    ("index", "digest"),
    [(True, "sha256:" + "0" * 64), (64, "sha256:" + "0" * 64), (1, "bad")],
)
def test_extension_argument_pin_rejects_invalid_fields(index: int, digest: str) -> None:
    with pytest.raises(FormatError, match="argument-file"):
        PinnedArgumentFile(index, digest)


def test_extension_launch_rejects_duplicate_out_of_range_pins_and_large_payload(
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    executable = Path(sys.executable).resolve()
    digest = sha256_digest(executable.read_bytes())
    pin = PinnedArgumentFile(1, digest)
    with pytest.raises(FormatError, match="pins are invalid"):
        ExtensionLaunch(
            manifest.digest,
            "describe",
            (str(executable), "value"),
            digest,
            (pin, pin),
            tmp_path,
            1,
            {},
        )
    with pytest.raises(FormatError, match="pins are invalid"):
        ExtensionLaunch(
            manifest.digest,
            "describe",
            (str(executable),),
            digest,
            (pin,),
            tmp_path,
            1,
            {},
        )
    with pytest.raises(FormatError, match="exceeds 1 MiB"):
        ExtensionLaunch(
            manifest.digest,
            "invoke",
            (str(executable),),
            digest,
            (),
            tmp_path,
            1,
            {"data": "x" * (1024 * 1024)},
        )


@pytest.mark.parametrize(
    "mutation",
    [
        {"unexpected": True},
        {"argumentFiles": ["bad"]},
        {"argumentFiles": [{"index": True, "digest": "sha256:" + "0" * 64}]},
        {"manifestDigest": 7},
    ],
)
def test_extension_launch_parser_rejects_strict_nested_contracts(
    tmp_path: Path,
    mutation: dict[str, Any],
) -> None:
    manifest = _manifest()
    value = _launch(manifest, _script(tmp_path), tmp_path).to_mapping()
    value.update(mutation)
    with pytest.raises(FormatError):
        extension_launch_from_mapping(value)


def test_extension_manifest_parser_rejects_versions_arrays_and_member_types() -> None:
    manifest = _manifest().to_mapping()
    mutations = (
        {**manifest, "schemaVersion": "9"},
        {**manifest, "capabilities": "bad"},
        {**manifest, "capabilities": [7]},
        {**manifest, "identifier": 7},
    )
    for value in mutations:
        with pytest.raises(FormatError):
            ExtensionManifest.from_mapping(value)


def test_extension_prepare_refuses_in_process_missing_and_directory_arguments(
    tmp_path: Path,
) -> None:
    executable = Path(sys.executable).resolve()
    in_process = ExtensionManifest(
        "example.first-party",
        "1",
        EXTENSION_API_VERSION,
        ExtensionKind.ORACLE,
        (),
        (),
        isolation="in-process",
        trust="first-party",
    )
    with pytest.raises(FormatError, match="requires subprocess"):
        prepare_extension_launch(
            in_process,
            operation="describe",
            executable=executable,
            arguments=(),
            working_directory=tmp_path,
        )
    with pytest.raises(FormatError, match="executable is unsafe"):
        prepare_extension_launch(
            _manifest(),
            operation="describe",
            executable=tmp_path / "missing.exe",
            arguments=(),
            working_directory=tmp_path,
        )
    with pytest.raises(FormatError, match="argument file is unsafe"):
        prepare_extension_launch(
            _manifest(),
            operation="describe",
            executable=executable,
            arguments=(str(tmp_path),),
            working_directory=tmp_path,
        )


def test_extension_workflow_records_failure_and_false_acceptance(tmp_path: Path) -> None:
    manifest = _manifest()
    failing = _script(tmp_path, "raise SystemExit(3)\n")
    destination = tmp_path / "failed"
    with pytest.raises(FormatError, match="extension process failed"):
        run_extension_workflow(
            manifest,
            _launch(manifest, failing, tmp_path),
            destination,
            approval_prompt=_approve,
        )
    assert (destination / "extension.sova-trace").is_file()

    rejecting = tmp_path / "rejecting.py"
    rejecting.write_text(
        "import json, sys\n"
        "r=json.loads(sys.stdin.buffer.readline())\n"
        "print(json.dumps({'protocol':'sova.extension-jsonl/0.1',"
        "'manifestDigest':r['manifestDigest'],'operation':r['operation'],"
        "'accepted':False}))\n",
        encoding="utf-8",
    )
    artifacts = run_extension_workflow(
        manifest,
        _launch(manifest, rejecting, tmp_path),
        tmp_path / "rejected",
        approval_prompt=_approve,
    )
    assert artifacts.status == "fail"
