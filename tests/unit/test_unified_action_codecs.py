# SPDX-License-Identifier: Apache-2.0
"""Strict model-output codecs for unified browser, workspace, and process actions."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, cast

import pytest

import sova.runtime.action_codecs as codec_module
from sova.formats import canonical_json_bytes
from sova.formats.errors import FormatError
from sova.live import SemanticBrowserMission
from sova.runtime.action_codecs import (
    BrowserActionCodec,
    ComputerActionCodec,
    ComputerIdentityBinding,
    OciProcessActionCodec,
    ProcessActionCodec,
    ReviewedComputerTarget,
    WorkspaceActionCodec,
    normalize_workspace_relative_path,
)

_OBSERVATION_DIGEST = "sha256:" + "a" * 64
_SESSION_DIGEST = "sha256:" + "b" * 64
_APPLICATION_IDENTITY_DIGEST = "sha256:" + "c" * 64
_WINDOW_IDENTITY_DIGEST = "sha256:" + "d" * 64


def _mission() -> SemanticBrowserMission:
    return SemanticBrowserMission(
        identifier="sova:semantic-mission:codec",
        title="Codec fixture",
        entry_url="http://127.0.0.1:9123/start",
        objective="Exercise one reviewed UI action.",
        allowed_actions=(
            "browser.navigate",
            "browser.click",
            "browser.type",
            "browser.drag",
            "browser.wait",
        ),
        seed_inputs=("safe",),
        setup_actions=(),
        reset_actions=(),
        oracle_contains="FIXTURE",
        max_planner_turns=2,
        max_actions=4,
        max_actions_per_plan=2,
        max_duration_seconds=60,
        max_pages=2,
        max_mutations=4,
        max_consecutive_failures=2,
        max_generated_text_characters=64,
        max_total_tokens=100,
        offensive=False,
        provider_observation_disclosure="redacted-accessibility-snapshot",
    )


def _browser_codec() -> BrowserActionCodec:
    return BrowserActionCodec(
        _mission(),
        frozenset({"f1", "f2"}),
        _OBSERVATION_DIGEST,
        reviewed_targets=frozenset({"[data-reviewed='submit']"}),
    )


def _application_binding() -> ComputerIdentityBinding:
    return ComputerIdentityBinding(
        "application",
        _SESSION_DIGEST,
        _APPLICATION_IDENTITY_DIGEST,
    )


def _application_computer_codec() -> ComputerActionCodec:
    return ComputerActionCodec(
        _application_binding(),
        _OBSERVATION_DIGEST,
        (
            ReviewedComputerTarget(
                "arm-button",
                ("computer.click",),
                {"strategy": "accessibility id", "value": "arm"},
            ),
            ReviewedComputerTarget(
                "editor",
                ("computer.type",),
                {"strategy": "accessibility id", "value": "editor"},
            ),
        ),
    )


def _computer_document(
    codec: ComputerActionCodec,
    action: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    return {
        "action": action,
        "arguments": arguments,
        "binding": codec.binding.to_mapping(),
        "observationDigest": codec.observation_digest,
    }


def test_action_codecs_publish_stable_explicit_versioned_ids() -> None:
    assert _browser_codec().codec_id == "sova.action-codec.browser/0.1.0"
    assert _application_computer_codec().codec_id == "sova.action-codec.computer/0.1.0"
    assert WorkspaceActionCodec().codec_id == "sova.action-codec.workspace/0.1.0"
    assert (
        ProcessActionCodec(Path(sys.executable).resolve()).codec_id
        == "sova.action-codec.process/0.1.0"
    )


def test_browser_codec_reuses_semantic_algebra_and_binds_fresh_locators() -> None:
    request = _browser_codec().decode(
        {
            "action": "browser.click",
            "arguments": {"element": "Submit", "ref": "f2", "doubleClick": False},
            "observationDigest": _OBSERVATION_DIGEST,
        },
        request_id="browser-1",
        timeout_seconds=5,
    )

    assert request.action == "browser.click"
    assert request.inputs == {"doubleClick": False, "element": "Submit", "ref": "f2"}
    assert canonical_json_bytes(request.inputs) == (
        b'{"doubleClick":false,"element":"Submit","ref":"f2"}'
    )

    reviewed = _browser_codec().decode(
        {
            "action": "browser.click",
            "arguments": {
                "element": "Reviewed selector",
                "target": "[data-reviewed='submit']",
            },
            "observationDigest": _OBSERVATION_DIGEST,
        },
        request_id="browser-2",
        timeout_seconds=5,
    )
    assert reviewed.inputs["target"] == "[data-reviewed='submit']"


def test_browser_codec_reproduction_rebinds_only_observation_generation() -> None:
    recorded = {
        "action": "browser.click",
        "arguments": {"element": "Submit", "ref": "f2", "doubleClick": False},
        "observationDigest": "sha256:" + "9" * 64,
    }
    rebound = _browser_codec().rebind_for_reproduction(recorded)
    assert rebound["action"] == recorded["action"]
    assert rebound["arguments"] == recorded["arguments"]
    assert rebound["observationDigest"] == _OBSERVATION_DIGEST
    request = _browser_codec().decode(rebound, request_id="browser-replay", timeout_seconds=5)
    assert request.inputs == recorded["arguments"]


@pytest.mark.parametrize(
    "value",
    [
        {
            "action": "browser.click",
            "arguments": {"element": "Old", "ref": "f9"},
            "observationDigest": _OBSERVATION_DIGEST,
        },
        {
            "action": "browser.click",
            "arguments": {"element": "Old", "ref": "f1"},
            "observationDigest": "sha256:" + "b" * 64,
        },
        {
            "action": "browser.click",
            "arguments": {"element": "Unreviewed", "target": "#arbitrary"},
            "observationDigest": _OBSERVATION_DIGEST,
        },
        {
            "action": "browser.evaluate",
            "arguments": {},
            "observationDigest": _OBSERVATION_DIGEST,
        },
        {
            "action": "browser.navigate",
            "arguments": {"url": "https://example.invalid/escape"},
            "observationDigest": _OBSERVATION_DIGEST,
        },
        {
            "action": "browser.type",
            "arguments": {
                "element": "Message",
                "ref": "f1",
                "text": "Bearer synthetic-credential-value",
            },
            "observationDigest": _OBSERVATION_DIGEST,
        },
        {
            "action": "browser.type",
            "arguments": {
                "element": "Message",
                "ref": "f1",
                "text": ".sova/browser-profiles/default",
            },
            "observationDigest": _OBSERVATION_DIGEST,
        },
        {
            "action": "browser.wait",
            "arguments": {"time": 1},
            "observationDigest": _OBSERVATION_DIGEST,
            "extra": True,
        },
    ],
)
def test_browser_codec_rejects_stale_unreviewed_unknown_cross_origin_and_sensitive(
    value: dict[str, Any],
) -> None:
    with pytest.raises(FormatError):
        _browser_codec().decode(value, request_id="bad", timeout_seconds=5)


def test_computer_codec_emits_exact_appium_accessibility_requests() -> None:
    codec = _application_computer_codec()

    snapshot = codec.decode(
        _computer_document(codec, "computer.snapshot", {}),
        request_id="snapshot",
        timeout_seconds=5,
    )
    click = codec.decode(
        _computer_document(codec, "computer.click", {"targetRef": "arm-button"}),
        request_id="click",
        timeout_seconds=5,
    )
    typed = codec.decode(
        _computer_document(
            codec,
            "computer.type",
            {"targetRef": "editor", "text": "blue owl"},
        ),
        request_id="type",
        timeout_seconds=5,
    )

    assert snapshot.inputs == {}
    assert click.inputs == {"strategy": "accessibility id", "value": "arm"}
    assert typed.inputs == {
        "strategy": "accessibility id",
        "text": "blue owl",
        "value": "editor",
    }
    assert canonical_json_bytes(typed.inputs) == (
        b'{"strategy":"accessibility id","text":"blue owl","value":"editor"}'
    )


def test_computer_codec_reproduction_rebinds_identity_but_preserves_effect_arguments() -> None:
    codec = _application_computer_codec()
    recorded = {
        "action": "computer.type",
        "arguments": {"targetRef": "editor", "text": "blue owl"},
        "binding": ComputerIdentityBinding(
            "application",
            "sha256:" + "1" * 64,
            "sha256:" + "2" * 64,
        ).to_mapping(),
        "observationDigest": "sha256:" + "3" * 64,
    }
    rebound = codec.rebind_for_reproduction(recorded)
    assert rebound["action"] == recorded["action"]
    assert rebound["arguments"] == recorded["arguments"]
    assert rebound["binding"] == codec.binding.to_mapping()
    assert rebound["observationDigest"] == codec.observation_digest


def test_computer_codec_emits_exact_atspi_role_name_request() -> None:
    codec = ComputerActionCodec(
        _application_binding(),
        _OBSERVATION_DIGEST,
        (
            ReviewedComputerTarget(
                "atspi-editor",
                ("computer.type",),
                {"role": "text", "name": "Editor"},
            ),
        ),
    )

    request = codec.decode(
        _computer_document(
            codec,
            "computer.type",
            {"targetRef": "atspi-editor", "text": "bounded value"},
        ),
        request_id="atspi-type",
        timeout_seconds=5,
    )

    assert request.inputs == {"name": "Editor", "role": "text", "text": "bounded value"}


def test_computer_codec_binds_cua_window_and_copies_only_reviewed_targets() -> None:
    binding = ComputerIdentityBinding(
        "window",
        _SESSION_DIGEST,
        _WINDOW_IDENTITY_DIGEST,
        pid=412,
        window_id=73,
    )
    codec = ComputerActionCodec(
        binding,
        _OBSERVATION_DIGEST,
        (
            ReviewedComputerTarget(
                "reviewed-coordinate",
                ("computer.click",),
                {"x": 24, "y": 48},
            ),
            ReviewedComputerTarget(
                "reviewed-element",
                ("computer.type",),
                {"elementToken": "node-7"},
            ),
        ),
    )

    inspect = codec.decode(
        _computer_document(codec, "computer.inspect", {}),
        request_id="inspect",
        timeout_seconds=5,
    )
    click = codec.decode(
        _computer_document(
            codec,
            "computer.click",
            {"targetRef": "reviewed-coordinate"},
        ),
        request_id="click",
        timeout_seconds=5,
    )
    typed = codec.decode(
        _computer_document(
            codec,
            "computer.type",
            {"targetRef": "reviewed-element", "text": "safe"},
        ),
        request_id="type",
        timeout_seconds=5,
    )

    assert inspect.inputs == {"pid": 412, "windowId": 73}
    assert click.inputs == {"pid": 412, "windowId": 73, "x": 24, "y": 48}
    assert typed.inputs == {
        "elementToken": "node-7",
        "pid": 412,
        "text": "safe",
        "windowId": 73,
    }


def test_computer_codec_rejects_stale_binding_unreviewed_coordinates_and_secrets() -> None:
    codec = _application_computer_codec()
    stale_observation = _computer_document(
        codec,
        "computer.click",
        {"targetRef": "arm-button"},
    )
    stale_observation["observationDigest"] = "sha256:" + "e" * 64
    stale_binding = _computer_document(
        codec,
        "computer.click",
        {"targetRef": "arm-button"},
    )
    stale_binding["binding"] = {
        **codec.binding.to_mapping(),
        "sessionDigest": "sha256:" + "f" * 64,
    }
    invalid_documents = (
        stale_observation,
        stale_binding,
        _computer_document(codec, "computer.click", {"targetRef": "not-observed"}),
        _computer_document(
            codec,
            "computer.click",
            {"targetRef": "arm-button", "x": 10, "y": 20},
        ),
        _computer_document(codec, "computer.click", {"targetRef": "editor"}),
        _computer_document(
            codec,
            "computer.type",
            {"targetRef": "editor", "text": "Bearer synthetic-credential-value"},
        ),
        _computer_document(
            codec,
            "computer.type",
            {"targetRef": "editor", "text": "x" * (16 * 1024 + 1)},
        ),
        _computer_document(codec, "computer.hotkey", {"keys": ["CTRL", "S"]}),
        {
            **_computer_document(codec, "computer.snapshot", {}),
            "unexpected": True,
        },
    )

    for document in invalid_documents:
        with pytest.raises(FormatError):
            codec.decode(document, request_id="bad", timeout_seconds=5)


def test_computer_codec_rejects_incompatible_or_unbound_target_contracts() -> None:
    appium = ReviewedComputerTarget(
        "appium",
        ("computer.click",),
        {"strategy": "accessibility id", "value": "arm"},
    )
    atspi = ReviewedComputerTarget(
        "atspi",
        ("computer.click",),
        {"role": "push button", "name": "Arm"},
    )
    coordinate = ReviewedComputerTarget(
        "coordinate",
        ("computer.click",),
        {"x": 10, "y": 20},
    )

    with pytest.raises(FormatError, match="mix"):
        ComputerActionCodec(
            _application_binding(),
            _OBSERVATION_DIGEST,
            (appium, atspi),
        )
    with pytest.raises(FormatError, match="bound"):
        ComputerActionCodec(
            _application_binding(),
            _OBSERVATION_DIGEST,
            (coordinate,),
        )
    with pytest.raises(FormatError, match="bound"):
        ComputerActionCodec(
            ComputerIdentityBinding(
                "window",
                _SESSION_DIGEST,
                _WINDOW_IDENTITY_DIGEST,
                pid=1,
                window_id=2,
            ),
            _OBSERVATION_DIGEST,
            (appium,),
        )
    with pytest.raises(FormatError, match="duplicated"):
        ComputerActionCodec(
            _application_binding(),
            _OBSERVATION_DIGEST,
            (appium, appium),
        )
    with pytest.raises(FormatError, match="admitted"):
        ReviewedComputerTarget(
            "windows-mcp-loc",
            ("computer.click",),
            {"loc": [10, 20]},
        )
    with pytest.raises(FormatError):
        ReviewedComputerTarget(
            "secret-path",
            ("computer.type",),
            {"strategy": "id", "value": "profiles/default"},
        )


def test_computer_identity_binding_rejects_partial_window_and_application_pid() -> None:
    with pytest.raises(FormatError):
        ComputerIdentityBinding(
            "window",
            _SESSION_DIGEST,
            _WINDOW_IDENTITY_DIGEST,
            pid=1,
        )
    with pytest.raises(FormatError):
        ComputerIdentityBinding(
            "application",
            _SESSION_DIGEST,
            _APPLICATION_IDENTITY_DIGEST,
            pid=1,
            window_id=2,
        )


def test_workspace_codec_emits_exact_text_file_requests() -> None:
    codec = WorkspaceActionCodec(max_content_bytes=32)
    request = codec.decode(
        {
            "action": "filesystem.write",
            "arguments": {
                "path": "notes/result.txt",
                "content": "bounded result",
                "overwrite": False,
            },
        },
        request_id="write",
        timeout_seconds=3,
    )
    assert request.action == "filesystem.write"
    assert request.inputs == {
        "path": "notes/result.txt",
        "content": "bounded result",
        "overwrite": False,
    }

    assert normalize_workspace_relative_path(".", allow_root=True) == "."
    assert codec.decode(
        {"action": "filesystem.read", "arguments": {"path": "notes/result.txt"}},
        request_id="read",
        timeout_seconds=3,
    ).inputs == {"path": "notes/result.txt"}
    assert codec.decode(
        {
            "action": "filesystem.move",
            "arguments": {
                "source": "notes/result.txt",
                "destination": "archive/result.txt",
                "overwrite": False,
            },
        },
        request_id="move",
        timeout_seconds=3,
    ).inputs == {
        "source": "notes/result.txt",
        "destination": "archive/result.txt",
        "overwrite": False,
    }


@pytest.mark.parametrize(
    "path",
    [
        "../outside.txt",
        "/outside.txt",
        "notes//result.txt",
        "notes\\result.txt",
        "C:/outside.txt",
        ".sova/browser-profiles/default",
        "profiles/session.json",
        "notes/CON.txt",
        "notes/result.txt/",
    ],
)
def test_workspace_codec_rejects_escape_non_normalized_and_sensitive_paths(path: str) -> None:
    with pytest.raises(FormatError):
        WorkspaceActionCodec().decode(
            {"action": "filesystem.read", "arguments": {"path": path}},
            request_id="read",
            timeout_seconds=3,
        )


@pytest.mark.parametrize(
    "value",
    [
        {"action": "filesystem.mkdir", "arguments": {"path": "notes"}},
        {
            "action": "filesystem.write",
            "arguments": {"path": "out.txt", "content": "toolong", "overwrite": False},
        },
        {
            "action": "filesystem.write",
            "arguments": {
                "path": "out.txt",
                "content": "sk-" + "syntheticcredential123456789",
                "overwrite": False,
            },
        },
        {
            "action": "filesystem.delete",
            "arguments": {"path": "out.txt", "recursive": True},
        },
        {
            "action": "filesystem.move",
            "arguments": {
                "source": "out.txt",
                "destination": "out.txt",
                "overwrite": False,
            },
        },
        {
            "action": "filesystem.move",
            "arguments": {
                "source": "out.txt",
                "destination": "../outside.txt",
                "overwrite": False,
            },
        },
        {
            "action": "filesystem.move",
            "arguments": {
                "source": "out.txt",
                "destination": "archive/out.txt",
                "overwrite": "yes",
            },
        },
        {"action": "filesystem.read", "arguments": ("out.txt",)},
    ],
)
def test_workspace_codec_rejects_unknown_over_limit_sensitive_and_non_json(
    value: dict[str, Any],
) -> None:
    with pytest.raises(FormatError):
        WorkspaceActionCodec(max_content_bytes=4).decode(
            value,
            request_id="bad",
            timeout_seconds=3,
        )


def test_process_codec_builds_exact_prefix_argv_without_a_shell(tmp_path: Path) -> None:
    executable = Path(sys.executable).resolve()
    codec = ProcessActionCodec(executable, ("fixture-tool.py", "--mode", "bounded"))
    request = codec.decode(
        {
            "action": "process.exec",
            "arguments": {
                "args": ["--output=notes/result.txt", "; echo never-interpreted"],
                "cwd": ".",
            },
        },
        request_id="process",
        timeout_seconds=10,
    )
    assert request.inputs == {
        "argv": [
            str(executable),
            "fixture-tool.py",
            "--mode",
            "bounded",
            "--output=notes/result.txt",
            "; echo never-interpreted",
        ],
        "cwd": ".",
    }

    fake_shell = tmp_path / "cmd.exe"
    fake_shell.write_bytes(b"fixture")
    with pytest.raises(FormatError, match="non-shell"):
        ProcessActionCodec(fake_shell.resolve())


@pytest.mark.parametrize(
    "arguments",
    [
        {"command": "tool --output out.txt", "cwd": "."},
        {"args": "tool --output out.txt", "cwd": "."},
        {"args": ["../outside.txt"], "cwd": "."},
        {"args": ["--output=C:/outside.txt"], "cwd": "."},
        {"args": ["-o../outside.txt"], "cwd": "."},
        {"args": ["profiles/session.json"], "cwd": "."},
        {"args": ["Bearer synthetic-credential-value"], "cwd": "."},
        {"args": ["safe\x00bad"], "cwd": "."},
        {"args": ["safe"], "cwd": "../outside"},
    ],
)
def test_process_codec_rejects_shell_strings_escape_sensitive_and_nul(
    arguments: dict[str, Any],
) -> None:
    with pytest.raises(FormatError):
        ProcessActionCodec(Path(sys.executable).resolve()).decode(
            {"action": "process.exec", "arguments": arguments},
            request_id="bad",
            timeout_seconds=5,
        )


def test_process_codec_enforces_argument_count_and_bytes() -> None:
    executable = Path(sys.executable).resolve()
    with pytest.raises(FormatError, match="count"):
        ProcessActionCodec(executable, ("fixed",), max_args=1).decode(
            {"action": "process.exec", "arguments": {"args": ["extra"], "cwd": "."}},
            request_id="count",
            timeout_seconds=5,
        )
    with pytest.raises(FormatError, match="4096"):
        ProcessActionCodec(executable).decode(
            {
                "action": "process.exec",
                "arguments": {"args": ["x" * 4097], "cwd": "."},
            },
            request_id="bytes",
            timeout_seconds=5,
        )


def test_codec_json_path_and_sensitive_helpers_cover_all_fail_closed_shapes() -> None:
    with pytest.raises(FormatError, match="JSON-native"):
        codec_module._canonical_object({"value": object()}, code="FIXTURE")
    with pytest.raises(FormatError, match="1 MiB"):
        codec_module._canonical_object({"value": "x" * (1024 * 1024)}, code="FIXTURE")
    for path in ("x" * 513, "notes/trailing. ", "notes/control\x01.txt"):
        with pytest.raises(FormatError):
            normalize_workspace_relative_path(path)
    with pytest.raises(FormatError, match="UTF-8"):
        normalize_workspace_relative_path("\ud800")
    codec_module._reject_sensitive_material({"safe": ["fixture", {"value": 1}]}, code="SAFE")
    with pytest.raises(FormatError, match="secret-shaped"):
        codec_module._reject_sensitive_material(
            {"nested": [".sova/browser-profiles/default"]},
            code="SENSITIVE",
        )


@pytest.mark.parametrize(
    ("reference", "actions", "locator"),
    [
        ("bad reference", ("computer.click",), {"x": 1, "y": 2}),
        ("target", (), {"x": 1, "y": 2}),
        ("target", ("computer.click", "computer.click"), {"x": 1, "y": 2}),
        ("target", ("computer.unknown",), {"x": 1, "y": 2}),
        ("target", ("computer.click",), {"strategy": "xpath", "value": "id"}),
        ("target", ("computer.click",), {"strategy": "id", "value": "x" * 513}),
        ("target", ("computer.click",), {"elementToken": "bad token"}),
        ("target", ("computer.click",), {"x": -1, "y": 2}),
        ("target", ("computer.click",), {"x": True, "y": 2}),
        ("target", ("computer.click",), {"unknown": "locator"}),
    ],
)
def test_reviewed_computer_target_rejects_every_ambiguous_locator_shape(
    reference: str,
    actions: tuple[str, ...],
    locator: dict[str, Any],
) -> None:
    with pytest.raises(FormatError):
        ReviewedComputerTarget(reference, actions, locator)


def test_computer_binding_codec_and_reproduction_guards_cover_invalid_types() -> None:
    with pytest.raises(FormatError, match="kind"):
        ComputerIdentityBinding(cast("Any", "desktop"), _SESSION_DIGEST, _WINDOW_IDENTITY_DIGEST)
    with pytest.raises(FormatError, match="canonical digests"):
        ComputerIdentityBinding("application", "bad", _APPLICATION_IDENTITY_DIGEST)
    with pytest.raises(FormatError, match="positive"):
        ComputerIdentityBinding(
            "window",
            _SESSION_DIGEST,
            _WINDOW_IDENTITY_DIGEST,
            pid=0,
            window_id=1,
        )
    with pytest.raises(FormatError, match="explicit identity"):
        ComputerActionCodec(cast("Any", "bad"), _OBSERVATION_DIGEST)
    with pytest.raises(FormatError, match="canonical observation"):
        ComputerActionCodec(_application_binding(), "bad")
    with pytest.raises(FormatError, match="immutable contract"):
        ComputerActionCodec(_application_binding(), _OBSERVATION_DIGEST, cast("Any", [object()]))

    codec = _application_computer_codec()
    with pytest.raises(FormatError, match="reproduction fields"):
        codec.rebind_for_reproduction({"action": "computer.snapshot"})
    with pytest.raises(FormatError, match="reviewed target reference"):
        codec.decode(
            _computer_document(codec, "computer.click", {"targetRef": 1}),
            request_id="bad-ref",
            timeout_seconds=1,
        )
    with pytest.raises(FormatError, match="observation action"):
        codec.decode(
            _computer_document(codec, "computer.inspect", {}),
            request_id="wrong-observation",
            timeout_seconds=1,
        )
    assert ComputerActionCodec.reproduction_equivalence_inputs(
        {"pid": 1, "windowId": 2, "x": 3, "y": 4}
    ) == {"x": 3, "y": 4}


def test_workspace_process_and_oci_codec_constructor_limits_are_explicit() -> None:
    for value in (True, 0, 1024 * 1024 + 1):
        with pytest.raises(FormatError, match="content limit"):
            WorkspaceActionCodec(max_content_bytes=value)

    executable = Path(sys.executable).resolve()
    for options in ({"max_args": True}, {"max_arg_bytes": 0}):
        with pytest.raises(FormatError, match="argument limits"):
            ProcessActionCodec(executable, **options)
    with pytest.raises(FormatError, match="argv array"):
        ProcessActionCodec(executable, ("",))
    relative = Path("relative-program")
    with pytest.raises(FormatError, match="non-shell"):
        ProcessActionCodec(relative)
    with pytest.raises(FormatError, match=r"exactly process.exec"):
        ProcessActionCodec(executable).decode(
            {"action": "process.read", "arguments": {"args": [], "cwd": "."}},
            request_id="wrong-action",
            timeout_seconds=1,
        )

    invalid_oci_options: tuple[dict[str, Any], ...] = (
        {"argv_prefix": ["bad"]},
        {"max_args": True},
        {"max_arg_bytes": 0},
        {"max_stdin_bytes": 0},
    )
    for options in invalid_oci_options:
        with pytest.raises(FormatError):
            OciProcessActionCodec("/opt/sova/agent", **options)
    with pytest.raises(FormatError, match="command shell"):
        OciProcessActionCodec("/bin/sh")
    with pytest.raises(FormatError, match="absolute POSIX"):
        OciProcessActionCodec("relative")
    with pytest.raises(FormatError, match="normalized absolute"):
        OciProcessActionCodec("//opt/sova/agent")
    with pytest.raises(FormatError, match="option values"):
        OciProcessActionCodec("/opt/sova/agent", ("--output=",))
    with pytest.raises(FormatError, match="option names"):
        OciProcessActionCodec("/opt/sova/agent", ("--bad/path=value",))
    with pytest.raises(FormatError, match="4096"):
        OciProcessActionCodec("/opt/sova/agent", ("x" * 4097,))


def test_computer_codec_scroll_key_drag_and_unicode_text_branches() -> None:
    codec = ComputerActionCodec(
        ComputerIdentityBinding(
            "window",
            _SESSION_DIGEST,
            _WINDOW_IDENTITY_DIGEST,
            pid=1,
            window_id=2,
        ),
        _OBSERVATION_DIGEST,
        (
            ReviewedComputerTarget("scroll-region", ("computer.scroll",), {"x": 10, "y": 20}),
            ReviewedComputerTarget("key-target", ("computer.key",), {"x": 11, "y": 21}),
            ReviewedComputerTarget("drag-start", ("computer.drag",), {"x": 12, "y": 22}),
            ReviewedComputerTarget("drag-end", ("computer.drag",), {"x": 13, "y": 23}),
            ReviewedComputerTarget("editor", ("computer.type",), {"x": 14, "y": 24}),
        ),
    )
    scroll = codec.decode(
        _computer_document(
            codec,
            "computer.scroll",
            {"targetRef": "scroll-region", "direction": "down", "amount": 2},
        ),
        request_id="scroll",
        timeout_seconds=1,
    )
    assert scroll.inputs["direction"] == "down"
    key = codec.decode(
        _computer_document(codec, "computer.key", {"targetRef": "key-target", "key": "Enter"}),
        request_id="key",
        timeout_seconds=1,
    )
    assert key.inputs["key"] == "Enter"
    drag = codec.decode(
        _computer_document(
            codec,
            "computer.drag",
            {"targetRef": "drag-start", "endTargetRef": "drag-end"},
        ),
        request_id="drag",
        timeout_seconds=1,
    )
    assert drag.inputs["endLocator"] == {"x": 13, "y": 23}

    for arguments, message in (
        ({"targetRef": "scroll-region", "direction": "diagonal", "amount": 2}, "direction"),
        ({"targetRef": "scroll-region", "direction": "down", "amount": True}, "amount"),
        ({"targetRef": "key-target", "key": "CTRL+ALT+DELETE"}, "allowlisted"),
    ):
        action = "computer.key" if "key" in arguments else "computer.scroll"
        with pytest.raises(FormatError, match=message):
            codec.decode(
                _computer_document(codec, action, arguments),
                request_id="invalid",
                timeout_seconds=1,
            )
    with pytest.raises(FormatError, match="valid UTF-8"):
        codec._type_text("\ud800")
    with pytest.raises(FormatError, match="non-empty string"):
        codec_module._bounded_computer_string("", role="locator")
    with pytest.raises(FormatError, match="valid UTF-8"):
        codec_module._bounded_computer_string("\ud800", role="locator")


def test_browser_workspace_process_and_oci_unicode_and_shape_guards() -> None:
    with pytest.raises(FormatError, match="canonical observation"):
        BrowserActionCodec(_mission(), frozenset(), "bad")
    with pytest.raises(FormatError, match="admission sets"):
        BrowserActionCodec(_mission(), frozenset({""}), _OBSERVATION_DIGEST)
    with pytest.raises(FormatError, match="reproduction fields"):
        _browser_codec().rebind_for_reproduction(
            {"action": "browser.click", "arguments": {}, "extra": True}
        )

    workspace = WorkspaceActionCodec()
    with pytest.raises(FormatError, match="arguments must be an object"):
        workspace.decode(
            {"action": "filesystem.read", "arguments": []},
            request_id="workspace-shape",
            timeout_seconds=1,
        )
    with pytest.raises(FormatError, match="not valid UTF-8"):
        codec_module._workspace_write_inputs(
            {"path": "result.txt", "content": "\ud800", "overwrite": False},
            workspace.max_content_bytes,
        )

    executable = Path(sys.executable).resolve()
    with pytest.raises(FormatError, match="not valid UTF-8"):
        ProcessActionCodec(executable)._validate_arguments(["\ud800"], model_supplied=True)
    with pytest.raises(FormatError, match="total encoded byte"):
        ProcessActionCodec(executable, max_arg_bytes=len(str(executable))).decode(
            {"action": "process.exec", "arguments": {"args": ["x"], "cwd": "."}},
            request_id="process-total",
            timeout_seconds=1,
        )

    with pytest.raises(FormatError, match="not valid UTF-8"):
        codec_module._absolute_container_path("/opt/\ud800", role="fixture")
    with pytest.raises(FormatError, match="not valid UTF-8"):
        codec_module._oci_argument("\ud800", role="fixture")
    with pytest.raises(FormatError, match="argument-count"):
        OciProcessActionCodec("/opt/sova/agent", ("fixed",), max_args=1)
    with pytest.raises(FormatError, match="encoded byte"):
        OciProcessActionCodec("/opt/sova/agent", ("fixed",), max_arg_bytes=15)
    oci = OciProcessActionCodec("/opt/sova/agent")
    with pytest.raises(FormatError, match="bounded UTF-8"):
        oci.decode(
            {
                "action": "process.exec",
                "arguments": {"args": [], "stdin": cast("Any", 1)},
            },
            request_id="oci-stdin-shape",
            timeout_seconds=1,
        )
    with pytest.raises(FormatError, match="Unicode scalar values"):
        oci.decode(
            {"action": "process.exec", "arguments": {"args": [], "stdin": "\ud800"}},
            request_id="oci-stdin-unicode",
            timeout_seconds=1,
        )
