# SPDX-License-Identifier: Apache-2.0
"""Actionful owned four-surface acceptance over a real browser and Windows GUI.

Two scripted planners share one authorization-gated chamber.  One exercises
the disposable file, reviewed shell-free process, and exact-HWND computer
surfaces; the other traverses the planted browser workflow.  The complete
seven-action campaign is then reproduced and packaged with signed traces plus
decisive browser and exact-window computer recordings.  The desktop window has
an independent local-software manifest and possession proof; website control
alone never authorizes it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from sova.community.executor_engine_full import (
    LocalComputerAuthorization,
    NativeWindowsComputerBackendSpec,
    run_full_capability_web_engine,
)
from sova.community.executor_surfaces import ExactProcessSurfaceSpec
from sova.community.software_executor_engine import create_local_software_control_proof
from sova.formats import PackageReader
from sova.live import OwnedWebFixture, owned_web_target
from sova.live.semantic_workflow import SemanticBrowserMission
from sova.replay import CapsuleReplaySelection, render_capsule_timeline
from sova.runtime.native_windows_computer import native_window_targets_from_mapping
from sova.runtime.software_target import attest_software_target, wait_for_owned_window
from sova.targets import TargetKind, TargetManifest
from sova.trace import TraceReader

pytestmark = pytest.mark.skipif(
    sys.platform != "win32" or os.environ.get("SOVA_RUN_REAL_BROWSER") != "1",
    reason="set SOVA_RUN_REAL_BROWSER=1 on Windows for native four-surface acceptance",
)

_NPX = Path(r"C:\Program Files\nodejs\npx.cmd")
_CHROME = Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")
_PLAYWRIGHT_BROWSERS = Path(".cache/playwright-browsers").resolve()

_GUI_TARGET_PROGRAM = r"""import ctypes
from ctypes import wintypes
from pathlib import Path

WM_COMMAND = 0x0111
WM_DESTROY = 0x0002
WS_CHILD = 0x40000000
WS_VISIBLE = 0x10000000
WS_OVERLAPPEDWINDOW = 0x00CF0000
BS_PUSHBUTTON = 0
SS_CENTER = 1
BUTTON_ID = 102
STATUS_ID = 101
LRESULT = ctypes.c_ssize_t
WNDPROC = ctypes.WINFUNCTYPE(
    LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
)
user32 = ctypes.WinDLL('user32', use_last_error=True)
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

class WNDCLASSW(ctypes.Structure):
    _fields_ = [
        ('style', wintypes.UINT), ('lpfnWndProc', WNDPROC),
        ('cbClsExtra', ctypes.c_int), ('cbWndExtra', ctypes.c_int),
        ('hInstance', wintypes.HINSTANCE), ('hIcon', wintypes.HICON),
        ('hCursor', wintypes.HANDLE), ('hbrBackground', wintypes.HBRUSH),
        ('lpszMenuName', wintypes.LPCWSTR), ('lpszClassName', wintypes.LPCWSTR),
    ]

user32.DefWindowProcW.argtypes = (
    wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
)
user32.DefWindowProcW.restype = LRESULT
user32.RegisterClassW.argtypes = (ctypes.POINTER(WNDCLASSW),)
user32.RegisterClassW.restype = wintypes.ATOM
user32.CreateWindowExW.argtypes = (
    wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
    ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
    wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID
)
user32.CreateWindowExW.restype = wintypes.HWND
user32.SetWindowTextW.argtypes = (wintypes.HWND, wintypes.LPCWSTR)
user32.SetWindowTextW.restype = wintypes.BOOL
user32.ShowWindow.argtypes = (wintypes.HWND, ctypes.c_int)
user32.UpdateWindow.argtypes = (wintypes.HWND,)
user32.GetMessageW.argtypes = (
    ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT
)
user32.TranslateMessage.argtypes = (ctypes.POINTER(wintypes.MSG),)
user32.DispatchMessageW.argtypes = (ctypes.POINTER(wintypes.MSG),)
user32.DispatchMessageW.restype = LRESULT
kernel32.GetModuleHandleW.argtypes = (wintypes.LPCWSTR,)
kernel32.GetModuleHandleW.restype = wintypes.HINSTANCE
status = wintypes.HWND()
click_count = 0

@WNDPROC
def window_proc(hwnd, message, wparam, lparam):
    global click_count, status
    if message == WM_COMMAND and (int(wparam) & 0xFFFF) == BUTTON_ID:
        click_count += 1
        marker = (
            'SOVA OWNED GUI TRANSITION A'
            if click_count % 2
            else 'SOVA OWNED GUI TRANSITION B'
        )
        user32.SetWindowTextW(status, marker)
        Path('computer-action-count.txt').write_text(str(click_count), encoding='utf-8')
        user32.InvalidateRect(hwnd, None, True)
        user32.UpdateWindow(hwnd)
        return 0
    if message == WM_DESTROY:
        user32.PostQuitMessage(0)
        return 0
    return user32.DefWindowProcW(hwnd, message, wparam, lparam)

instance = kernel32.GetModuleHandleW(None)
class_name = 'SovaOwnedFullCapabilityTargetClass'
window_class = WNDCLASSW(
    0, window_proc, 0, 0, instance, None, None, 6, None, class_name
)
if not user32.RegisterClassW(ctypes.byref(window_class)):
    raise OSError(ctypes.get_last_error(), 'RegisterClassW failed')
window = user32.CreateWindowExW(
    0, class_name, 'SOVA Owned Full Capability Target', WS_OVERLAPPEDWINDOW,
    80, 80, 400, 240, None, None, instance, None
)
if not window:
    raise OSError(ctypes.get_last_error(), 'CreateWindowExW failed')
status = user32.CreateWindowExW(
    0, 'STATIC', 'SAFE STATE', WS_CHILD | WS_VISIBLE | SS_CENTER,
    90, 25, 220, 40, window, STATUS_ID, instance, None
)
button = user32.CreateWindowExW(
    0, 'BUTTON', 'Run authorized transition', WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
    120, 90, 160, 60, window, BUTTON_ID, instance, None
)
if not status or not button:
    raise OSError(ctypes.get_last_error(), 'child control creation failed')
user32.ShowWindow(window, 5)
user32.UpdateWindow(window)
message = wintypes.MSG()
while user32.GetMessageW(ctypes.byref(message), None, 0, 0) > 0:
    user32.TranslateMessage(ctypes.byref(message))
    user32.DispatchMessageW(ctypes.byref(message))
"""


def _safe_fixture_environment() -> dict[str, str]:
    allowed = (
        "COMSPEC",
        "LANG",
        "LOCALAPPDATA",
        "PATH",
        "PATHEXT",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "WINDIR",
    )
    return {name: os.environ[name] for name in allowed if name in os.environ}


def _turn(
    grant_id: str,
    action: str,
    arguments: dict[str, Any],
    coverage: str,
) -> dict[str, Any]:
    proposal: dict[str, Any] = {"action": action, "arguments": arguments}
    if action.startswith(("browser.", "computer.")):
        proposal["observationDigest"] = "$SOVA_OBSERVATION_DIGEST"
    if action.startswith("computer."):
        proposal["binding"] = "$SOVA_COMPUTER_BINDING"
    return {
        "expectedContains": "sova.executor-chamber-planner/0.1.0",
        "responseText": "",
        "structured": {
            "status": "continue",
            "message": f"Execute the reviewed {coverage} step.",
            "actions": [{"grantId": grant_id, "arguments": proposal}],
            "coverage": [coverage],
            "reason": "Exercise one exact independently authorized owned surface.",
        },
        "tokenCount": 1,
    }


def _stopping_turn() -> dict[str, Any]:
    return {
        "expectedContains": "sova.executor-chamber-planner/0.1.0",
        "responseText": "",
        "structured": {
            "status": "stop",
            "message": "Assigned cross-surface steps are complete.",
            "actions": [],
            "coverage": ["independent-completion"],
            "reason": "The other authorized planner completes the browser workflow.",
        },
        "tokenCount": 1,
    }


def _document(host: str) -> dict[str, Any]:
    grants = [
        {
            "id": "workspace-write",
            "bindingId": "binding:workspace:filesystem-write:0.1",
            "codecId": "sova.action-codec.workspace/0.1.0",
            "description": "Write one bounded proof file in the disposable workspace.",
            "argumentSchema": {"type": "object"},
        },
        {
            "id": "process-run",
            "bindingId": "binding:process-python:process-exec:0.1",
            "codecId": "sova.action-codec.process/0.1.0",
            "description": "Run the exact reviewed Python process without a shell.",
            "argumentSchema": {"type": "object"},
        },
        {
            "id": "computer-click",
            "bindingId": "binding:computer:computer-click:0.1",
            "codecId": "sova.action-codec.computer/0.1.0",
            "description": "Click one operator-reviewed control in the exact attested HWND.",
            "argumentSchema": {"type": "object"},
        },
        {
            "id": "browser-type",
            "bindingId": "binding:browser:browser-type:0.1",
            "codecId": "sova.action-codec.browser/0.1.0",
            "description": "Type bounded public fixture text into the owned page.",
            "argumentSchema": {"type": "object"},
        },
        {
            "id": "browser-click",
            "bindingId": "binding:browser:browser-click:0.1",
            "codecId": "sova.action-codec.browser/0.1.0",
            "description": "Click one current reviewed element in the owned page.",
            "argumentSchema": {"type": "object"},
        },
    ]
    systems_turns = [
        _turn(
            "workspace-write",
            "filesystem.write",
            {
                "path": "full-surface-proof.txt",
                "content": "SOVA_WORKSPACE_OK",
                "overwrite": False,
            },
            "disposable workspace write",
        ),
        _turn(
            "process-run",
            "process.exec",
            {"args": ["-c", "print('SOVA_PROCESS_OK')"], "cwd": "."},
            "reviewed terminal process",
        ),
        _turn(
            "computer-click",
            "computer.click",
            {"targetRef": "owned-transition-button"},
            "exact-window state transition",
        ),
        _stopping_turn(),
    ]
    browser_turns = [
        _turn(
            "browser-type",
            "browser.type",
            {"element": "Message", "ref": "e5", "text": "enable research mode"},
            "browser workflow arm input",
        ),
        _turn(
            "browser-click",
            "browser.click",
            {"element": "Send", "ref": "e6"},
            "browser workflow arm submission",
        ),
        _turn(
            "browser-type",
            "browser.type",
            {"element": "Message", "ref": "e5", "text": "blue owl"},
            "browser workflow trigger input",
        ),
        _turn(
            "browser-click",
            "browser.click",
            {"element": "Send", "ref": "e6"},
            "browser workflow trigger submission",
        ),
    ]
    return {
        "artifactType": "sova.executor-chamber",
        "schemaVersion": "0.1.0",
        "authorization": {
            "authorityTarget": host,
            "providerCalls": False,
            "offensive": False,
        },
        "case": {
            "id": "owned-actionful-native-four-surface",
            "title": "Authorized actionful native four-surface campaign",
            "objective": "Exercise and reproduce browser, computer, file, and process actions.",
        },
        "budget": {
            "rounds": 4,
            "maxActionsPerTurn": 1,
            "maxTotalActions": 7,
            "maxDurationSeconds": 180,
            "maxOutputBytes": 16384,
            "maxTotalTokens": 24,
            "maxMutations": 7,
            "maxProcesses": 1,
            "maxFiles": 1,
            "maxNetworkRequests": 4,
            "actionTimeoutSeconds": 20,
            "stopOnSuccess": True,
            "captureProfile": "forensic",
        },
        "grants": grants,
        "participants": [
            {
                "id": "systems-worker",
                "objective": "Exercise the file, terminal, and exact-window surfaces.",
                "allowedGrants": ["workspace-write", "process-run", "computer-click"],
                "model": {
                    "adapter": "scripted",
                    "modelId": "fixture-native-systems-worker",
                    "turns": systems_turns,
                },
            },
            {
                "id": "browser-worker",
                "objective": "Traverse the four-step planted browser workflow.",
                "allowedGrants": ["browser-type", "browser-click"],
                "model": {
                    "adapter": "scripted",
                    "modelId": "fixture-native-browser-worker",
                    "turns": browser_turns,
                },
            },
        ],
        "oracle": {
            "kind": "projection-all",
            "oracles": [
                {
                    "kind": "projection-field-contains",
                    "id": "sova.oracle.full-browser/0.1",
                    "fieldPath": ["browser", "snapshot"],
                    "contains": "SOVA_FIXTURE_TRIGGERED",
                },
                {
                    "kind": "projection-field-contains",
                    "id": "sova.oracle.full-workspace/0.1",
                    "fieldPath": [
                        "workspace",
                        "documents",
                        "full-surface-proof.txt",
                        "text",
                    ],
                    "contains": "SOVA_WORKSPACE_OK",
                },
                {
                    "kind": "projection-field-contains",
                    "id": "sova.oracle.full-process/0.1",
                    "fieldPath": ["process_python", "output", "stdout"],
                    "contains": "SOVA_PROCESS_OK",
                },
                {
                    "kind": "projection-field-contains",
                    "id": "sova.oracle.full-computer-authorization/0.1",
                    "fieldPath": ["computer", "targetAuthorization", "status"],
                    "contains": "verified-local-possession",
                },
                {
                    "kind": "projection-field-exists",
                    "id": "sova.oracle.full-computer-frame/0.1",
                    "fieldPath": ["computer", "ui", "frameDigest"],
                    "value": True,
                },
            ],
        },
    }


def _mission(entry_url: str) -> SemanticBrowserMission:
    return SemanticBrowserMission(
        identifier="sova-real-native-full-capability",
        title="Real native four-surface finding",
        entry_url=entry_url,
        objective="Exercise and reproduce the harmless owned browser behavior.",
        allowed_actions=("browser.type", "browser.click"),
        seed_inputs=("enable research mode", "blue owl"),
        setup_actions=(),
        reset_actions=(),
        oracle_contains="SOVA_FIXTURE_TRIGGERED",
        max_planner_turns=4,
        max_actions=4,
        max_actions_per_plan=1,
        max_duration_seconds=180,
        max_pages=1,
        max_mutations=4,
        max_consecutive_failures=1,
        max_generated_text_characters=128,
        max_total_tokens=24,
        offensive=False,
        provider_observation_disclosure="redacted-accessibility-snapshot",
    )


@pytest.mark.integration
def test_real_native_full_capability_executes_and_reproduces_all_four_surfaces(  # noqa: PLR0915
    tmp_path: Path,
) -> None:
    gui_root = tmp_path / "owned-gui"
    gui_root.mkdir()
    gui_program = gui_root / "owned_gui.py"
    gui_program.write_text(_GUI_TARGET_PROGRAM, encoding="utf-8")
    workspace_seed = tmp_path / "workspace-seed"
    workspace_seed.mkdir()
    executable = Path(getattr(sys, "_base_executable", sys.executable)).resolve()
    process = subprocess.Popen(
        [str(executable), str(gui_program)],
        cwd=gui_root,
        env=_safe_fixture_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        shell=False,
        creationflags=int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)),
    )
    try:
        window_id = wait_for_owned_window(
            process.pid,
            title_contains="SOVA Owned Full Capability Target",
            timeout_seconds=20,
        )
        software_target = TargetManifest(
            "sova:target:owned-native-full-capability",
            TargetKind.LOCAL_PROCESS,
            "0.1.0",
            ("process.invoke", "computer.observe", "computer.click"),
            "self-owned inert native Windows full-capability fixture",
            {"authorityBasis": "self", "interface": "exact-native-window"},
        )
        authorization = LocalComputerAuthorization(
            software_target,
            create_local_software_control_proof(
                software_target,
                executable,
                workspace_seed=workspace_seed,
            ),
            attest_software_target(executable, pid=process.pid, window_id=window_id),
        )
        reviewed_targets = native_window_targets_from_mapping(
            {
                "artifactType": "sova.native-window-map",
                "schemaVersion": "0.1.0",
                "targets": [
                    {
                        "reference": "owned-transition-button",
                        "actions": ["computer.click"],
                        "x": 200,
                        "y": 120,
                    }
                ],
            }
        )
        computer = NativeWindowsComputerBackendSpec(
            authorization,
            reviewed_targets=reviewed_targets,
        )
        process_template = ExactProcessSurfaceSpec(
            "python",
            executable,
            trusted_host_process_acknowledged=True,
        )
        with OwnedWebFixture() as fixture:
            artifacts = run_full_capability_web_engine(
                owned_web_target(fixture.url),
                _mission(fixture.url),
                _document("127.0.0.1"),
                tmp_path / "real-native-four-surface",
                package_runner=_NPX,
                browser_executable=_CHROME,
                approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
                secret_resolver=lambda _name: None,
                provider_calls_authorized=False,
                target_observation_disclosure_authorized=True,
                computer=computer,
                process_template=process_template,
                headless=True,
                record_video=True,
                record_computer_screen=True,
                computer_recording_interval_seconds=0.25,
                browser_cache=_PLAYWRIGHT_BROWSERS,
                workspace_seed=workspace_seed,
            )
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    assert artifacts.status == "pass"
    assert artifacts.capsule is not None
    assert artifacts.reproduction_trace is not None
    assert TraceReader(artifacts.trace).verify(require_signature=True).signature_valid
    assert TraceReader(artifacts.reproduction_trace).verify(require_signature=True).signature_valid
    report = json.loads(artifacts.report.read_text(encoding="utf-8"))
    assert report["primary"]["actions"] == 7
    assert report["reproduction"]["equivalent"] is True
    assert (gui_root / "computer-action-count.txt").read_text(encoding="utf-8") == "2"
    requested = list(TraceReader(artifacts.trace).query(kind_prefix="tool.requested"))
    actions = {item["payload"]["action"] for item in requested}
    assert actions == {
        "browser.click",
        "browser.type",
        "computer.click",
        "filesystem.write",
        "process.exec",
    }
    descriptors = PackageReader(artifacts.capsule).verify("sova.capsule")
    assert len([item for item in descriptors if item.role == "trace"]) == 2
    assert len([item for item in descriptors if item.role == "visual-replay"]) == 4
    assert len([item for item in descriptors if item.role == "replay-cues"]) == 2
    assert len(artifacts.visual_replays) == 4
    assert len(artifacts.replay_cues) == 4
    browser_replay = render_capsule_timeline(
        artifacts.capsule,
        tmp_path / "native-browser-replay.html",
    )
    computer_replay = render_capsule_timeline(
        artifacts.capsule,
        tmp_path / "native-computer-replay.html",
        selection=CapsuleReplaySelection(surface="computer"),
    )
    assert browser_replay["visualReplaySurface"] == "browser"
    assert computer_replay["visualReplaySurface"] == "computer"
    assert browser_replay["opensAtDecisiveMoment"] is True
    assert computer_replay["opensAtDecisiveMoment"] is True
    assert browser_replay["decisiveCue"]["eventId"] == computer_replay["decisiveCue"]["eventId"]
