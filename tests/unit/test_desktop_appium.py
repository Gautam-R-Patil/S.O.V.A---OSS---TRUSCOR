# SPDX-License-Identifier: Apache-2.0
"""Accessibility-first Appium desktop adapter tests."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

import sova.desktop.appium as appium_module
from sova.desktop import AppiumDesktopExecutor, AppiumDesktopTarget, DesktopPlatform
from sova.desktop.appium import LoopbackAppiumTransport
from sova.executors import ActionRequest, CancellationToken, ExecutionContext, OutcomeStatus
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from pathlib import Path


class _Transport:
    def __init__(self, responses: list[dict[str, Any]]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str, dict[str, Any] | None]] = []

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None,
        *,
        timeout_seconds: float,
    ) -> dict[str, Any]:
        assert timeout_seconds > 0
        self.calls.append((method, path, payload))
        return self.responses.pop(0)


def _windows_target(tmp_path: Path) -> AppiumDesktopTarget:
    executable = tmp_path / "owned-fixture.exe"
    executable.write_bytes(b"fixture placeholder")
    return AppiumDesktopTarget(DesktopPlatform.WINDOWS, executable.name, tmp_path)


def test_windows_appium_executor_binds_app_and_post_observes_click(tmp_path: Path) -> None:
    target = _windows_target(tmp_path)
    transport = _Transport(
        [
            {"value": {"sessionId": "session-1"}},
            {"value": "<Window><Button Name='Arm'/></Window>"},
            {"value": {"element-6066-11e4-a52e-4f735466cecf": "element-1"}},
            {"value": None},
            {"value": "<Window><Text Name='ARMED'/></Window>"},
            {"value": None},
        ]
    )
    executor = AppiumDesktopExecutor(target, transport=transport)
    outcome = executor.execute(
        ActionRequest(
            "click",
            "computer.click",
            {"strategy": "accessibility id", "value": "arm-button"},
            10,
        ),
        ExecutionContext(tmp_path, {"decision": "allowed"}),
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.SUCCEEDED
    assert outcome.output["targetBound"] is True
    assert outcome.output["beforeDigest"] != outcome.output["afterDigest"]
    assert outcome.verification == "w3c-webdriver-post-action-accessibility-snapshot"
    session_payload = transport.calls[0][2]
    assert session_payload is not None
    capabilities = session_payload["capabilities"]["alwaysMatch"]
    assert capabilities["appium:app"].endswith("owned-fixture.exe")
    assert "power_shell" not in str(session_payload).casefold()
    assert transport.calls[3][1].endswith("/element/element-1/click")
    executor.close()
    assert transport.calls[-1] == ("DELETE", "/session/session-1", None)


def test_mac2_target_and_type_use_exact_bundle_and_accessibility_locator(tmp_path: Path) -> None:
    target = AppiumDesktopTarget(DesktopPlatform.MACOS, "org.sova.OwnedFixture")
    transport = _Transport(
        [
            {"sessionId": "mac-session"},
            {"value": "<Application><TextArea/></Application>"},
            {"value": {"element-6066-11e4-a52e-4f735466cecf": "editor-1"}},
            {"value": None},
            {"value": "<Application><TextArea value='blue owl'/></Application>"},
        ]
    )
    executor = AppiumDesktopExecutor(target, transport=transport)
    outcome = executor.execute(
        ActionRequest(
            "type",
            "computer.type",
            {"strategy": "accessibility id", "value": "editor", "text": "blue owl"},
            10,
        ),
        ExecutionContext(tmp_path, {"decision": "allowed"}),
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.SUCCEEDED
    session_payload = transport.calls[0][2]
    assert session_payload is not None
    capabilities = session_payload["capabilities"]["alwaysMatch"]
    assert capabilities["appium:automationName"] == "Mac2"
    assert capabilities["appium:bundleId"] == "org.sova.OwnedFixture"
    assert transport.calls[3][2] == {"text": "blue owl", "value": list("blue owl")}


def test_desktop_target_and_actions_fail_closed(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside.exe"
    outside.write_bytes(b"fixture")
    with pytest.raises(FormatError, match="inside"):
        AppiumDesktopTarget(DesktopPlatform.WINDOWS, str(outside), tmp_path)
    with pytest.raises(FormatError, match="bundle"):
        AppiumDesktopTarget(DesktopPlatform.MACOS, "not a bundle")

    executor = AppiumDesktopExecutor(
        _windows_target(tmp_path),
        transport=_Transport(
            [
                {"sessionId": "session"},
                {"value": "<Window/>"},
            ]
        ),
    )
    outcome = executor.execute(
        ActionRequest(
            "coordinate",
            "computer.click",
            {"strategy": "coordinates", "value": "10,10"},
            10,
        ),
        ExecutionContext(tmp_path, {"decision": "allowed"}),
        CancellationToken(),
    )
    assert outcome.status == OutcomeStatus.FAILED
    assert outcome.error_code == "SOVA-DESKTOP-LOCATOR"


def test_cancelled_desktop_action_never_starts_session(tmp_path: Path) -> None:
    transport = _Transport([])
    executor = AppiumDesktopExecutor(_windows_target(tmp_path), transport=transport)
    cancellation = CancellationToken()
    cancellation.cancel()
    outcome = executor.execute(
        ActionRequest("cancel", "computer.snapshot", {}, 10),
        ExecutionContext(tmp_path, {"decision": "allowed"}),
        cancellation,
    )
    assert outcome.status == OutcomeStatus.CANCELLED
    assert transport.calls == []


class _Response:
    def __init__(self, status: int, data: bytes) -> None:
        self.status = status
        self.data = data

    def read(self, _limit: int) -> bytes:
        return self.data


class _Connection:
    def __init__(self, response: _Response | None = None, *, fails: bool = False) -> None:
        self.response = response or _Response(200, b"{}")
        self.fails = fails
        self.closed = False

    def request(self, *_args: Any, **_kwargs: Any) -> None:
        if self.fails:
            raise OSError("fixture transport failure")  # noqa: TRY003

    def getresponse(self) -> _Response:
        return self.response

    def close(self) -> None:
        self.closed = True


@pytest.mark.parametrize(
    "endpoint",
    (
        "https://127.0.0.1:4723",
        "http://example.test:4723",
        "http://user@127.0.0.1:4723",
        "http://127.0.0.1:4723/path",
        "http://127.0.0.1:4723?query=yes",
    ),
)
def test_loopback_appium_transport_rejects_nonlocal_or_decorated_endpoints(endpoint: str) -> None:
    with pytest.raises(FormatError, match="bare loopback"):
        LoopbackAppiumTransport(endpoint)


def test_loopback_appium_transport_bounds_protocol_and_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = LoopbackAppiumTransport("http://127.0.0.1:4723")
    with pytest.raises(FormatError, match="unsupported"):
        transport.request("PATCH", "session", None, timeout_seconds=1)

    connection = _Connection(_Response(200, b'{"value":{"ok":true}}'))
    monkeypatch.setattr(appium_module, "HTTPConnection", lambda *_args, **_kwargs: connection)
    assert transport.request("GET", "/status", None, timeout_seconds=1)["value"]["ok"]
    assert connection.closed

    malformed = _Connection(_Response(200, b"not-json"))
    monkeypatch.setattr(appium_module, "HTTPConnection", lambda *_args, **_kwargs: malformed)
    with pytest.raises(FormatError, match="malformed"):
        transport.request("GET", "/status", None, timeout_seconds=1)

    failed = _Connection(_Response(500, b'{"value":"failed"}'))
    monkeypatch.setattr(appium_module, "HTTPConnection", lambda *_args, **_kwargs: failed)
    with pytest.raises(FormatError, match="failed response"):
        transport.request("POST", "/session", {}, timeout_seconds=1)

    oversized = _Connection(_Response(200, b"x" * (8 * 1024 * 1024 + 1)))
    monkeypatch.setattr(appium_module, "HTTPConnection", lambda *_args, **_kwargs: oversized)
    with pytest.raises(FormatError, match="8 MiB"):
        transport.request("GET", "/source", None, timeout_seconds=1)

    broken = _Connection(fails=True)
    monkeypatch.setattr(appium_module, "HTTPConnection", lambda *_args, **_kwargs: broken)
    with pytest.raises(FormatError, match="request failed"):
        transport.request("DELETE", "/session/fixture", None, timeout_seconds=1)
    assert broken.closed


def test_appium_target_and_executor_cover_fail_closed_session_edges(tmp_path: Path) -> None:
    with pytest.raises(FormatError, match="workspace boundary"):
        AppiumDesktopTarget(DesktopPlatform.WINDOWS, "missing.exe")
    missing_workspace = tmp_path / "missing"
    with pytest.raises(FormatError, match="must exist"):
        AppiumDesktopTarget(DesktopPlatform.WINDOWS, "missing.exe", missing_workspace)

    target = _windows_target(tmp_path)
    invalid_session = AppiumDesktopExecutor(target, transport=_Transport([{"value": {}}]))
    outcome = invalid_session.execute(
        ActionRequest("session", "computer.snapshot", {}, 1),
        ExecutionContext(tmp_path, {"decision": "allowed"}),
        CancellationToken(),
    )
    assert outcome.error_code == "SOVA-DESKTOP-SESSION"

    missing_source = AppiumDesktopExecutor(
        target,
        transport=_Transport([{"sessionId": "valid"}, {"value": None}]),
    )
    outcome = missing_source.execute(
        ActionRequest("source", "computer.snapshot", {}, 1),
        ExecutionContext(tmp_path, {"decision": "allowed"}),
        CancellationToken(),
    )
    assert outcome.error_code == "SOVA-DESKTOP-SOURCE"

    missing_element = AppiumDesktopExecutor(
        target,
        transport=_Transport(
            [
                {"sessionId": "valid"},
                {"value": "<Window/>"},
                {"value": {}},
            ]
        ),
    )
    outcome = missing_element.execute(
        ActionRequest(
            "element",
            "computer.click",
            {"strategy": "name", "value": "Arm"},
            1,
        ),
        ExecutionContext(tmp_path, {"decision": "allowed"}),
        CancellationToken(),
    )
    assert outcome.error_code == "SOVA-DESKTOP-ELEMENT"

    executor = AppiumDesktopExecutor(target, transport=_Transport([]))
    unsupported = executor.execute(
        ActionRequest("drag", "computer.drag", {}, 1),
        ExecutionContext(tmp_path, {"decision": "allowed"}),
        CancellationToken(),
    )
    assert unsupported.status == OutcomeStatus.UNSUPPORTED
    executor.close()
    executor.close()
    closed = executor.execute(
        ActionRequest("closed", "computer.snapshot", {}, 1),
        ExecutionContext(tmp_path, {"decision": "allowed"}),
        CancellationToken(),
    )
    assert closed.error_code == "SOVA-DESKTOP-SESSION"
