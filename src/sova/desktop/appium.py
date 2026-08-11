# SPDX-License-Identifier: Apache-2.0
"""Bounded W3C WebDriver executor for Appium Windows and Mac2 drivers."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from http.client import HTTPConnection
from typing import TYPE_CHECKING, Any, Protocol
from urllib.parse import urlsplit

from sova.executors import (
    ActionOutcome,
    ActionRequest,
    CancellationToken,
    Capability,
    EvidenceReference,
    ExecutionContext,
    FailureCause,
    OutcomeStatus,
    SideEffect,
)
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from pathlib import Path

_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_MAX_TEXT_BYTES = 64 * 1024
_HTTP_SUCCESS_MIN = 200
_HTTP_SUCCESS_MAX = 300
_SESSION = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_ELEMENT = re.compile(r"^[A-Za-z0-9._:-]{1,512}$")
_BUNDLE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{1,254}$")
_LOCATOR_STRATEGIES = frozenset({"accessibility id", "name", "class name", "id"})


class DesktopPlatform(StrEnum):
    WINDOWS = "windows"
    MACOS = "macos"


class AppiumTransport(Protocol):
    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None,
        *,
        timeout_seconds: float,
    ) -> dict[str, Any]: ...


class LoopbackAppiumTransport:
    """Bounded loopback-only JSON transport; no credentials or redirects."""

    def __init__(self, endpoint: str) -> None:
        parsed = urlsplit(endpoint)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise FormatError("SOVA-DESKTOP-ENDPOINT", "Appium endpoint must be bare loopback HTTP")
        self._host = parsed.hostname
        self._port = parsed.port or 4723

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None,
        *,
        timeout_seconds: float,
    ) -> dict[str, Any]:
        if method not in {"GET", "POST", "DELETE"} or not path.startswith("/"):
            raise FormatError("SOVA-DESKTOP-HTTP", "unsupported Appium request")
        body = None if payload is None else canonical_json_bytes(payload)
        connection = HTTPConnection(self._host, self._port, timeout=timeout_seconds)
        try:
            connection.request(
                method,
                path,
                body=body,
                headers={"Content-Type": "application/json"} if body is not None else {},
            )
            response = connection.getresponse()
            data = response.read(_MAX_RESPONSE_BYTES + 1)
        except OSError as error:
            raise FormatError("SOVA-DESKTOP-TRANSPORT", "Appium request failed") from error
        finally:
            connection.close()
        if len(data) > _MAX_RESPONSE_BYTES:
            raise FormatError("SOVA-DESKTOP-RESPONSE", "Appium response exceeds 8 MiB")
        try:
            value = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise FormatError("SOVA-DESKTOP-RESPONSE", "Appium response is malformed") from error
        if not _HTTP_SUCCESS_MIN <= response.status < _HTTP_SUCCESS_MAX or not isinstance(
            value, dict
        ):
            raise FormatError("SOVA-DESKTOP-RESPONSE", "Appium returned a failed response")
        return value


@dataclass(frozen=True, slots=True)
class AppiumDesktopTarget:
    platform: DesktopPlatform
    application: str
    workspace: Path | None = None

    def __post_init__(self) -> None:
        if self.platform == DesktopPlatform.WINDOWS:
            if self.workspace is None:
                raise FormatError(
                    "SOVA-DESKTOP-TARGET",
                    "Windows Appium target requires a workspace boundary",
                )
            executable = self._windows_executable()
            workspace = self.workspace.resolve()
            if not workspace.is_dir() or workspace.is_symlink():
                raise FormatError(
                    "SOVA-DESKTOP-TARGET", "desktop workspace must be a real directory"
                )
            try:
                executable.relative_to(workspace)
            except ValueError as error:
                raise FormatError(
                    "SOVA-DESKTOP-TARGET",
                    "Windows fixture executable must stay inside its admitted workspace",
                ) from error
        elif _BUNDLE.fullmatch(self.application) is None:
            raise FormatError("SOVA-DESKTOP-TARGET", "macOS target must be an exact bundle id")

    def _windows_executable(self) -> Path:
        if self.workspace is None:  # pragma: no cover - enforced during construction
            raise FormatError("SOVA-DESKTOP-TARGET", "Windows workspace is absent")
        executable = self.workspace.joinpath(self.application).resolve()
        if not executable.is_file() or executable.is_symlink():
            raise FormatError("SOVA-DESKTOP-TARGET", "Windows fixture executable must exist")
        return executable

    def capabilities(self) -> dict[str, Any]:
        if self.platform == DesktopPlatform.WINDOWS:
            if self.workspace is None:  # pragma: no cover - enforced during construction
                raise FormatError("SOVA-DESKTOP-TARGET", "Windows workspace is absent")
            return {
                "platformName": "Windows",
                "appium:automationName": "Windows",
                "appium:app": str(self._windows_executable()),
                "appium:appWorkingDir": str(self.workspace.resolve()),
                "appium:createSessionTimeout": 20_000,
                "ms:experimental-webdriver": False,
                "ms:forcequit": True,
            }
        return {
            "platformName": "Mac",
            "appium:automationName": "Mac2",
            "appium:bundleId": self.application,
            "appium:noReset": False,
            "appium:skipAppKill": False,
            "appium:showServerLogs": False,
        }


def _value(document: dict[str, Any]) -> Any:
    return document.get("value")


def _locator(inputs: dict[str, Any]) -> tuple[str, str]:
    if set(inputs) - {"strategy", "value", "text"}:
        raise FormatError("SOVA-DESKTOP-INPUT", "desktop action contains unsupported fields")
    strategy = inputs.get("strategy")
    value = inputs.get("value")
    if strategy not in _LOCATOR_STRATEGIES or not isinstance(value, str) or not value:
        raise FormatError(
            "SOVA-DESKTOP-LOCATOR",
            "desktop action requires an accessibility locator",
        )
    return str(strategy), value


class AppiumDesktopExecutor:
    """Execute application-bound accessibility actions with post-action snapshots."""

    name = "sova-appium-desktop"

    def __init__(
        self,
        target: AppiumDesktopTarget,
        *,
        transport: AppiumTransport,
    ) -> None:
        self._target = target
        self._transport = transport
        self._session: str | None = None
        self._closed = False

    def capabilities(self) -> tuple[Capability, ...]:
        return (
            Capability(
                name="computer.snapshot",
                version="0.1",
                side_effect=SideEffect.READ,
                idempotent=True,
                evidence=("ui-source",),
            ),
            Capability(
                name="computer.click",
                version="0.1",
                side_effect=SideEffect.MUTATE,
                idempotent=False,
                evidence=("ui-source-before", "ui-source-after"),
            ),
            Capability(
                name="computer.type",
                version="0.1",
                side_effect=SideEffect.MUTATE,
                idempotent=False,
                evidence=("ui-source-before", "ui-source-after"),
            ),
        )

    def _ensure_session(self, timeout_seconds: float) -> str:
        if self._closed:
            raise FormatError("SOVA-DESKTOP-SESSION", "desktop executor is closed")
        if self._session is not None:
            return self._session
        response = self._transport.request(
            "POST",
            "/session",
            {"capabilities": {"alwaysMatch": self._target.capabilities()}},
            timeout_seconds=timeout_seconds,
        )
        value = _value(response)
        session = response.get("sessionId")
        if isinstance(value, dict) and isinstance(value.get("sessionId"), str):
            session = value["sessionId"]
        if not isinstance(session, str) or _SESSION.fullmatch(session) is None:
            raise FormatError("SOVA-DESKTOP-SESSION", "Appium omitted a valid session id")
        self._session = session
        return session

    def _source(self, session: str, timeout_seconds: float) -> tuple[str, int]:
        response = self._transport.request(
            "GET",
            f"/session/{session}/source",
            None,
            timeout_seconds=timeout_seconds,
        )
        value = _value(response)
        if not isinstance(value, str):
            raise FormatError("SOVA-DESKTOP-SOURCE", "Appium UI source is absent")
        encoded = value.encode()
        if len(encoded) > _MAX_RESPONSE_BYTES:
            raise FormatError("SOVA-DESKTOP-SOURCE", "Appium UI source exceeds 8 MiB")
        return sha256_digest(encoded), len(encoded)

    def _element(self, session: str, inputs: dict[str, Any], timeout_seconds: float) -> str:
        strategy, value = _locator(inputs)
        response = self._transport.request(
            "POST",
            f"/session/{session}/element",
            {"using": strategy, "value": value},
            timeout_seconds=timeout_seconds,
        )
        result = _value(response)
        element = None
        if isinstance(result, dict):
            element = result.get("element-6066-11e4-a52e-4f735466cecf")
        if not isinstance(element, str) or _ELEMENT.fullmatch(element) is None:
            raise FormatError("SOVA-DESKTOP-ELEMENT", "Appium omitted a valid element id")
        return element

    @staticmethod
    def _text_payload(inputs: dict[str, Any]) -> dict[str, Any]:
        text = inputs.get("text")
        if not isinstance(text, str) or len(text.encode()) > _MAX_TEXT_BYTES:
            raise FormatError(
                "SOVA-DESKTOP-TEXT",
                "desktop text is absent or exceeds 64 KiB",
            )
        return {"text": text, "value": list(text)}

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        del context
        effects = {
            "computer.snapshot": SideEffect.READ,
            "computer.click": SideEffect.MUTATE,
            "computer.type": SideEffect.MUTATE,
        }
        effect = effects.get(request.action)
        if effect is None:
            return ActionOutcome(
                request.id,
                OutcomeStatus.UNSUPPORTED,
                SideEffect.READ,
                {},
                error_code="SOVA-DESKTOP-UNSUPPORTED",
            )
        if cancellation.cancelled:
            return ActionOutcome(request.id, OutcomeStatus.CANCELLED, effect, {})
        try:
            session = self._ensure_session(request.timeout_seconds)
            before_digest, before_size = self._source(session, request.timeout_seconds)
            if request.action != "computer.snapshot":
                element = self._element(session, request.inputs, request.timeout_seconds)
                if request.action == "computer.click":
                    payload: dict[str, Any] = {}
                    path = f"/session/{session}/element/{element}/click"
                else:
                    payload = self._text_payload(request.inputs)
                    path = f"/session/{session}/element/{element}/value"
                self._transport.request(
                    "POST",
                    path,
                    payload,
                    timeout_seconds=request.timeout_seconds,
                )
            after_digest, after_size = self._source(session, request.timeout_seconds)
            return ActionOutcome(
                request_id=request.id,
                status=OutcomeStatus.SUCCEEDED,
                side_effect=effect,
                output={
                    "platform": self._target.platform.value,
                    "targetBound": True,
                    "beforeDigest": before_digest,
                    "afterDigest": after_digest,
                    "postObservationCaptured": True,
                },
                evidence=(
                    EvidenceReference(
                        "ui-source-before", "application/xml", before_digest, before_size
                    ),
                    EvidenceReference(
                        "ui-source-after", "application/xml", after_digest, after_size
                    ),
                ),
                verification="w3c-webdriver-post-action-accessibility-snapshot",
                retryable=False,
                error_code=None,
                limitations=(
                    "Appium and its platform driver are provider observation sources.",
                    "Host desktop automation is not a security sandbox.",
                    "No coordinate-only fallback or arbitrary script execution is enabled.",
                ),
                failure_cause=FailureCause.NONE,
            )
        except FormatError as error:
            return ActionOutcome(
                request.id,
                OutcomeStatus.FAILED,
                effect,
                {},
                error_code=error.issue.code,
                limitations=("Desktop provider error details are omitted from evidence.",),
                failure_cause=FailureCause.EXECUTOR,
            )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._session is not None:
            self._transport.request(
                "DELETE",
                f"/session/{self._session}",
                None,
                timeout_seconds=10,
            )
            self._session = None


__all__ = [
    "AppiumDesktopExecutor",
    "AppiumDesktopTarget",
    "AppiumTransport",
    "DesktopPlatform",
    "LoopbackAppiumTransport",
]
