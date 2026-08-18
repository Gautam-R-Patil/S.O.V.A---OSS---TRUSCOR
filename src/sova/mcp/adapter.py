# SPDX-License-Identifier: Apache-2.0
"""MCP executor adapters with SOVA-owned normalization and verification."""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Self
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
from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from collections.abc import Callable

    from sova.mcp.protocol import MCPClient, MCPToolResult

_MAX_TEXT_BYTES = 1024 * 1024
_MAX_BINARY_BYTES = 16 * 1024 * 1024
_MELRA_STATUS_MAP = {
    "verified_success": (OutcomeStatus.SUCCEEDED, FailureCause.NONE),
    "partial": (OutcomeStatus.PARTIAL, FailureCause.EVIDENCE),
    "budget_exhausted": (OutcomeStatus.PARTIAL, FailureCause.EXECUTOR),
    "recovery_required": (OutcomeStatus.PARTIAL, FailureCause.EXECUTOR),
    "awaiting_approval": (OutcomeStatus.DENIED, FailureCause.POLICY),
    "waiting_user": (OutcomeStatus.DENIED, FailureCause.POLICY),
    "policy_blocked": (OutcomeStatus.DENIED, FailureCause.POLICY),
    "cancelled": (OutcomeStatus.CANCELLED, FailureCause.CANCELLATION),
    "failed": (OutcomeStatus.FAILED, FailureCause.EXECUTOR),
    "planned": (OutcomeStatus.PARTIAL, FailureCause.EXECUTOR),
    "running": (OutcomeStatus.PARTIAL, FailureCause.EXECUTOR),
    "verifying": (OutcomeStatus.PARTIAL, FailureCause.EXECUTOR),
}
_MELRA_TERMINAL = {
    "verified_success",
    "partial",
    "budget_exhausted",
    "recovery_required",
    "policy_blocked",
    "cancelled",
    "failed",
}
_MELRA_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_MELRA_EFFECT_RANK = {"read": 0, "mutate": 1, "destructive": 2}
_MAX_CUA_SESSION_ID_CHARS = 128


def _melra_action_catalog() -> tuple[tuple[str, str, SideEffect], ...]:
    browser_reads = ("inspect", "wait", "screenshot", "tabs")
    browser_mutations = (
        "navigate",
        "back",
        "forward",
        "reload",
        "click",
        "type",
        "fill_form",
        "select",
        "press",
        "scroll",
        "upload",
        "download",
        "tab_new",
        "tab_switch",
        "close",
    )
    computer_reads = ("capabilities", "inspect", "screenshot")
    computer_mutations = ("click", "move", "drag", "type", "key", "scroll")
    terminal_reads = ("status", "output")
    terminal_mutations = ("run", "start", "stop", "send")
    groups = (
        ("browser", browser_reads, SideEffect.READ),
        ("browser", browser_mutations, SideEffect.MUTATE),
        ("computer", computer_reads, SideEffect.READ),
        ("computer", computer_mutations, SideEffect.MUTATE),
        ("terminal", terminal_reads, SideEffect.READ),
        ("terminal", terminal_mutations, SideEffect.MUTATE),
    )
    return tuple(
        (kind, action, side_effect) for kind, actions, side_effect in groups for action in actions
    )


@dataclass(frozen=True, slots=True)
class ToolMapping:
    """Map one portable SOVA action to one server-specific MCP tool."""

    action: str
    tool: str
    version: str
    side_effect: SideEffect
    idempotent: bool
    evidence: tuple[str, ...]
    argument_builder: Callable[[Mapping[str, Any]], dict[str, Any]]
    post_observe_tool: str | None = None
    post_observe_arguments: Mapping[str, Any] | None = None
    result_validator: Callable[[MCPToolResult, MCPToolResult | None], None] | None = None


@dataclass(frozen=True, slots=True)
class MelraTaskState:
    """Secret-free normalized state returned by MELRA status and cancel tools."""

    task_id: str
    provider_status: str
    normalized_status: OutcomeStatus
    terminal: bool

    def to_mapping(self) -> dict[str, Any]:
        return {
            "taskId": self.task_id,
            "providerStatus": self.provider_status,
            "normalizedStatus": self.normalized_status.value,
            "terminal": self.terminal,
        }


@dataclass(frozen=True, slots=True)
class _MelraApprovalExpectation:
    task_id: str
    capability: str
    operation: Mapping[str, Any]
    maximum_effect: SideEffect


def _identity(arguments: Mapping[str, Any]) -> dict[str, Any]:
    return dict(arguments)


def _selected(
    *names: str,
    constants: Mapping[str, Any] | None = None,
) -> Callable[[Mapping[str, Any]], dict[str, Any]]:
    def build(arguments: Mapping[str, Any]) -> dict[str, Any]:
        return {
            **dict(constants or {}),
            **{name: arguments[name] for name in names if name in arguments},
        }

    return build


def _renamed(
    names: Mapping[str, str],
    *,
    constants: Mapping[str, Any] | None = None,
) -> Callable[[Mapping[str, Any]], dict[str, Any]]:
    def build(arguments: Mapping[str, Any]) -> dict[str, Any]:
        return {
            **dict(constants or {}),
            **{
                destination: arguments[source]
                for source, destination in names.items()
                if source in arguments
            },
        }

    return build


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise FormatError("SOVA-MCP-NAVIGATION-URL", "browser URL must be an HTTP(S) origin")
    default_port = 80 if parsed.scheme == "http" else 443
    port = parsed.port or default_port
    rendered_port = "" if port == default_port else f":{port}"
    return f"{parsed.scheme}://{parsed.hostname.casefold()}{rendered_port}"


def _navigate_builder(
    allowed_origins: tuple[str, ...],
) -> Callable[[Mapping[str, Any]], dict[str, Any]]:
    normalized = frozenset(_origin(value) for value in allowed_origins)

    def build(arguments: Mapping[str, Any]) -> dict[str, Any]:
        value = arguments.get("url")
        if not isinstance(value, str):
            raise FormatError("SOVA-MCP-NAVIGATION-URL", "browser navigation requires a URL")
        requested = _origin(value)
        if normalized and requested not in normalized:
            raise FormatError(
                "SOVA-MCP-NAVIGATION-SCOPE",
                "browser navigation URL is outside the admitted origin set",
                details={"requestedOrigin": requested, "allowedOrigins": sorted(normalized)},
            )
        return {"url": value}

    return build


def _observed_page_urls(result: MCPToolResult | None) -> tuple[str, ...]:
    if result is None:
        return ()
    values: list[str] = []
    for item in result.content:
        text = item.get("text")
        if not isinstance(text, str):
            continue
        values.extend(
            line.removeprefix("- Page URL:").strip()
            for line in text.splitlines()
            if line.startswith("- Page URL:") and line.removeprefix("- Page URL:").strip()
        )
        values.extend(
            match.group(1) for match in re.finditer(r'RootWebArea[^\r\n]*?\burl="([^"]+)"', text)
        )
    structured = result.structured_content
    if isinstance(structured, Mapping) and isinstance(structured.get("url"), str):
        values.append(structured["url"])
    return tuple(values)


def _page_origin_validator(
    allowed_origins: tuple[str, ...],
) -> Callable[[MCPToolResult, MCPToolResult | None], None]:
    allowed = frozenset(_origin(value) for value in allowed_origins)

    def validate(result: MCPToolResult, observation: MCPToolResult | None) -> None:
        observed = (*_observed_page_urls(result), *_observed_page_urls(observation))
        if not observed:
            raise FormatError(
                "SOVA-MCP-BROWSER-LOCATION",
                "browser action supplied no independently observable final page URL",
            )
        outside = sorted({_origin(url) for url in observed} - allowed) if allowed else []
        if outside:
            raise FormatError(
                "SOVA-MCP-BROWSER-ORIGIN-DRIFT",
                "browser ended outside the admitted origin set",
                details={"observedOrigins": outside, "allowedOrigins": sorted(allowed)},
            )

    return validate


def _normalize_result(
    request: ActionRequest,
    result: MCPToolResult,
    *,
    side_effect: SideEffect,
    verification: str,
    observation: MCPToolResult | None = None,
) -> ActionOutcome:
    output: dict[str, Any] = {}
    evidence: list[EvidenceReference] = []
    text_items: list[str] = []
    for index, item in enumerate(result.content):
        kind = item.get("type")
        if kind == "text" and isinstance(item.get("text"), str):
            encoded = item["text"].encode("utf-8")
            text_items.append(encoded[:_MAX_TEXT_BYTES].decode("utf-8", errors="replace"))
            evidence.append(
                EvidenceReference("mcp-text", "text/plain", sha256_digest(encoded), len(encoded))
            )
        elif kind in {"image", "audio"} and isinstance(item.get("data"), str):
            try:
                data = base64.b64decode(item["data"], validate=True)
            except (ValueError, binascii.Error) as error:
                raise FormatError("SOVA-MCP-CONTENT", "invalid base64 MCP content") from error
            if len(data) > _MAX_BINARY_BYTES:
                raise FormatError("SOVA-MCP-CONTENT-LIMIT", "MCP binary content exceeds budget")
            media_type = str(item.get("mimeType", "application/octet-stream"))
            evidence.append(
                EvidenceReference(f"mcp-{kind}-{index}", media_type, sha256_digest(data), len(data))
            )
        elif kind == "resource_link":
            link = {key: item[key] for key in ("uri", "name", "mimeType") if key in item}
            output.setdefault("resourceLinks", []).append(link)
        else:
            output.setdefault("unrecognizedContent", []).append(str(kind))
    if text_items:
        output["text"] = text_items
    if result.structured_content is not None:
        encoded = canonical_json_bytes(result.structured_content)
        if len(encoded) > _MAX_TEXT_BYTES:
            raise FormatError("SOVA-MCP-CONTENT-LIMIT", "structured MCP content exceeds budget")
        output["structured"] = result.structured_content
        evidence.append(
            EvidenceReference(
                "mcp-structured", "application/json", sha256_digest(encoded), len(encoded)
            )
        )
    if observation is not None:
        observation_bytes = canonical_json_bytes(
            {
                "content": list(observation.content),
                "structuredContent": observation.structured_content,
                "isError": observation.is_error,
            }
        )
        output["postObservationDigest"] = sha256_digest(observation_bytes)
        evidence.append(
            EvidenceReference(
                "post-observation",
                "application/vnd.mcp.result+json",
                sha256_digest(observation_bytes),
                len(observation_bytes),
            )
        )
    status = OutcomeStatus.FAILED if result.is_error else OutcomeStatus.SUCCEEDED
    return ActionOutcome(
        request.id,
        status,
        side_effect,
        output,
        tuple(evidence),
        verification=verification,
        retryable=False,
        error_code="SOVA-MCP-TOOL-ERROR" if result.is_error else None,
        limitations=(
            "MCP tool annotations and receipts are untrusted provider input.",
            "SOVA independently records authorization, result normalization, and evidence.",
        ),
        failure_cause=FailureCause.EXECUTOR if result.is_error else FailureCause.NONE,
    )


class MCPExecutorAdapter:
    """Capability-discovered adapter for direct MCP tool mappings."""

    def __init__(
        self,
        name: str,
        client: MCPClient,
        mappings: tuple[ToolMapping, ...],
    ) -> None:
        if not name or not mappings:
            raise FormatError("SOVA-MCP-ADAPTER", "adapter name and mappings are required")
        self._name = name
        self._client = client
        tools = {tool.name: tool for tool in client.list_tools()}
        self._mappings = {mapping.action: mapping for mapping in mappings if mapping.tool in tools}
        self._tools = tools
        self._closed = False

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    @property
    def name(self) -> str:
        return self._name

    @property
    def discovered_tools(self) -> tuple[str, ...]:
        return tuple(sorted(self._tools))

    def capabilities(self) -> tuple[Capability, ...]:
        return tuple(
            Capability(
                mapping.action,
                mapping.version,
                mapping.side_effect,
                mapping.idempotent,
                mapping.evidence,
            )
            for mapping in sorted(self._mappings.values(), key=lambda item: item.action)
        )

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        del context
        mapping = self._mappings.get(request.action)
        if mapping is None:
            return ActionOutcome(
                request.id,
                OutcomeStatus.UNSUPPORTED,
                SideEffect.READ,
                {},
                error_code="SOVA-MCP-UNSUPPORTED",
            )
        if cancellation.cancelled:
            return ActionOutcome(
                request.id,
                OutcomeStatus.CANCELLED,
                mapping.side_effect,
                {},
                error_code="SOVA-MCP-CANCELLED",
            )
        try:
            result = self._client.call_tool(
                mapping.tool,
                mapping.argument_builder(request.inputs),
                timeout_seconds=request.timeout_seconds,
            )
            observation = None
            verification = (
                "direct-read-observation"
                if mapping.side_effect == SideEffect.READ
                else "provider-result-only"
            )
            if mapping.post_observe_tool is not None and not result.is_error:
                observation = self._client.call_tool(
                    mapping.post_observe_tool,
                    mapping.post_observe_arguments or {},
                    timeout_seconds=request.timeout_seconds,
                )
                verification = (
                    "post-action-observation" if not observation.is_error else "observation-failed"
                )
            if mapping.result_validator is not None and not result.is_error:
                mapping.result_validator(result, observation)
            return _normalize_result(
                request,
                result,
                side_effect=mapping.side_effect,
                verification=verification,
                observation=observation,
            )
        except FormatError as error:
            return ActionOutcome(
                request.id,
                (
                    OutcomeStatus.TIMEOUT
                    if error.issue.code == "SOVA-MCP-TIMEOUT"
                    else OutcomeStatus.FAILED
                ),
                mapping.side_effect,
                {},
                verification="adapter-protocol-failure",
                retryable=mapping.idempotent,
                error_code=error.issue.code,
                limitations=("MCP failure details are omitted from trace payloads.",),
                failure_cause=(
                    FailureCause.TIMEOUT
                    if error.issue.code == "SOVA-MCP-TIMEOUT"
                    else FailureCause.EXECUTOR
                ),
            )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if "browser_close" in self._tools:
                with suppress(FormatError):
                    self._client.call_tool("browser_close", {}, timeout_seconds=10.0)
        finally:
            self._client.close()


def playwright_mappings(*, allowed_origins: tuple[str, ...] = ()) -> tuple[ToolMapping, ...]:
    """Pinned portable subset of Microsoft Playwright MCP actions."""
    snapshot = "browser_snapshot"
    location_validator = _page_origin_validator(allowed_origins)
    return (
        ToolMapping(
            action="browser.snapshot",
            tool=snapshot,
            version="0.1",
            side_effect=SideEffect.READ,
            idempotent=True,
            evidence=("aria-snapshot",),
            argument_builder=_identity,
            result_validator=location_validator,
        ),
        ToolMapping(
            action="browser.navigate",
            tool="browser_navigate",
            version="0.1",
            side_effect=SideEffect.MUTATE,
            idempotent=False,
            evidence=("url", "snapshot"),
            argument_builder=_navigate_builder(allowed_origins),
            post_observe_tool=snapshot,
            result_validator=location_validator,
        ),
        ToolMapping(
            action="browser.click",
            tool="browser_click",
            version="0.1",
            side_effect=SideEffect.MUTATE,
            idempotent=False,
            evidence=("snapshot",),
            argument_builder=_selected("element", "target", "doubleClick"),
            post_observe_tool=snapshot,
            result_validator=location_validator,
        ),
        ToolMapping(
            action="browser.type",
            tool="browser_type",
            version="0.1",
            side_effect=SideEffect.MUTATE,
            idempotent=False,
            evidence=("snapshot",),
            argument_builder=_selected("element", "target", "text", "submit", "slowly"),
            post_observe_tool=snapshot,
            result_validator=location_validator,
        ),
        ToolMapping(
            action="browser.wait",
            tool="browser_wait_for",
            version="0.1",
            side_effect=SideEffect.READ,
            idempotent=True,
            evidence=("snapshot",),
            argument_builder=_selected("time", "text", "textGone"),
            post_observe_tool=snapshot,
            result_validator=location_validator,
        ),
        ToolMapping(
            action="browser.tabs",
            tool="browser_tabs",
            version="0.1",
            side_effect=SideEffect.MUTATE,
            idempotent=False,
            evidence=("tabs",),
            argument_builder=_selected("action", "index", "url"),
            post_observe_tool=snapshot,
        ),
        ToolMapping(
            action="browser.screenshot",
            tool="browser_take_screenshot",
            version="0.1",
            side_effect=SideEffect.READ,
            idempotent=True,
            evidence=("screenshot",),
            argument_builder=_identity,
        ),
        ToolMapping(
            action="browser.console",
            tool="browser_console_messages",
            version="0.1",
            side_effect=SideEffect.READ,
            idempotent=True,
            evidence=("console-messages",),
            argument_builder=_selected("level"),
            post_observe_tool=snapshot,
            result_validator=location_validator,
        ),
        ToolMapping(
            action="browser.network",
            tool="browser_network_requests",
            version="0.1",
            side_effect=SideEffect.READ,
            idempotent=True,
            evidence=("network-requests",),
            argument_builder=_selected("includeStatic"),
            post_observe_tool=snapshot,
            result_validator=location_validator,
        ),
    )


def _devtools_navigate_builder(
    allowed_origins: tuple[str, ...],
) -> Callable[[Mapping[str, Any]], dict[str, Any]]:
    checked = _navigate_builder(allowed_origins)

    def build(arguments: Mapping[str, Any]) -> dict[str, Any]:
        return {"type": "url", **checked(arguments)}

    return build


def _devtools_wait_builder(arguments: Mapping[str, Any]) -> dict[str, Any]:
    text = arguments.get("text")
    if isinstance(text, str) and text:
        return {"text": [text]}
    if isinstance(text, list) and text and all(isinstance(item, str) and item for item in text):
        return {"text": list(text)}
    raise FormatError("SOVA-MCP-WAIT", "Chrome DevTools wait requires one or more texts")


def chrome_devtools_mappings(*, allowed_origins: tuple[str, ...] = ()) -> tuple[ToolMapping, ...]:
    """Portable browser subset implemented through Chrome DevTools MCP 1.6.0."""
    snapshot = "take_snapshot"
    location_validator = _page_origin_validator(allowed_origins)
    return (
        ToolMapping(
            action="browser.snapshot",
            tool=snapshot,
            version="0.1",
            side_effect=SideEffect.READ,
            idempotent=True,
            evidence=("accessibility-snapshot",),
            argument_builder=_selected("verbose"),
            result_validator=location_validator,
        ),
        ToolMapping(
            action="browser.navigate",
            tool="navigate_page",
            version="0.1",
            side_effect=SideEffect.MUTATE,
            idempotent=False,
            evidence=("url", "snapshot"),
            argument_builder=_devtools_navigate_builder(allowed_origins),
            post_observe_tool=snapshot,
            result_validator=location_validator,
        ),
        ToolMapping(
            action="browser.click",
            tool="click",
            version="0.1",
            side_effect=SideEffect.MUTATE,
            idempotent=False,
            evidence=("snapshot",),
            argument_builder=_renamed(
                {"target": "uid", "doubleClick": "dblClick"},
                constants={"includeSnapshot": True},
            ),
            post_observe_tool=snapshot,
            result_validator=location_validator,
        ),
        ToolMapping(
            action="browser.type",
            tool="fill",
            version="0.1",
            side_effect=SideEffect.MUTATE,
            idempotent=False,
            evidence=("snapshot",),
            argument_builder=_renamed(
                {"target": "uid", "text": "value"},
                constants={"includeSnapshot": True},
            ),
            post_observe_tool=snapshot,
            result_validator=location_validator,
        ),
        ToolMapping(
            action="browser.wait",
            tool="wait_for",
            version="0.1",
            side_effect=SideEffect.READ,
            idempotent=True,
            evidence=("snapshot",),
            argument_builder=_devtools_wait_builder,
            post_observe_tool=snapshot,
            result_validator=location_validator,
        ),
        ToolMapping(
            action="browser.screenshot",
            tool="take_screenshot",
            version="0.1",
            side_effect=SideEffect.READ,
            idempotent=True,
            evidence=("screenshot",),
            argument_builder=_selected("format", "fullPage", "quality", "uid"),
        ),
        ToolMapping(
            action="browser.console",
            tool="list_console_messages",
            version="0.1",
            side_effect=SideEffect.READ,
            idempotent=True,
            evidence=("console-messages",),
            argument_builder=_selected("types", "pageIdx", "pageSize"),
            post_observe_tool=snapshot,
            result_validator=location_validator,
        ),
        ToolMapping(
            action="browser.network",
            tool="list_network_requests",
            version="0.1",
            side_effect=SideEffect.READ,
            idempotent=True,
            evidence=("network-requests",),
            argument_builder=_selected("resourceTypes", "pageIdx", "pageSize"),
            post_observe_tool=snapshot,
            result_validator=location_validator,
        ),
    )


def windows_mcp_mappings() -> tuple[ToolMapping, ...]:
    """Deliberately excludes PowerShell, files, processes, registry, and clipboard."""
    snapshot = "Snapshot"
    return (
        ToolMapping(
            action="computer.snapshot",
            tool=snapshot,
            version="0.1",
            side_effect=SideEffect.READ,
            idempotent=True,
            evidence=("accessibility-tree",),
            argument_builder=_selected("use_vision", "use_dom", "display"),
        ),
        ToolMapping(
            action="computer.screenshot",
            tool="Screenshot",
            version="0.1",
            side_effect=SideEffect.READ,
            idempotent=True,
            evidence=("screenshot",),
            argument_builder=_selected("display"),
        ),
        ToolMapping(
            action="computer.click",
            tool="Click",
            version="0.1",
            side_effect=SideEffect.MUTATE,
            idempotent=False,
            evidence=("snapshot",),
            argument_builder=_selected("loc", "button", "clicks"),
            post_observe_tool=snapshot,
        ),
        ToolMapping(
            action="computer.type",
            tool="Type",
            version="0.1",
            side_effect=SideEffect.MUTATE,
            idempotent=False,
            evidence=("snapshot",),
            argument_builder=_selected("text", "loc", "clear"),
            post_observe_tool=snapshot,
        ),
        ToolMapping(
            action="computer.scroll",
            tool="Scroll",
            version="0.1",
            side_effect=SideEffect.MUTATE,
            idempotent=False,
            evidence=("snapshot",),
            argument_builder=_selected("direction", "amount", "loc"),
            post_observe_tool=snapshot,
        ),
        ToolMapping(
            action="computer.wait",
            tool="WaitFor",
            version="0.1",
            side_effect=SideEffect.READ,
            idempotent=True,
            evidence=("snapshot",),
            argument_builder=_identity,
            post_observe_tool=snapshot,
        ),
    )


_CUA_ACTIONS: dict[str, tuple[str, SideEffect, bool, tuple[str, ...]]] = {
    "computer.windows": ("list_windows", SideEffect.READ, True, ("window-list",)),
    "computer.inspect": (
        "get_window_state",
        SideEffect.READ,
        True,
        ("accessibility-tree", "window-screenshot"),
    ),
    "computer.desktop": (
        "get_desktop_state",
        SideEffect.READ,
        True,
        ("desktop-screenshot",),
    ),
    "computer.click": ("click", SideEffect.MUTATE, False, ("window-state",)),
    "computer.type": ("type_text", SideEffect.MUTATE, False, ("window-state",)),
    "computer.key": ("press_key", SideEffect.MUTATE, False, ("window-state",)),
    "computer.hotkey": ("hotkey", SideEffect.MUTATE, False, ("window-state",)),
    "computer.scroll": ("scroll", SideEffect.MUTATE, False, ("window-state",)),
}
_CUA_INPUTS: dict[str, tuple[str, ...]] = {
    "computer.windows": ("pid", "onScreenOnly"),
    "computer.inspect": ("pid", "windowId", "query", "maxDepth", "maxElements"),
    "computer.desktop": (),
    "computer.click": (
        "pid",
        "windowId",
        "elementToken",
        "x",
        "y",
        "button",
        "count",
        "allowForegroundEscalation",
    ),
    "computer.type": (
        "pid",
        "windowId",
        "elementToken",
        "x",
        "y",
        "text",
        "delayMs",
        "allowForegroundEscalation",
    ),
    "computer.key": (
        "pid",
        "windowId",
        "elementToken",
        "x",
        "y",
        "key",
        "modifiers",
        "allowForegroundEscalation",
    ),
    "computer.hotkey": (
        "pid",
        "windowId",
        "x",
        "y",
        "keys",
        "allowForegroundEscalation",
    ),
    "computer.scroll": (
        "pid",
        "windowId",
        "elementToken",
        "x",
        "y",
        "direction",
        "amount",
        "by",
        "allowForegroundEscalation",
    ),
}
_CUA_ARGUMENT_NAMES = {
    "windowId": "window_id",
    "elementToken": "element_token",
    "onScreenOnly": "on_screen_only",
    "maxDepth": "max_depth",
    "maxElements": "max_elements",
    "delayMs": "delay_ms",
}


class CuaDriverExecutorAdapter:
    """Bounded CUA adapter with SOVA authorization and provider-observation labels."""

    name = "cua-driver-mcp"

    def __init__(
        self,
        client: MCPClient,
        *,
        session_id: str,
        allow_desktop_scope: bool = False,
    ) -> None:
        if not session_id or len(session_id) > _MAX_CUA_SESSION_ID_CHARS:
            raise FormatError("SOVA-CUA-SESSION", "CUA session id is invalid")
        self._client = client
        self._session_id = session_id
        self._allow_desktop_scope = allow_desktop_scope
        self._tools = {tool.name for tool in client.list_tools()}
        self._started = False
        self._closed = False

    def capabilities(self) -> tuple[Capability, ...]:
        return tuple(
            Capability(action, "0.12.6", effect, idempotent, evidence)
            for action, (tool, effect, idempotent, evidence) in sorted(_CUA_ACTIONS.items())
            if tool in self._tools and (action != "computer.desktop" or self._allow_desktop_scope)
        )

    @staticmethod
    def _authorized(context: ExecutionContext, *, foreground: bool = False) -> bool:
        digest = context.authorization.get("scopeDigest")
        return bool(
            context.authorization.get("decision") == "allowed"
            and isinstance(digest, str)
            and digest.startswith("sha256:")
            and _MELRA_DIGEST.fullmatch(digest.removeprefix("sha256:")) is not None
            and (not foreground or context.authorization.get("foregroundApproved") is True)
        )

    @staticmethod
    def _provider_text(result: MCPToolResult) -> str:
        return "\n".join(
            str(item.get("text", "")) for item in result.content if item.get("type") == "text"
        ).casefold()

    def _ensure_session(self, timeout_seconds: float) -> None:
        if self._started:
            return
        if "start_session" not in self._tools:
            raise FormatError("SOVA-CUA-SESSION", "CUA start_session tool is unavailable")
        result = self._client.call_tool(
            "start_session",
            {
                "session": self._session_id,
                "capture_scope": "desktop" if self._allow_desktop_scope else "window",
            },
            timeout_seconds=timeout_seconds,
        )
        if result.is_error:
            raise FormatError("SOVA-CUA-SESSION", "CUA session start was refused")
        self._started = True

    @staticmethod
    def _arguments(action: str, inputs: Mapping[str, Any], session_id: str) -> dict[str, Any]:
        allowed = _CUA_INPUTS[action]
        unsupported = sorted(set(inputs) - set(allowed))
        if unsupported:
            raise FormatError(
                "SOVA-CUA-INPUT",
                "CUA action contains unsupported input fields",
                details={"fields": unsupported},
            )
        if action == "computer.type":
            text = inputs.get("text")
            if not isinstance(text, str) or len(text.encode("utf-8")) > 16 * 1024:
                raise FormatError("SOVA-CUA-TEXT", "CUA text input is absent or exceeds 16 KiB")
        arguments = {
            _CUA_ARGUMENT_NAMES.get(key, key): value
            for key, value in inputs.items()
            if key != "allowForegroundEscalation"
        }
        if action == "computer.inspect":
            arguments["include_screenshot"] = True
        if _CUA_ACTIONS[action][1] == SideEffect.MUTATE:
            pid = inputs.get("pid")
            window_id = inputs.get("windowId")
            if (
                not isinstance(pid, int)
                or pid <= 0
                or not isinstance(window_id, int)
                or window_id <= 0
            ):
                raise FormatError(
                    "SOVA-CUA-WINDOW-BINDING",
                    "CUA mutation requires an exact positive pid and windowId",
                )
            arguments["scope"] = "window"
            arguments["delivery_mode"] = "background"
        arguments["session"] = session_id
        return arguments

    def execute(  # noqa: PLR0911 - each refusal state is an explicit executor outcome
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        contract = _CUA_ACTIONS.get(request.action)
        if contract is None or contract[0] not in self._tools:
            return ActionOutcome(request.id, OutcomeStatus.UNSUPPORTED, SideEffect.READ, {})
        tool, effect, idempotent, _evidence = contract
        if cancellation.cancelled:
            return ActionOutcome(request.id, OutcomeStatus.CANCELLED, effect, {})
        if not self._authorized(context):
            return ActionOutcome(
                request.id,
                OutcomeStatus.DENIED,
                effect,
                {},
                error_code="SOVA-CUA-AUTHORIZATION",
            )
        if request.action == "computer.desktop" and not self._allow_desktop_scope:
            return ActionOutcome(
                request.id,
                OutcomeStatus.DENIED,
                effect,
                {},
                error_code="SOVA-CUA-DESKTOP-SCOPE",
            )
        try:
            arguments = self._arguments(request.action, request.inputs, self._session_id)
            self._ensure_session(request.timeout_seconds)
            result = self._client.call_tool(
                tool,
                arguments,
                timeout_seconds=request.timeout_seconds,
            )
            foreground_used = False
            if result.is_error and effect == SideEffect.MUTATE:
                foreground_requested = request.inputs.get("allowForegroundEscalation") is True
                background_unavailable = "background_unavailable" in self._provider_text(result)
                if background_unavailable and foreground_requested:
                    if not self._authorized(context, foreground=True):
                        return ActionOutcome(
                            request.id,
                            OutcomeStatus.DENIED,
                            effect,
                            {},
                            error_code="SOVA-CUA-FOREGROUND-AUTHORIZATION",
                        )
                    arguments["delivery_mode"] = "foreground"
                    result = self._client.call_tool(
                        tool,
                        arguments,
                        timeout_seconds=request.timeout_seconds,
                    )
                    foreground_used = True
            observation = None
            verification = "direct-provider-observation"
            if effect == SideEffect.MUTATE and not result.is_error:
                if "get_window_state" in self._tools:
                    observation = self._client.call_tool(
                        "get_window_state",
                        {
                            "pid": request.inputs["pid"],
                            "window_id": request.inputs["windowId"],
                            "session": self._session_id,
                            "include_screenshot": False,
                            "max_depth": 12,
                            "max_elements": 2000,
                        },
                        timeout_seconds=request.timeout_seconds,
                    )
                verification = (
                    "cua-provider-post-action-observation"
                    if observation is not None and not observation.is_error
                    else "observation-failed"
                )
            outcome = _normalize_result(
                request,
                result,
                side_effect=effect,
                verification=verification,
                observation=observation,
            )
            output = dict(outcome.output)
            output["cua"] = {
                "sessionScope": "desktop" if self._allow_desktop_scope else "window",
                "foregroundEscalationUsed": foreground_used,
                "targetBound": effect == SideEffect.READ
                or ("pid" in request.inputs and "windowId" in request.inputs),
            }
            return ActionOutcome(
                outcome.request_id,
                outcome.status,
                outcome.side_effect,
                output,
                outcome.evidence,
                outcome.verification,
                idempotent and outcome.retryable,
                outcome.error_code,
                (
                    *outcome.limitations,
                    "CUA provider observations are not independent SOVA verification.",
                    "Host desktop execution is not a security sandbox.",
                ),
                outcome.failure_cause,
            )
        except (FormatError, KeyError) as error:
            code = error.issue.code if isinstance(error, FormatError) else "SOVA-CUA-INPUT"
            return ActionOutcome(
                request.id,
                OutcomeStatus.TIMEOUT if code == "SOVA-MCP-TIMEOUT" else OutcomeStatus.FAILED,
                effect,
                {},
                verification="adapter-protocol-failure",
                retryable=idempotent,
                error_code=code,
                failure_cause=(
                    FailureCause.TIMEOUT if code == "SOVA-MCP-TIMEOUT" else FailureCause.EXECUTOR
                ),
            )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._started and "end_session" in self._tools:
            with suppress(FormatError):
                self._client.call_tool(
                    "end_session",
                    {"session": self._session_id},
                    timeout_seconds=10,
                )
        self._client.close()


class MelraExecutorAdapter:
    """Optional MELRA plan/execute adapter; SOVA remains the authority and evidence root."""

    name = "melra-mcp"

    def __init__(self, client: MCPClient) -> None:
        self._client = client
        self._tools = {tool.name for tool in client.list_tools()}
        required = {"melra_capabilities", "melra_plan", "melra_execute"}
        self._available = required <= self._tools

    def capabilities(self) -> tuple[Capability, ...]:
        if not self._available:
            return ()
        return tuple(
            Capability(
                name=f"{kind}.{action}",
                version="0.3.0-alpha.10",
                side_effect=effect,
                idempotent=effect == SideEffect.READ,
                evidence=("melra-receipt",),
            )
            for kind, action, effect in _melra_action_catalog()
        )

    @staticmethod
    def _contains_projection(actual: Any, expected: Any) -> bool:
        if isinstance(expected, dict):
            return isinstance(actual, dict) and all(
                key in actual and MelraExecutorAdapter._contains_projection(actual[key], value)
                for key, value in expected.items()
            )
        if isinstance(expected, list):
            return (
                isinstance(actual, list)
                and len(actual) == len(expected)
                and all(
                    MelraExecutorAdapter._contains_projection(left, right)
                    for left, right in zip(actual, expected, strict=True)
                )
            )
        return bool(actual == expected)

    @staticmethod
    def _required_evidence(
        kind: str,
        action: str,
        inputs: Mapping[str, Any],
        side_effect: SideEffect,
    ) -> list[dict[str, Any]]:
        if kind == "browser" and action == "navigate" and isinstance(inputs.get("url"), str):
            return [{"type": "url_matches", "pattern": f"{inputs['url']}*"}]
        if side_effect == SideEffect.READ:
            return []
        if kind == "terminal" and action == "run":
            return [{"type": "exit_code", "value": 0}]
        return [{"type": "result_equals", "path": "success", "value": True}]

    @staticmethod
    def _provider_approval(
        plan: Mapping[str, Any],
        *,
        expected: _MelraApprovalExpectation,
        authorization: Mapping[str, Any],
    ) -> dict[str, str] | None:
        contract = plan.get("contract")
        if not isinstance(contract, dict):
            raise FormatError("SOVA-MELRA-PLAN-CONTRACT", "MELRA plan omitted its effect contract")
        if (
            contract.get("taskId") != expected.task_id
            or contract.get("capability") != expected.capability
            or not MelraExecutorAdapter._contains_projection(
                contract.get("operation"), dict(expected.operation)
            )
        ):
            raise FormatError(
                "SOVA-MELRA-PLAN-CONTRACT",
                "MELRA effect contract did not match the SOVA-authorized action",
            )
        effect = contract.get("effect")
        if (
            not isinstance(effect, str)
            or effect not in _MELRA_EFFECT_RANK
            or _MELRA_EFFECT_RANK[effect] > _MELRA_EFFECT_RANK[expected.maximum_effect.value]
        ):
            raise FormatError(
                "SOVA-MELRA-EFFECT-ESCALATION",
                "MELRA classified an effect above the SOVA-authorized maximum",
            )
        approval = plan.get("approval")
        if approval is None:
            return None
        scope_digest = authorization.get("scopeDigest")
        if (
            authorization.get("decision") != "allowed"
            or not isinstance(scope_digest, str)
            or not scope_digest.startswith("sha256:")
            or _MELRA_DIGEST.fullmatch(scope_digest.removeprefix("sha256:")) is None
        ):
            raise FormatError(
                "SOVA-MELRA-SOVA-AUTHORIZATION",
                "MELRA approval delegation requires a fresh SOVA authorization decision",
            )
        if not isinstance(approval, dict):
            raise FormatError("SOVA-MELRA-APPROVAL", "MELRA approval challenge was malformed")
        approval_id = approval.get("approvalId")
        phrase = approval.get("phrase")
        action_digest = approval.get("actionDigest")
        if (
            approval.get("taskId") != expected.task_id
            or not isinstance(approval_id, str)
            or not isinstance(phrase, str)
            or not isinstance(action_digest, str)
            or _MELRA_DIGEST.fullmatch(action_digest) is None
            or phrase != f"APPROVE {action_digest[:12]}"
        ):
            raise FormatError(
                "SOVA-MELRA-APPROVAL",
                "MELRA approval challenge was not bound to the planned action",
            )
        return {"approvalId": approval_id, "phrase": phrase}

    @staticmethod
    def _structured(result: MCPToolResult) -> dict[str, Any] | None:
        if result.structured_content is not None:
            return result.structured_content
        for item in result.content:
            if item.get("type") == "text" and isinstance(item.get("text"), str):
                try:
                    value = strict_json_loads(item["text"].encode(), max_bytes=_MAX_TEXT_BYTES)
                except FormatError:
                    continue
                if isinstance(value, dict):
                    return value
        return None

    @classmethod
    def _task_state(
        cls,
        result: MCPToolResult,
        *,
        expected_task_id: str,
    ) -> MelraTaskState:
        structured = cls._structured(result)
        task = structured.get("task") if isinstance(structured, dict) else None
        if not isinstance(task, dict):
            task = structured
        task_id = task.get("id") if isinstance(task, dict) else None
        status = task.get("status") if isinstance(task, dict) else None
        if task_id != expected_task_id or not isinstance(status, str):
            raise FormatError(
                "SOVA-MELRA-TASK-SHAPE",
                "MELRA task state did not match the requested task",
            )
        normalized = _MELRA_STATUS_MAP.get(status)
        if normalized is None:
            raise FormatError("SOVA-MELRA-UNKNOWN-STATUS", "unknown MELRA task status")
        return MelraTaskState(task_id, status, normalized[0], status in _MELRA_TERMINAL)

    def task_status(self, task_id: str, *, timeout_seconds: float = 20) -> MelraTaskState:
        """Read a MELRA task state without accepting it as SOVA evidence."""
        if "melra_task_status" not in self._tools:
            raise FormatError("SOVA-MELRA-STATUS-UNAVAILABLE", "MELRA status tool unavailable")
        result = self._client.call_tool(
            "melra_task_status",
            {"taskId": task_id},
            timeout_seconds=timeout_seconds,
        )
        return self._task_state(result, expected_task_id=task_id)

    def cancel_task(self, task_id: str, *, timeout_seconds: float = 20) -> MelraTaskState:
        """Request MELRA cancellation and return the explicit resulting state."""
        if "melra_task_cancel" not in self._tools:
            raise FormatError("SOVA-MELRA-CANCEL-UNAVAILABLE", "MELRA cancel tool unavailable")
        result = self._client.call_tool(
            "melra_task_cancel",
            {"taskId": task_id},
            timeout_seconds=timeout_seconds,
        )
        return self._task_state(result, expected_task_id=task_id)

    @staticmethod
    def _execution_outcome(
        request: ActionRequest,
        capability: Capability,
        planned_task_id: str,
        result: MCPToolResult,
        *,
        provider_approval_delegated: bool,
    ) -> ActionOutcome:
        """Translate MELRA's task state without trusting MCP transport success."""
        execution = MelraExecutorAdapter._structured(result)
        task = execution.get("task") if isinstance(execution, dict) else None
        task_id = task.get("id") if isinstance(task, dict) else None
        provider_status = task.get("status") if isinstance(task, dict) else None
        if task_id != planned_task_id or not isinstance(provider_status, str):
            return ActionOutcome(
                request.id,
                OutcomeStatus.FAILED,
                capability.side_effect,
                {},
                error_code="SOVA-MELRA-EXECUTION-SHAPE",
                limitations=(
                    "MELRA transport success is not treated as task success.",
                    "The execution result did not identify the planned task and a known status.",
                ),
                failure_cause=FailureCause.EXECUTOR,
            )

        normalized = _MELRA_STATUS_MAP.get(provider_status)
        if normalized is None:
            return ActionOutcome(
                request.id,
                OutcomeStatus.FAILED,
                capability.side_effect,
                {"taskId": task_id, "providerStatus": "unrecognized"},
                error_code="SOVA-MELRA-UNKNOWN-STATUS",
                failure_cause=FailureCause.EXECUTOR,
            )

        outcome_status, failure_cause = normalized
        provider_output = execution.get("output") if isinstance(execution, dict) else None
        output: dict[str, Any] = {
            "taskId": task_id,
            "providerStatus": provider_status,
            "providerApprovalDelegated": provider_approval_delegated,
        }
        evidence: list[EvidenceReference] = []
        if isinstance(provider_output, dict):
            output["providerOutput"] = provider_output
            encoded_output = canonical_json_bytes(provider_output)
            evidence.append(
                EvidenceReference(
                    "melra-output",
                    "application/json",
                    sha256_digest(encoded_output),
                    len(encoded_output),
                )
            )
        for field, role in (("receipt", "melra-receipt"), ("certificate", "melra-certificate")):
            material = execution.get(field) if isinstance(execution, dict) else None
            if isinstance(material, dict):
                encoded_material = canonical_json_bytes(material)
                evidence.append(
                    EvidenceReference(
                        role,
                        "application/json",
                        sha256_digest(encoded_material),
                        len(encoded_material),
                    )
                )

        error_code = None
        if outcome_status != OutcomeStatus.SUCCEEDED:
            error_code = f"SOVA-MELRA-{provider_status.upper().replace('_', '-')}"
        return ActionOutcome(
            request.id,
            outcome_status,
            capability.side_effect,
            output,
            tuple(evidence),
            verification=(
                "melra-result-defense-in-depth-only"
                if outcome_status == OutcomeStatus.SUCCEEDED
                else "melra-task-not-verified-success"
            ),
            retryable=False,
            error_code=error_code,
            limitations=(
                "MELRA task state and receipts are untrusted provider input.",
                "SOVA independently records authorization, effects, and evidence.",
            ),
            failure_cause=failure_cause,
        )

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        available = {capability.name: capability for capability in self.capabilities()}
        capability = available.get(request.action)
        if capability is None:
            return ActionOutcome(request.id, OutcomeStatus.UNSUPPORTED, SideEffect.READ, {})
        if cancellation.cancelled:
            return ActionOutcome(request.id, OutcomeStatus.CANCELLED, capability.side_effect, {})
        kind, action = request.action.split(".", 1)
        operation = {"kind": kind, "action": action, **request.inputs}
        required_evidence = self._required_evidence(
            kind, action, request.inputs, capability.side_effect
        )
        plan_request = {
            "goal": f"SOVA authorized action {request.id}",
            "operation": operation,
            "constraints": [],
            "forbiddenEffects": ["destructive"],
            "budget": {
                "maxSteps": 1,
                "maxDurationMs": min(int(request.timeout_seconds * 1000), 120_000),
                "maxRetries": 0,
            },
            "requiredEvidence": required_evidence,
            "identity": {
                "principal": {"kind": "harness", "id": "sova-oss"},
                "onBehalfOf": [],
            },
        }
        try:
            planned = self._client.call_tool(
                "melra_plan", plan_request, timeout_seconds=request.timeout_seconds
            )
            plan = self._structured(planned)
            if not isinstance(plan, dict):
                return ActionOutcome(
                    request.id,
                    OutcomeStatus.FAILED,
                    capability.side_effect,
                    {},
                    error_code="SOVA-MELRA-PLAN",
                    failure_cause=FailureCause.EXECUTOR,
                )
            task_id = plan.get("id")
            if not isinstance(task_id, str):
                return ActionOutcome(
                    request.id,
                    OutcomeStatus.FAILED,
                    capability.side_effect,
                    {},
                    error_code="SOVA-MELRA-PLAN",
                    failure_cause=FailureCause.EXECUTOR,
                )
            approval = self._provider_approval(
                plan,
                expected=_MelraApprovalExpectation(
                    task_id,
                    request.action,
                    operation,
                    capability.side_effect,
                ),
                authorization=context.authorization,
            )
            execute_arguments: dict[str, Any] = {"taskId": task_id}
            if approval is not None:
                execute_arguments["approval"] = approval
            result = self._client.call_tool(
                "melra_execute", execute_arguments, timeout_seconds=request.timeout_seconds
            )
            return self._execution_outcome(
                request,
                capability,
                task_id,
                result,
                provider_approval_delegated=approval is not None,
            )
        except FormatError as error:
            return ActionOutcome(
                request.id,
                (
                    OutcomeStatus.TIMEOUT
                    if error.issue.code == "SOVA-MCP-TIMEOUT"
                    else OutcomeStatus.FAILED
                ),
                capability.side_effect,
                {},
                retryable=False,
                error_code=error.issue.code,
                failure_cause=FailureCause.EXECUTOR,
            )

    def close(self) -> None:
        self._client.close()


__all__ = [
    "CuaDriverExecutorAdapter",
    "MCPExecutorAdapter",
    "MelraExecutorAdapter",
    "MelraTaskState",
    "ToolMapping",
    "chrome_devtools_mappings",
    "playwright_mappings",
    "windows_mcp_mappings",
]
