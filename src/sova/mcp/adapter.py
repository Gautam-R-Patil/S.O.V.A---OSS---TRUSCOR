# SPDX-License-Identifier: Apache-2.0
"""MCP executor adapters with SOVA-owned normalization and verification."""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping
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
        self._client.close()


def playwright_mappings(
    *, allowed_origins: tuple[str, ...] = ()
) -> tuple[ToolMapping, ...]:
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
        actions = (
            ("browser", "navigate", SideEffect.MUTATE),
            ("browser", "inspect", SideEffect.READ),
            ("browser", "click", SideEffect.MUTATE),
            ("browser", "type", SideEffect.MUTATE),
            ("browser", "screenshot", SideEffect.READ),
            ("computer", "capabilities", SideEffect.READ),
            ("computer", "screenshot", SideEffect.READ),
            ("computer", "click", SideEffect.MUTATE),
            ("computer", "type", SideEffect.MUTATE),
            ("terminal", "run", SideEffect.MUTATE),
        )
        return tuple(
            Capability(
                name=f"{kind}.{action}",
                version="0.1",
                side_effect=effect,
                idempotent=effect == SideEffect.READ,
                evidence=("melra-receipt",),
            )
            for kind, action, effect in actions
        )

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
        del context
        available = {capability.name: capability for capability in self.capabilities()}
        capability = available.get(request.action)
        if capability is None:
            return ActionOutcome(request.id, OutcomeStatus.UNSUPPORTED, SideEffect.READ, {})
        if cancellation.cancelled:
            return ActionOutcome(request.id, OutcomeStatus.CANCELLED, capability.side_effect, {})
        kind, action = request.action.split(".", 1)
        operation = {"kind": kind, "action": action, **request.inputs}
        plan_request = {
            "goal": f"SOVA authorized action {request.id}",
            "operation": operation,
            "constraints": ["Return bounded observable evidence to SOVA."],
            "forbiddenEffects": ["destructive"],
            "budget": {
                "maxSteps": 1,
                "maxDurationMs": min(int(request.timeout_seconds * 1000), 120_000),
                "maxRetries": 0,
            },
            "requiredEvidence": [],
        }
        try:
            planned = self._client.call_tool(
                "melra_plan", plan_request, timeout_seconds=request.timeout_seconds
            )
            plan = self._structured(planned)
            task_id = plan.get("id") if isinstance(plan, dict) else None
            if not isinstance(task_id, str):
                return ActionOutcome(
                    request.id,
                    OutcomeStatus.FAILED,
                    capability.side_effect,
                    {},
                    error_code="SOVA-MELRA-PLAN",
                    failure_cause=FailureCause.EXECUTOR,
                )
            if isinstance(plan, dict) and plan.get("approval") is not None:
                return ActionOutcome(
                    request.id,
                    OutcomeStatus.DENIED,
                    capability.side_effect,
                    {"taskId": task_id, "providerApprovalRequired": True},
                    error_code="SOVA-MELRA-PROVIDER-APPROVAL",
                    limitations=(
                        "MELRA approval cannot replace or silently weaken SOVA authorization.",
                    ),
                    failure_cause=FailureCause.POLICY,
                )
            result = self._client.call_tool(
                "melra_execute", {"taskId": task_id}, timeout_seconds=request.timeout_seconds
            )
            return self._execution_outcome(request, capability, task_id, result)
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
    "MCPExecutorAdapter",
    "MelraExecutorAdapter",
    "MelraTaskState",
    "ToolMapping",
    "playwright_mappings",
    "windows_mcp_mappings",
]
