# SPDX-License-Identifier: Apache-2.0
"""Managed Playwright surface for session-bound Executor Chamber missions."""

from __future__ import annotations

import re
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn
from urllib.parse import urlsplit

from sova.executors import (
    ActionOutcome,
    ActionRequest,
    CancellationToken,
    Capability,
    ExecutionContext,
    Executor,
    OutcomeStatus,
)
from sova.formats import canonical_json_bytes, strict_json_loads
from sova.formats.errors import FormatError
from sova.live.recording import (
    VisualRecordingSession,
    add_visual_chapter,
    collect_visual_replays,
    start_visual_recording,
    stop_visual_recording,
    write_replay_cues,
)
from sova.live.semantic_workflow import SemanticBrowserMission
from sova.mcp import playwright_mappings, playwright_stdio_spec
from sova.mcp.profile_state import profiled_playwright_adapter
from sova.runtime.managed_surfaces import LazyStdioExecutor
from sova.runtime.sessions import BrowserProfileLease
from sova.trace import Redactor

if TYPE_CHECKING:
    from collections.abc import Mapping

    from sova.mcp import MCPClient, ToolMapping

_SESSION_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_PAGE_URL = re.compile(r"(?m)^- Page URL:\s*(\S+)\s*$")
_LOCATOR_REF = re.compile(r"\[ref=([A-Za-z][A-Za-z0-9_-]{0,127})\]")
_MAX_RAW_SNAPSHOT_BYTES = 256 * 1024
_MAX_SNAPSHOT_BYTES = 64 * 1024
_MAX_PROJECTION_BYTES = 96 * 1024
_MAX_URL_CHARS = 8 * 1024
_INITIALIZATION_ACTOR = "sova.browser-surface-initializer/0.1"


def _is_link(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", lambda: False)
    return path.is_symlink() or bool(is_junction())


def _absolute(path: Path, role: str) -> Path:
    if not isinstance(path, Path):
        raise FormatError(
            "SOVA-BROWSER-SURFACE-PATH",
            f"{role} must be a filesystem path",
        )
    return path.absolute()


def _reject_link_chain(path: Path, role: str) -> None:
    for candidate in (path, *path.parents):
        if _is_link(candidate):
            raise FormatError(
                "SOVA-BROWSER-SURFACE-PATH-LINK",
                f"{role} cannot traverse a symbolic link or junction",
            )


def _existing_file(path: Path, role: str) -> Path:
    candidate = _absolute(path, role)
    _reject_link_chain(candidate, role)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise FormatError(
            "SOVA-BROWSER-SURFACE-PATH",
            f"{role} must resolve to an existing file",
        ) from error
    if not resolved.is_file():
        raise FormatError(
            "SOVA-BROWSER-SURFACE-PATH",
            f"{role} must resolve to an existing file",
        )
    return candidate


def _existing_directory(path: Path, role: str) -> Path:
    candidate = _absolute(path, role)
    _reject_link_chain(candidate, role)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise FormatError(
            "SOVA-BROWSER-SURFACE-PATH",
            f"{role} must resolve to an existing directory",
        ) from error
    if not resolved.is_dir():
        raise FormatError(
            "SOVA-BROWSER-SURFACE-PATH",
            f"{role} must resolve to an existing directory",
        )
    return resolved


def _cache_directory(path: Path | None, role: str) -> Path | None:
    if path is None:
        return None
    candidate = _absolute(path, role)
    _reject_link_chain(candidate, role)
    current = next((item for item in (candidate, *candidate.parents) if item.exists()), None)
    if current is None or not current.is_dir():  # pragma: no cover - filesystem roots exist
        raise FormatError(
            "SOVA-BROWSER-SURFACE-PATH",
            f"{role} requires an existing directory ancestor",
        )
    if candidate.exists() and not candidate.is_dir():
        raise FormatError(
            "SOVA-BROWSER-SURFACE-PATH",
            f"{role} must be a directory",
        )
    return candidate


def _exact_origin(url: str) -> str:
    if not isinstance(url, str) or not url or len(url) > _MAX_URL_CHARS:
        raise FormatError(
            "SOVA-BROWSER-SURFACE-URL",
            "browser observation URL is missing or malformed",
        )
    try:
        parsed = urlsplit(url)
        port = parsed.port or (80 if parsed.scheme == "http" else 443)
    except ValueError as error:
        raise FormatError(
            "SOVA-BROWSER-SURFACE-URL",
            "browser observation URL is missing or malformed",
        ) from error
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise FormatError(
            "SOVA-BROWSER-SURFACE-URL",
            "browser observation URL is missing or malformed",
        )
    default_port = 80 if parsed.scheme == "http" else 443
    suffix = "" if port == default_port else f":{port}"
    return f"{parsed.scheme}://{parsed.hostname.casefold()}{suffix}"


def _capability(mapping: ToolMapping) -> Capability:
    return Capability(
        mapping.action,
        mapping.version,
        mapping.side_effect,
        mapping.idempotent,
        mapping.evidence,
    )


def _snapshot_projection(
    outcome: ActionOutcome,
    *,
    origin: str,
    mission_digest: str,
) -> dict[str, Any]:
    if outcome.status != OutcomeStatus.SUCCEEDED:
        code = (
            "SOVA-BROWSER-SURFACE-ORIGIN-DRIFT"
            if outcome.error_code == "SOVA-MCP-BROWSER-ORIGIN-DRIFT"
            else "SOVA-BROWSER-SURFACE-SNAPSHOT"
        )
        raise FormatError(code, "fresh browser snapshot did not succeed")
    text = outcome.output.get("text")
    if not isinstance(text, list) or not text or not all(isinstance(item, str) for item in text):
        raise FormatError(
            "SOVA-BROWSER-SURFACE-SNAPSHOT",
            "fresh browser snapshot did not contain bounded text",
        )
    rendered = "\n".join(text)
    raw = rendered.encode("utf-8")
    if not raw or len(raw) > _MAX_RAW_SNAPSHOT_BYTES or "\x00" in rendered:
        raise FormatError(
            "SOVA-BROWSER-SURFACE-SNAPSHOT",
            "fresh browser snapshot text is malformed or exceeds its trust boundary",
        )
    matches = _PAGE_URL.findall(rendered)
    if len(matches) != 1:
        raise FormatError(
            "SOVA-BROWSER-SURFACE-URL",
            "fresh browser snapshot did not expose one unambiguous current URL",
        )
    current_url = matches[0]
    if _exact_origin(current_url) != origin:
        raise FormatError(
            "SOVA-BROWSER-SURFACE-ORIGIN-DRIFT",
            "fresh browser snapshot left the exact admitted mission origin",
        )
    truncated = len(raw) > _MAX_SNAPSHOT_BYTES
    bounded = raw[:_MAX_SNAPSHOT_BYTES].decode("utf-8", errors="ignore") if truncated else rendered
    redacted, disclosures = Redactor(context_id=mission_digest).redact(bounded)
    if disclosures or not isinstance(redacted, str):
        raise FormatError(
            "SOVA-BROWSER-SURFACE-SENSITIVE",
            "credential-shaped browser snapshot material was withheld",
        )
    projection = {
        "missionDigest": mission_digest,
        "url": current_url,
        "snapshot": redacted,
        "locatorRefs": sorted(set(_LOCATOR_REF.findall(redacted))),
        "snapshotTruncated": truncated,
    }
    encoded = canonical_json_bytes(projection)
    if len(encoded) > _MAX_PROJECTION_BYTES:
        raise FormatError(
            "SOVA-BROWSER-SURFACE-SNAPSHOT",
            "browser observation projection exceeds its bounded disclosure",
        )
    detached = strict_json_loads(encoded, max_bytes=_MAX_PROJECTION_BYTES)
    if not isinstance(detached, dict):  # pragma: no cover - source is a dict
        raise TypeError
    return detached


class _SessionBoundBrowserExecutor:
    """Executor façade that withholds the lazy backend and enforces surface affinity."""

    __slots__ = ("__surface",)

    def __init__(self, surface: ManagedPlaywrightBrowserSurface) -> None:
        self.__surface = surface

    @property
    def name(self) -> str:
        return "sova-managed-playwright-browser"

    def capabilities(self) -> tuple[Capability, ...]:
        return self.__surface.capabilities()

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        return self.__surface._dispatch(request, context, cancellation)


class ManagedPlaywrightBrowserSurface:
    """One mission-origin Playwright backend with a trusted fresh-state sensor."""

    __slots__ = (
        "__backend_capabilities",
        "__capabilities",
        "__closed",
        "__entry_url_value",
        "__executor",
        "__initialized",
        "__lazy",
        "__lock",
        "__mission_digest",
        "__mission_duration_value",
        "__origin",
        "__record_video",
        "__recording",
        "__recording_destination",
        "__recording_label",
        "__replay_cues",
        "__session_digest",
        "__target_digest",
        "__visual_replays",
        "__workspace",
    )

    def __init__(  # noqa: PLR0913, PLR0915 - launch trust inputs/checks stay explicit
        self,
        *,
        mission: SemanticBrowserMission,
        target_digest: str,
        package_runner: Path,
        browser_executable: Path,
        package_cache: Path | None = None,
        browser_cache: Path | None = None,
        profile_lease: BrowserProfileLease | None = None,
        headless: bool = True,
        record_video: bool = False,
        recording_destination: Path | None = None,
        recording_label: str = "browser",
    ) -> None:
        if type(mission) is not SemanticBrowserMission:
            raise FormatError(
                "SOVA-BROWSER-SURFACE-MISSION",
                "browser surface requires one exact SemanticBrowserMission",
            )
        if not isinstance(target_digest, str) or _SESSION_DIGEST.fullmatch(target_digest) is None:
            raise FormatError(
                "SOVA-BROWSER-SURFACE-TARGET",
                "browser surface requires one canonical target digest",
            )
        if not isinstance(headless, bool) or not isinstance(record_video, bool):
            raise FormatError(
                "SOVA-BROWSER-SURFACE-CONFIG",
                "browser display and recording controls must be booleans",
            )
        origin = mission.entry_origin
        runner = _existing_file(package_runner, "package runner")
        browser = _existing_file(browser_executable, "browser executable")
        npm_cache = _cache_directory(package_cache, "package cache")
        browsers = _cache_directory(browser_cache, "browser cache")
        if npm_cache is not None and browsers is not None and npm_cache == browsers:
            raise FormatError(
                "SOVA-BROWSER-SURFACE-PATH",
                "package and browser caches must be distinct directories",
            )
        if profile_lease is not None and type(profile_lease) is not BrowserProfileLease:
            raise FormatError(
                "SOVA-BROWSER-SURFACE-PROFILE",
                "browser profile must be one exact opaque lease",
            )
        if record_video:
            if (
                not isinstance(recording_destination, Path)
                or not recording_label
                or not recording_label.replace("-", "_").isidentifier()
            ):
                raise FormatError(
                    "SOVA-BROWSER-SURFACE-RECORDING",
                    "browser recording requires one trusted destination and label",
                )
            recording_destination = recording_destination.resolve()

        mappings = playwright_mappings(allowed_origins=(origin,))
        exposed_actions = frozenset((*mission.allowed_actions, "browser.snapshot"))
        backend_actions = exposed_actions | {"browser.navigate"}
        backend_mappings = tuple(item for item in mappings if item.action in backend_actions)
        if {item.action for item in backend_mappings} != backend_actions:
            raise FormatError(
                "SOVA-BROWSER-SURFACE-CAPABILITY",
                "mission action surface is not implemented by the pinned Playwright adapter",
            )
        exposed_mappings = tuple(
            item for item in backend_mappings if item.action in exposed_actions
        )
        capabilities = tuple(
            sorted(
                (_capability(item) for item in exposed_mappings), key=lambda item: item.identifier
            )
        )
        backend_capabilities = tuple(
            sorted(
                (_capability(item) for item in backend_mappings), key=lambda item: item.identifier
            )
        )

        def profile_paths() -> tuple[Path | None, Path | None]:
            if profile_lease is None:
                return None, None
            profile_lease.require_target(target_digest)
            profile = _existing_directory(
                profile_lease.path_for_executor(),
                "browser profile directory",
            )
            root = _existing_directory(
                profile_lease.root_for_executor(),
                "browser profile vault root",
            )
            if profile == root or root not in profile.parents:
                raise FormatError(
                    "SOVA-BROWSER-SURFACE-PROFILE",
                    "browser profile escaped its opaque vault root",
                )
            return profile, root

        # Validate the opaque lease at admission, then revalidate immediately
        # before launch to catch release, replacement, or path drift.
        profile_paths()

        profile_workspace: Path | None = None

        def spec_factory(workspace: Path) -> Any:
            nonlocal profile_workspace
            checked_runner = _existing_file(runner, "package runner")
            checked_browser = _existing_file(browser, "browser executable")
            checked_npm = _cache_directory(npm_cache, "package cache")
            checked_browsers = _cache_directory(browsers, "browser cache")
            profile, root = profile_paths()
            profile_workspace = workspace
            return playwright_stdio_spec(
                package_runner=checked_runner,
                workspace=workspace,
                browser_executable=checked_browser,
                allowed_origins=(origin,),
                package_cache=checked_npm,
                browser_cache=checked_browsers,
                profile_directory=profile,
                profile_vault_root=root,
                headless=headless,
                record_video=record_video,
            )

        def adapter_factory(client: MCPClient) -> Executor:
            if profile_workspace is None:  # pragma: no cover - spec factory always runs first
                raise FormatError(
                    "SOVA-BROWSER-SURFACE-PROFILE",
                    "browser profile lifecycle lost its bound workspace",
                )
            return profiled_playwright_adapter(
                "microsoft-playwright-mcp",
                client,
                backend_mappings,
                profile_lease=profile_lease,
                workspace=profile_workspace,
            )

        self.__origin = origin
        self.__mission_digest = mission.digest
        self.__entry_url_value = mission.entry_url
        self.__mission_duration_value = mission.max_duration_seconds
        self.__target_digest = target_digest
        self.__record_video = record_video
        self.__recording_destination = recording_destination
        self.__recording_label = recording_label
        self.__recording: VisualRecordingSession | None = None
        self.__visual_replays: tuple[Path, ...] = ()
        self.__replay_cues: Path | None = None
        self.__capabilities = capabilities
        self.__backend_capabilities = backend_capabilities
        self.__lazy = LazyStdioExecutor(
            name="sova-managed-playwright-browser",
            capabilities=backend_capabilities,
            spec_factory=spec_factory,
            adapter_factory=adapter_factory,
        )
        self.__executor: Executor = _SessionBoundBrowserExecutor(self)
        self.__workspace: Path | None = None
        self.__session_digest: str | None = None
        self.__initialized = False
        self.__closed = False
        self.__lock = threading.RLock()

    @property
    def allowed_origin(self) -> str:
        return self.__origin

    @property
    def mission_digest(self) -> str:
        return self.__mission_digest

    @property
    def target_digest(self) -> str:
        return self.__target_digest

    @property
    def executor(self) -> Executor:
        return self.__executor

    @property
    def closed(self) -> bool:
        with self.__lock:
            return self.__closed

    @property
    def cleanup_complete(self) -> bool:
        return self.__lazy.cleanup_complete

    @property
    def visual_replays(self) -> tuple[Path, ...]:
        return self.__visual_replays

    @property
    def replay_cues(self) -> Path | None:
        return self.__replay_cues

    def capabilities(self) -> tuple[Capability, ...]:
        return self.__capabilities

    def bind(self, *, workspace: Path, session_digest: str) -> None:
        """Bind the surface to one trusted disposable workspace/session generation."""
        checked_workspace = _existing_directory(workspace, "browser session workspace")
        if not isinstance(session_digest, str) or _SESSION_DIGEST.fullmatch(session_digest) is None:
            raise FormatError(
                "SOVA-BROWSER-SURFACE-SESSION",
                "browser surface requires one canonical session digest",
            )
        with self.__lock:
            if self.__closed:
                raise FormatError(
                    "SOVA-BROWSER-SURFACE-CLOSED",
                    "browser surface is already closed",
                )
            if self.__workspace is not None and (
                self.__workspace != checked_workspace or self.__session_digest != session_digest
            ):
                self._fail_closed(
                    FormatError(
                        "SOVA-BROWSER-SURFACE-AFFINITY",
                        "browser surface cannot move to another workspace or session generation",
                    )
                )
            self.__workspace = checked_workspace
            self.__session_digest = session_digest

    def _bound(self) -> tuple[Path, str]:
        if self.__closed:
            raise FormatError(
                "SOVA-BROWSER-SURFACE-CLOSED",
                "browser surface is already closed",
            )
        if self.__workspace is None or self.__session_digest is None:
            raise FormatError(
                "SOVA-BROWSER-SURFACE-UNBOUND",
                "browser surface must be bound before observation or execution",
            )
        current = _existing_directory(self.__workspace, "browser session workspace")
        if current != self.__workspace:
            raise FormatError(
                "SOVA-BROWSER-SURFACE-AFFINITY",
                "browser session workspace identity changed after binding",
            )
        return self.__workspace, self.__session_digest

    def _assert_inventory(self) -> None:
        if self.__lazy.capabilities() != self.__backend_capabilities:
            raise FormatError(
                "SOVA-BROWSER-SURFACE-CAPABILITY-SUBSTITUTION",
                "browser surface capability inventory changed after admission",
            )

    def _dispatch(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        with self.__lock:
            try:
                workspace, session_digest = self._bound()
                if not self.__initialized:
                    raise FormatError(  # noqa: TRY301 - caught to close the surface
                        "SOVA-BROWSER-SURFACE-UNINITIALIZED",
                        "browser surface requires one trusted initial observation before actions",
                    )
                supplied_session = context.environment.get("sessionDigest")
                try:
                    supplied_workspace = context.workspace.resolve(strict=True)
                except OSError as error:
                    raise FormatError(
                        "SOVA-BROWSER-SURFACE-AFFINITY",
                        "browser execution workspace is unavailable",
                    ) from error
                grant = context.authorization.get("executionGrant")
                allowed_action = any(
                    capability.name == request.action for capability in self.__capabilities
                )
                if not allowed_action:
                    raise FormatError(  # noqa: TRY301 - caught to close the surface
                        "SOVA-BROWSER-SURFACE-CAPABILITY",
                        "browser action is outside the mission-exposed capability inventory",
                    )
                if (
                    supplied_workspace != workspace
                    or supplied_session != session_digest
                    or context.authorization.get("decision") != "allowed"
                    or not isinstance(grant, dict)
                ):
                    raise FormatError(  # noqa: TRY301 - caught to close the surface
                        "SOVA-BROWSER-SURFACE-AFFINITY",
                        "browser execution changed its workspace, session, or allowed grant",
                    )
                self._assert_inventory()
                outcome = self.__lazy.execute(request, context, cancellation)
                self._assert_inventory()
                return outcome  # noqa: TRY300 - guarded success path
            except Exception as error:  # noqa: BLE001 - every backend fault closes the surface
                self._fail_closed(
                    error,
                    code="SOVA-BROWSER-SURFACE-EXECUTION",
                    message="managed browser execution failed without exposing backend details",
                )

    def _initialize(self, workspace: Path, session_digest: str) -> None:
        if self.__initialized:
            return
        timeout = float(min(30, max(1, self.__mission_duration_seconds())))
        context = ExecutionContext(
            workspace,
            {
                "decision": "allowed",
                "scopeDigest": self.__mission_digest,
                "decidedBy": _INITIALIZATION_ACTOR,
                "coordinatorInitialization": True,
                "executionGrant": {},
            },
            environment={"sessionDigest": session_digest},
        )
        outcome = self.__lazy.execute(
            ActionRequest(
                "trusted-browser-surface-initialize",
                "browser.navigate",
                {"url": self.__entry_url()},
                timeout,
            ),
            context,
            CancellationToken(),
        )
        if outcome.status != OutcomeStatus.SUCCEEDED:
            code = (
                "SOVA-BROWSER-SURFACE-ORIGIN-DRIFT"
                if outcome.error_code == "SOVA-MCP-BROWSER-ORIGIN-DRIFT"
                else "SOVA-BROWSER-SURFACE-INITIALIZATION"
            )
            raise FormatError(code, "trusted browser mission initialization did not succeed")
        if self.__record_video:
            client = self.__lazy.coordinator_client(
                workspace=workspace,
                session_digest=session_digest,
            )
            self.__recording = start_visual_recording(client)
            add_visual_chapter(
                client,
                title=f"SOVA executor engine — {self.__recording_label}",
                description="Authorized typed UI actions with signed oracle evidence.",
            )
        self._assert_inventory()
        self.__initialized = True

    def observe_recording_event(self, channel: str, event: dict[str, Any]) -> None:
        """Index a signed decisive event against this surface's active video."""
        with self.__lock:
            if self.__recording is None:
                return
            workspace, session_digest = self._bound()
            client = self.__lazy.coordinator_client(
                workspace=workspace,
                session_digest=session_digest,
            )
            self.__recording.observe(client, channel, event)

    def _finalize_recording(self) -> None:
        recording = self.__recording
        destination = self.__recording_destination
        workspace = self.__workspace
        session_digest = self.__session_digest
        if recording is None:
            return
        if destination is None or workspace is None or session_digest is None:
            raise FormatError(
                "SOVA-BROWSER-SURFACE-RECORDING",
                "browser recording lost its admitted destination or session",
            )
        client = self.__lazy.coordinator_client(
            workspace=workspace,
            session_digest=session_digest,
        )
        stop_visual_recording(client)
        materialized = collect_visual_replays(workspace)
        copied: list[Path] = []
        destination.mkdir(parents=True, exist_ok=True)
        for index, media in enumerate(materialized, 1):
            target = destination / f"{self.__recording_label}-visual-replay-{index:02d}.webm"
            target.write_bytes(media.read_bytes())
            copied.append(target)
        if recording.cues and copied:
            cue_source = write_replay_cues(workspace, recording, materialized[0])
            cue_target = destination / f"{self.__recording_label}-replay-cues.json"
            cue_target.write_bytes(cue_source.read_bytes())
            self.__replay_cues = cue_target
        self.__visual_replays = tuple(copied)
        self.__recording = None

    def __entry_url(self) -> str:
        # The entry URL is recovered only from the digest-bound spec closure's
        # reviewed mission via this private value stored at construction time.
        return self.__entry_url_value

    def __mission_duration_seconds(self) -> int:
        return self.__mission_duration_value

    def observe(self) -> Mapping[str, Any]:
        """Navigate once, then return one fresh independently origin-checked snapshot."""
        with self.__lock:
            try:
                workspace, session_digest = self._bound()
                self._assert_inventory()
                self._initialize(workspace, session_digest)
                snapshot = self.__lazy.trusted_observe(
                    workspace=workspace,
                    action="browser.snapshot",
                    inputs={},
                    timeout_seconds=20.0,
                )
                self._assert_inventory()
                return _snapshot_projection(
                    snapshot,
                    origin=self.__origin,
                    mission_digest=self.__mission_digest,
                )
            except Exception as error:  # noqa: BLE001 - every sensor fault closes the surface
                self._fail_closed(
                    error,
                    code="SOVA-BROWSER-SURFACE-OBSERVATION",
                    message="trusted browser observation failed without exposing backend details",
                )

    def _fail_closed(
        self,
        error: Exception,
        *,
        code: str | None = None,
        message: str | None = None,
    ) -> NoReturn:
        try:
            self.close()
        except Exception:  # noqa: BLE001 - cleanup is normalized and chained
            raise FormatError(
                "SOVA-BROWSER-SURFACE-CLEANUP",
                "browser surface failed and backend cleanup could not be verified",
            ) from error
        if isinstance(error, FormatError):
            raise error
        if code is None or message is None:  # pragma: no cover - internal calls provide both
            raise TypeError from error
        raise FormatError(code, message) from error

    def close(self) -> None:
        with self.__lock:
            if self.__closed:
                if not self.__lazy.cleanup_complete:
                    self.__lazy.close()
                return
            self.__closed = True
            failures: list[Exception] = []
            try:
                self._finalize_recording()
            except Exception as error:  # noqa: BLE001 - still close the owned backend
                failures.append(error)
            try:
                self.__lazy.close()
            except Exception as error:  # noqa: BLE001 - normalized below
                failures.append(error)
            if not self.__lazy.cleanup_complete or failures:
                raise FormatError(
                    "SOVA-BROWSER-SURFACE-CLEANUP",
                    "browser surface recording or backend cleanup could not be verified",
                ) from (failures[0] if failures else None)


__all__ = ["ManagedPlaywrightBrowserSurface"]
