# SPDX-License-Identifier: Apache-2.0
"""Bounded browser-video recording and decisive-event synchronization."""

from __future__ import annotations

from dataclasses import dataclass, field
from time import monotonic_ns
from typing import TYPE_CHECKING, Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from sova.mcp import MCPClient

_MAX_VISUAL_REPLAY_BYTES = 128 * 1024 * 1024
_MAX_VISUAL_REPLAYS = 4
_VISUAL_RECORDING_TOOLS = frozenset(
    {
        "browser_snapshot",
        "browser_start_video",
        "browser_stop_video",
        "browser_video_chapter",
        "browser_video_show_actions",
    }
)


def _decimal_string(numerator: int, denominator: int, places: int) -> str:
    factor = 10**places
    scaled = (max(0, numerator) * factor + denominator // 2) // denominator
    whole, fraction = divmod(scaled, factor)
    return f"{whole}.{fraction:0{places}d}"


def call_visual_recording_tool(
    client: MCPClient,
    name: str,
    arguments: dict[str, Any],
) -> None:
    result = client.call_tool(name, arguments, timeout_seconds=30)
    if result.is_error:
        raise FormatError(
            "SOVA-LIVE-VIDEO-FAILED",
            f"browser recording tool failed: {name}",
        )


def require_visual_recording_tools(client: MCPClient) -> None:
    available = {tool.name for tool in client.list_tools()}
    missing = sorted(_VISUAL_RECORDING_TOOLS - available)
    if missing:
        raise FormatError(
            "SOVA-LIVE-VIDEO-UNAVAILABLE",
            "the pinned browser backend did not advertise the required recording tools",
            details={"missing": missing},
        )


@dataclass(slots=True)
class VisualRecordingSession:
    """Same-host monotonic bounds and decisive events for one WebM recording."""

    started_before_ns: int
    started_after_ns: int
    cues: list[dict[str, Any]] = field(default_factory=list)

    @property
    def estimated_start_ns(self) -> int:
        return self.started_before_ns + (self.started_after_ns - self.started_before_ns) // 2

    @property
    def uncertainty_ms(self) -> str:
        return _decimal_string(self.started_after_ns - self.started_before_ns, 2_000_000, 3)

    def observe(self, client: MCPClient, channel: str, event: dict[str, Any]) -> None:
        """Record and visibly chapter-mark a persisted passing oracle event."""
        payload = event.get("payload")
        if (
            event.get("kind") != "oracle.completed"
            or not isinstance(payload, dict)
            or payload.get("status") != "pass"
        ):
            return
        event_time = event.get("monotonicNs")
        if not isinstance(event_time, int):
            event_time = monotonic_ns()
        offset_seconds = _decimal_string(event_time - self.estimated_start_ns, 1_000_000_000, 6)
        marker_before_ns = monotonic_ns()
        call_visual_recording_tool(
            client,
            "browser_video_chapter",
            {
                "title": "SOVA — EXPLOIT CONFIRMED",
                "description": (
                    f"Deterministic oracle passed · {channel} · trace sequence "
                    f"{event.get('sequence', '?')}"
                ),
                "duration": 1400,
            },
        )
        self.cues.append(
            {
                "id": f"decisive-{len(self.cues) + 1:02d}",
                "label": "Exploit confirmed",
                "channel": channel,
                "eventId": event.get("id"),
                "eventKind": "oracle.completed",
                "eventSequence": event.get("sequence"),
                "oracleStatus": "pass",
                "offsetSeconds": offset_seconds,
                "chapterOffsetSeconds": _decimal_string(
                    marker_before_ns - self.estimated_start_ns,
                    1_000_000_000,
                    6,
                ),
                "preRollSeconds": "2.000000",
                "postRollSeconds": "3.000000",
            }
        )

    def document(self, media: Path) -> dict[str, Any]:
        """Return the bounded replay-cue document bound to one exact recording."""
        return {
            "artifactType": "sova.replay-cues",
            "schemaVersion": "0.1.0",
            "mediaName": media.name,
            "mediaDigest": sha256_digest(media.read_bytes()),
            "synchronization": {
                "method": "same-host-monotonic-recorder-start-rpc-bound",
                "uncertaintyMs": self.uncertainty_ms,
                "frameTimestampAttested": False,
                "statement": (
                    "Cue offsets share the recorder host monotonic clock and are bounded by "
                    "the successful recorder-start RPC. Browser frames are not independently "
                    "cryptographically timestamped."
                ),
            },
            "cues": list(self.cues),
        }


def start_visual_recording(
    client: MCPClient,
    *,
    filename: str = ".sova/playwright-output/sova-browser-session.webm",
) -> VisualRecordingSession:
    """Start one annotated video and return its host-clock synchronization bounds."""
    require_visual_recording_tools(client)
    # Playwright creates its first page lazily; materialize it before starting
    # the screencast to avoid a page-created race in headed and headless modes.
    call_visual_recording_tool(client, "browser_snapshot", {})
    started_before_ns = monotonic_ns()
    call_visual_recording_tool(
        client,
        "browser_start_video",
        {"filename": filename, "size": {"width": 1280, "height": 720}},
    )
    started_after_ns = monotonic_ns()
    call_visual_recording_tool(
        client,
        "browser_video_show_actions",
        {"duration": 650, "position": "top-right", "cursor": "pointer"},
    )
    return VisualRecordingSession(started_before_ns, started_after_ns)


def stop_visual_recording(client: MCPClient) -> None:
    call_visual_recording_tool(client, "browser_stop_video", {})


def add_visual_chapter(
    client: MCPClient,
    *,
    title: str,
    description: str,
    duration_ms: int = 1000,
) -> None:
    call_visual_recording_tool(
        client,
        "browser_video_chapter",
        {"title": title, "description": description, "duration": duration_ms},
    )


def recorded_observer(
    session: VisualRecordingSession | None,
    client: MCPClient,
    observer: Callable[[str, dict[str, Any]], None] | None,
    channel: str,
) -> Callable[[dict[str, Any]], None] | None:
    """Combine cue capture with the caller's already-redacted event observer."""
    if session is None and observer is None:
        return None

    def emit(event: dict[str, Any]) -> None:
        if session is not None:
            session.observe(client, channel, event)
        if observer is not None:
            observer(channel, event)

    return emit


def collect_visual_replays(destination: Path) -> tuple[Path, ...]:
    """Copy finalized WebM evidence out of the executor-owned output directory."""
    output_path = destination / ".sova" / "playwright-output"
    if output_path.is_symlink() or not output_path.is_dir():
        raise FormatError(
            "SOVA-LIVE-VIDEO-MISSING",
            "visual replay was requested but the browser output directory is missing",
        )
    output = output_path.resolve()
    candidates = tuple(sorted(output.rglob("*.webm")))
    if not candidates:
        raise FormatError(
            "SOVA-LIVE-VIDEO-MISSING",
            "visual replay was requested but Playwright produced no finalized WebM recording",
        )
    if len(candidates) > _MAX_VISUAL_REPLAYS:
        raise FormatError("SOVA-LIVE-VIDEO-LIMIT", "too many browser recordings were produced")
    materialized: list[Path] = []
    for index, source in enumerate(candidates, 1):
        if source.is_symlink():
            raise FormatError("SOVA-LIVE-VIDEO-PATH", "browser recording must not be a link")
        resolved = source.resolve()
        try:
            resolved.relative_to(output)
        except ValueError as error:
            raise FormatError(
                "SOVA-LIVE-VIDEO-PATH",
                "browser recording escaped the admitted output directory",
            ) from error
        if not resolved.is_file():
            raise FormatError("SOVA-LIVE-VIDEO-PATH", "browser recording is not a regular file")
        size = resolved.stat().st_size
        if size <= 0 or size > _MAX_VISUAL_REPLAY_BYTES:
            raise FormatError(
                "SOVA-LIVE-VIDEO-LIMIT",
                "browser recording is empty or exceeds the 128 MiB evidence budget",
            )
        with resolved.open("rb") as handle:
            data = handle.read(_MAX_VISUAL_REPLAY_BYTES + 1)
        if len(data) != size or len(data) > _MAX_VISUAL_REPLAY_BYTES:
            raise FormatError(
                "SOVA-LIVE-VIDEO-LIMIT",
                "browser recording changed during bounded evidence collection",
            )
        target = destination / f"visual-replay-{index:02d}.webm"
        target.write_bytes(data)
        materialized.append(target)
    return tuple(materialized)


def write_replay_cues(
    destination: Path,
    session: VisualRecordingSession,
    media: Path,
) -> Path:
    """Persist the exact recording-to-oracle index beside the evidence."""
    path = destination / "replay-cues.json"
    path.write_bytes(canonical_json_bytes(session.document(media)) + b"\n")
    return path


__all__ = [
    "VisualRecordingSession",
    "add_visual_chapter",
    "call_visual_recording_tool",
    "collect_visual_replays",
    "recorded_observer",
    "require_visual_recording_tools",
    "start_visual_recording",
    "stop_visual_recording",
    "write_replay_cues",
]
