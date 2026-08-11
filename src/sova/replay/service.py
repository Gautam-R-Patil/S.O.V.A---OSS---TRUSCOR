# SPDX-License-Identifier: Apache-2.0
"""Loopback-only live tail for the inert replay application."""

from __future__ import annotations

import hmac
import json
import secrets
import threading
import time
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlsplit

from sova.formats import canonical_json_bytes, strict_json_loads, validate_document
from sova.formats.errors import FormatError
from sova.replay.model import ReplayMode
from sova.replay.render import replay_document
from sova.trace import TraceReader
from sova.trace.integrity import event_hash
from sova.trace.redaction import RedactionVerifier

if TYPE_CHECKING:
    from pathlib import Path

_MAX_EVENT_BYTES = 8 * 1024 * 1024
_MAX_SOURCE_BYTES = 256 * 1024 * 1024
_MAX_EVENTS = 50_000
_MAX_PORT = 65_535
_MAX_CLIENTS = 16
_MIN_HOLD_SECONDS = 0.1
_MAX_HOLD_SECONDS = 30
_MIN_POLL_SECONDS = 0.02
_MAX_POLL_SECONDS = 2


@dataclass(frozen=True, slots=True)
class ReplayServiceConfig:
    """Bounded local replay-service configuration."""

    source: Path
    host: str = "127.0.0.1"
    port: int = 0
    max_clients: int = 4
    hold_seconds: float = 5.0
    poll_seconds: float = 0.1

    def __post_init__(self) -> None:
        if self.host != "127.0.0.1":
            raise FormatError(
                "SOVA-REPLAY-SERVICE-HOST",
                "the reference replay service binds only literal IPv4 loopback",
            )
        if not 0 <= self.port <= _MAX_PORT:
            raise FormatError("SOVA-REPLAY-SERVICE-PORT", "replay service port is invalid")
        if not 1 <= self.max_clients <= _MAX_CLIENTS:
            raise FormatError(
                "SOVA-REPLAY-SERVICE-CLIENTS", "replay service client limit is invalid"
            )
        if not _MIN_HOLD_SECONDS <= self.hold_seconds <= _MAX_HOLD_SECONDS:
            raise FormatError("SOVA-REPLAY-SERVICE-HOLD", "replay event hold duration is invalid")
        if not _MIN_POLL_SECONDS <= self.poll_seconds <= _MAX_POLL_SECONDS:
            raise FormatError("SOVA-REPLAY-SERVICE-POLL", "replay polling duration is invalid")


@dataclass(frozen=True, slots=True)
class ReplaySnapshot:
    """One integrity-checked sealed trace or validated live prefix."""

    source: str
    events: tuple[dict[str, Any], ...]
    completion: str

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.replay-snapshot",
            "schemaVersion": "0.1.0",
            "source": self.source,
            "eventCount": len(self.events),
            "completion": self.completion,
            "events": list(self.events),
            "limitations": [
                "A live prefix is not a sealed or signed trace.",
                "The replay service displays already-redacted observable events only.",
            ],
        }


def _staging_path(source: Path) -> Path:
    return source.with_name(f".{source.name}.partial")


def _validated_live_prefix(  # noqa: PLR0912 - linear integrity validation
    staging: Path,
) -> tuple[dict[str, Any], ...]:
    if staging.is_symlink() or not staging.is_dir():
        raise FormatError("SOVA-REPLAY-LIVE-SOURCE", "live trace staging source is unavailable")
    event_root = staging / "events"
    if event_root.is_symlink() or not event_root.is_dir():
        raise FormatError("SOVA-REPLAY-LIVE-SOURCE", "live trace event directory is unavailable")
    events: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    previous_hash: str | None = None
    total_bytes = 0
    paths = sorted(event_root.glob("*.jsonl"), key=lambda item: item.name)
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise FormatError("SOVA-REPLAY-LIVE-SOURCE", "live event segment is unsafe")
        data = path.read_bytes()
        total_bytes += len(data)
        if total_bytes > _MAX_SOURCE_BYTES:
            raise FormatError("SOVA-REPLAY-LIVE-LIMIT", "live trace exceeds 256 MiB")
        lines = data.split(b"\n")
        if lines and lines[-1]:
            lines.pop()  # the writer may still be persisting the final line
        for raw_line in lines:
            if not raw_line:
                continue
            if len(raw_line) > _MAX_EVENT_BYTES:
                raise FormatError("SOVA-REPLAY-LIVE-LIMIT", "live event exceeds 8 MiB")
            value = strict_json_loads(raw_line, max_bytes=_MAX_EVENT_BYTES)
            if not isinstance(value, dict):
                raise FormatError("SOVA-REPLAY-LIVE-EVENT", "live event must be an object")
            validate_document(value, "sova.event")
            if value["sequence"] != len(events):
                raise FormatError(
                    "SOVA-REPLAY-LIVE-SEQUENCE", "live event sequence is non-contiguous"
                )
            if value["id"] in seen_ids:
                raise FormatError("SOVA-REPLAY-LIVE-ID", "live event id is duplicated")
            if value["previousHash"] != previous_hash or event_hash(value) != value["eventHash"]:
                raise FormatError("SOVA-REPLAY-LIVE-CHAIN", "live event hash chain is invalid")
            if any(parent not in seen_ids for parent in value["parents"]):
                raise FormatError(
                    "SOVA-REPLAY-LIVE-PARENT", "live event has an unavailable causal parent"
                )
            RedactionVerifier().verify(value["payload"], value["redactions"])
            events.append(value)
            if len(events) > _MAX_EVENTS:
                raise FormatError("SOVA-REPLAY-LIVE-LIMIT", "live replay exceeds 50,000 events")
            seen_ids.add(value["id"])
            previous_hash = value["eventHash"]
    return tuple(events)


def read_replay_snapshot(source: Path) -> ReplaySnapshot:
    """Read a finalized trace or its writer-owned live staging prefix."""
    resolved = source.absolute()
    if resolved.is_symlink():
        raise FormatError("SOVA-REPLAY-LIVE-SOURCE", "replay source symlinks are refused")
    for _attempt in range(2):
        if resolved.is_file():
            reader = TraceReader(resolved)
            reader.verify()
            sealed_events = reader.events()
            if len(sealed_events) > _MAX_EVENTS:
                raise FormatError("SOVA-REPLAY-LIVE-LIMIT", "replay exceeds 50,000 events")
            return ReplaySnapshot(resolved.name, tuple(sealed_events), "sealed")
        staging = resolved if resolved.is_dir() else _staging_path(resolved)
        try:
            live_events = _validated_live_prefix(staging)
        except FileNotFoundError:
            continue
        return ReplaySnapshot(resolved.name, live_events, "live-prefix")
    raise FormatError(
        "SOVA-REPLAY-LIVE-SOURCE",
        "neither a finalized trace nor its live staging prefix is available",
    )


class _ReplayHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 8

    def __init__(
        self,
        address: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
        owner: ReplayHTTPService,
    ) -> None:
        self.owner = owner
        super().__init__(address, handler)


class ReplayHTTPService:
    """Capability-URL, loopback-only reference transport for replay data."""

    def __init__(self, config: ReplayServiceConfig) -> None:
        self.config = config
        self._token = secrets.token_urlsafe(32)
        self._server: _ReplayHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._clients = threading.BoundedSemaphore(config.max_clients)

    @property
    def url(self) -> str:
        if self._server is None:
            raise FormatError("SOVA-REPLAY-SERVICE-STATE", "replay service is not running")
        port = int(self._server.server_address[1])
        return f"http://{self.config.host}:{port}/r/{self._token}/"

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        service = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "SOVAReplay/0.1"
            sys_version = ""

            def log_message(self, _format: str, *_args: object) -> None:
                return  # capability URL and trace names must not enter access logs

            def _headers(self, status: HTTPStatus, media_type: str, length: int) -> None:
                self.send_response(status)
                self.send_header("Content-Type", media_type)
                self.send_header("Content-Length", str(length))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.end_headers()

            def _error(self, status: HTTPStatus, code: str) -> None:
                body = canonical_json_bytes(
                    {"artifactType": "sova.error", "code": code, "status": int(status)}
                )
                self._headers(status, "application/json", len(body))
                self.wfile.write(body)

            def _host_valid(self) -> bool:
                if service._server is None:
                    return False
                expected = f"{service.config.host}:{service._server.server_address[1]}"
                return hmac.compare_digest(self.headers.get("Host", ""), expected)

            def _route(self) -> tuple[str, dict[str, list[str]]] | None:
                if not self._host_valid():
                    return None
                parsed = urlsplit(self.path)
                prefix = f"/r/{service._token}/"
                if not parsed.path.startswith(prefix):
                    return None
                return parsed.path[len(prefix) :], parse_qs(parsed.query, strict_parsing=False)

            def do_HEAD(self) -> None:
                route = self._route()
                if route is None or route[0] not in {"", "snapshot"}:
                    self._error(HTTPStatus.NOT_FOUND, "SOVA-REPLAY-ROUTE")
                    return
                media_type = (
                    "application/json" if route[0] == "snapshot" else "text/html; charset=utf-8"
                )
                self._headers(HTTPStatus.OK, media_type, 0)

            def do_POST(self) -> None:
                self._error(HTTPStatus.METHOD_NOT_ALLOWED, "SOVA-REPLAY-READ-ONLY")

            def do_GET(self) -> None:
                if not service._clients.acquire(blocking=False):
                    self._error(HTTPStatus.SERVICE_UNAVAILABLE, "SOVA-REPLAY-CLIENT-LIMIT")
                    return
                try:
                    route = self._route()
                    if route is None:
                        self._error(HTTPStatus.NOT_FOUND, "SOVA-REPLAY-ROUTE")
                        return
                    name, query = route
                    if name == "":
                        self._page()
                    elif name == "snapshot":
                        self._snapshot()
                    elif name == "events":
                        self._events(query)
                    else:
                        self._error(HTTPStatus.NOT_FOUND, "SOVA-REPLAY-ROUTE")
                finally:
                    service._clients.release()

            def _page(self) -> None:
                snapshot = read_replay_snapshot(service.config.source)
                endpoint = None if snapshot.completion == "sealed" else "events"
                payload = {
                    "mode": ReplayMode.PLAYBACK.value,
                    "source": snapshot.source,
                    "comparison": None,
                    "counterfactual": None,
                    "events": list(snapshot.events),
                    "comparisonEvents": [],
                    "completion": snapshot.completion,
                    "liveEndpoint": endpoint,
                    "warning": "Inert playback only. No recorded action is executed.",
                }
                body = replay_document(payload).encode("utf-8")
                self._headers(HTTPStatus.OK, "text/html; charset=utf-8", len(body))
                self.wfile.write(body)

            def _snapshot(self) -> None:
                body = canonical_json_bytes(
                    read_replay_snapshot(service.config.source).to_mapping()
                )
                self._headers(HTTPStatus.OK, "application/json", len(body))
                self.wfile.write(body)

            def _events(self, query: dict[str, list[str]]) -> None:
                raw_after = self.headers.get("Last-Event-ID")
                if raw_after is None:
                    raw_after = query.get("after", ["-1"])[0]
                try:
                    after = int(raw_after)
                except ValueError:
                    self._error(HTTPStatus.BAD_REQUEST, "SOVA-REPLAY-EVENT-ID")
                    return
                if after < -1 or after > _MAX_EVENTS:
                    self._error(HTTPStatus.BAD_REQUEST, "SOVA-REPLAY-EVENT-ID")
                    return
                deadline = time.monotonic() + service.config.hold_seconds
                snapshot = read_replay_snapshot(service.config.source)
                while len(snapshot.events) <= after + 1 and snapshot.completion != "sealed":
                    if time.monotonic() >= deadline:
                        break
                    time.sleep(service.config.poll_seconds)
                    snapshot = read_replay_snapshot(service.config.source)
                chunks: list[bytes] = []
                for event in snapshot.events[after + 1 :]:
                    data = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
                    chunks.append(
                        f"id: {event['sequence']}\nevent: trace-event\ndata: {data}\n\n".encode()
                    )
                if snapshot.completion == "sealed":
                    chunks.append(b'event: sealed\ndata: {"completion":"sealed"}\n\n')
                if not chunks:
                    chunks.append(b": keepalive\n\n")
                body = b"".join(chunks)
                self._headers(HTTPStatus.OK, "text/event-stream; charset=utf-8", len(body))
                self.wfile.write(body)

        return Handler

    def start(self) -> ReplayHTTPService:
        if self._server is not None:
            raise FormatError("SOVA-REPLAY-SERVICE-STATE", "replay service is already running")
        read_replay_snapshot(self.config.source)
        self._server = _ReplayHTTPServer(
            (self.config.host, self.config.port), self._handler(), self
        )
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="sova-replay", daemon=True
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None


__all__ = [
    "ReplayHTTPService",
    "ReplayServiceConfig",
    "ReplaySnapshot",
    "read_replay_snapshot",
]
