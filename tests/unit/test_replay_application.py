# SPDX-License-Identifier: Apache-2.0
"""Evidence-native replay application and live-tail acceptance tests."""

from __future__ import annotations

import http.client
import json
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import pytest

from sova.cli import main
from sova.formats import canonical_json_bytes
from sova.formats.errors import FormatError
from sova.replay import (
    ReplayHTTPService,
    ReplayServiceConfig,
    read_replay_snapshot,
    render_timeline_html,
)
from sova.replay import service as replay_service
from sova.trace import TraceWriter
from sova.trace.integrity import event_hash

if TYPE_CHECKING:
    from pathlib import Path


def _trace(path: Path, *, hostile: bool = False) -> None:
    writer = TraceWriter(path)
    first = writer.append(
        "prompt.submitted",
        {"text": "</script><script>alert('fixture')</script>" if hostile else "safe"},
        actor={"id": "actor:a", "kind": "agent", "name": "Attacker"},
        target={"id": "target:model", "kind": "model", "name": "Fixture model"},
    )
    assert first is not None
    writer.append(
        "tool.completed",
        {"status": "observed"},
        actor={"id": "actor:a", "kind": "agent", "name": "Attacker"},
        target={"id": "tool:fixture", "kind": "tool", "name": "Fixture tool"},
        parents=[first],
    )
    writer.finalize()


def _request(
    url: str,
    *,
    host: str | None = None,
    method: str = "GET",
    extra_headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    parsed = urlsplit(url)
    assert parsed.hostname is not None and parsed.port is not None
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
    headers = dict(extra_headers or {})
    if host is not None:
        headers["Host"] = host
    connection.request(
        method, parsed.path + ("?" + parsed.query if parsed.query else ""), headers=headers
    )
    response = connection.getresponse()
    body = response.read()
    result = response.status, {key.lower(): value for key, value in response.getheaders()}, body
    connection.close()
    return result


def _live_rows(source: Path, count: int = 2) -> tuple[Path, list[dict[str, Any]]]:
    writer = TraceWriter(source)
    for index in range(count):
        writer.append("run.started", {"index": index})
    staging = source.with_name(f".{source.name}.partial")
    segment = next((staging / "events").glob("*.jsonl"))
    rows = [json.loads(line) for line in segment.read_text(encoding="utf-8").splitlines()]
    return segment, rows


def _write_rows(segment: Path, rows: list[dict[str, Any]]) -> None:
    segment.write_bytes(b"".join(canonical_json_bytes(row) + b"\n" for row in rows))


def test_rich_static_replay_has_controls_lanes_links_and_hostile_content_safety(
    tmp_path: Path,
) -> None:
    source = tmp_path / "hostile.sova-trace"
    comparison = tmp_path / "comparison.sova-trace"
    _trace(source, hostile=True)
    _trace(comparison)
    destination = tmp_path / "replay.html"

    render_timeline_html(source, destination, comparison=comparison, counterfactual="remove-x")

    rendered = destination.read_text(encoding="utf-8")
    assert 'id="play"' in rendered
    assert 'id="speed"' in rendered
    assert 'id="lanes"' in rendered
    assert "Recorded causal / correlation links" in rendered
    assert "Synchronized comparison" in rendered
    assert "EventSource" in rendered
    assert "textContent" in rendered
    assert "</script><script>alert('fixture')" not in rendered
    assert "\\u003c/script\\u003e\\u003cscript\\u003ealert('fixture')" in rendered
    assert "Content-Security-Policy" in rendered


def test_live_prefix_is_validated_then_transitions_to_sealed_trace(tmp_path: Path) -> None:
    source = tmp_path / "live.sova-trace"
    writer = TraceWriter(source)
    writer.append("run.started", {"safe": True})
    live = read_replay_snapshot(source)
    assert live.completion == "live-prefix"
    assert len(live.events) == 1
    writer.append("run.completed", {"safe": True})
    writer.finalize()
    sealed = read_replay_snapshot(source)
    assert sealed.completion == "sealed"
    assert len(sealed.events) == 2


def test_loopback_replay_service_uses_capability_url_sse_and_security_headers(
    tmp_path: Path,
) -> None:
    source = tmp_path / "served.sova-trace"
    _trace(source)
    service = ReplayHTTPService(
        ReplayServiceConfig(source, hold_seconds=0.1, poll_seconds=0.02)
    ).start()
    try:
        status, headers, page = _request(service.url)
        assert status == 200
        assert headers["cache-control"] == "no-store"
        assert headers["x-frame-options"] == "DENY"
        assert b"SOVA REPLAY" in page
        status, headers, snapshot = _request(service.url + "snapshot")
        assert status == 200
        assert headers["content-type"] == "application/json"
        assert json.loads(snapshot)["completion"] == "sealed"
        status, headers, stream = _request(service.url + "events?after=-1")
        assert status == 200
        assert headers["content-type"].startswith("text/event-stream")
        assert b"event: trace-event" in stream
        assert b"event: sealed" in stream

        parsed = urlsplit(service.url)
        wrong = f"http://{parsed.hostname}:{parsed.port}/r/wrong/snapshot"
        assert _request(wrong)[0] == 404
        assert _request(service.url, host="attacker.invalid")[0] == 404
    finally:
        service.stop()


def test_live_reader_refuses_tampering_symlink_and_limits(tmp_path: Path) -> None:
    source = tmp_path / "tampered.sova-trace"
    writer = TraceWriter(source)
    writer.append("run.started", {"safe": True})
    staging = source.with_name(f".{source.name}.partial")
    segment = next((staging / "events").glob("*.jsonl"))
    segment.write_bytes(segment.read_bytes().replace(b'"safe":true', b'"safe":false'))
    writer.finalize(completion="partial")
    with pytest.raises(FormatError, match="eventHash"):
        read_replay_snapshot(source)

    with pytest.raises(FormatError, match="literal IPv4 loopback"):
        ReplayServiceConfig(source, host="0.0.0.0")  # noqa: S104 - rejection fixture
    with pytest.raises(FormatError, match="client limit"):
        ReplayServiceConfig(source, max_clients=0)


def test_live_service_refuses_bad_event_id_and_is_read_only(tmp_path: Path) -> None:
    source = tmp_path / "routes.sova-trace"
    _trace(source)
    service = ReplayHTTPService(
        ReplayServiceConfig(source, hold_seconds=0.1, poll_seconds=0.02)
    ).start()
    try:
        assert _request(service.url + "events?after=not-an-integer")[0] == 400
        parsed = urlsplit(service.url)
        assert parsed.hostname is not None and parsed.port is not None
        connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
        connection.request("POST", parsed.path, body=b"{}")
        response = connection.getresponse()
        assert response.status == 405
        response.read()
        connection.close()
    finally:
        service.stop()


def test_live_sse_tails_new_persisted_events_then_reports_sealing(tmp_path: Path) -> None:
    source = tmp_path / "tail.sova-trace"
    writer = TraceWriter(source)
    writer.append("run.started", {"step": 0})
    service = ReplayHTTPService(
        ReplayServiceConfig(source, hold_seconds=0.1, poll_seconds=0.02)
    ).start()
    try:
        writer.append("tool.completed", {"step": 1})
        status, _headers, stream = _request(service.url + "events?after=0")
        assert status == 200
        assert b"id: 1" in stream
        assert b"tool.completed" in stream
        assert b"event: sealed" not in stream

        writer.finalize()
        status, _headers, sealed = _request(service.url + "events?after=1")
        assert status == 200
        assert b"event: sealed" in sealed
    finally:
        service.stop()


def test_snapshot_mapping_never_claims_sealed_live_prefix(tmp_path: Path) -> None:
    source = tmp_path / "partial.sova-trace"
    writer = TraceWriter(source)
    writer.append("run.started", {"safe": True})
    mapping: dict[str, Any] = read_replay_snapshot(source).to_mapping()
    assert mapping["completion"] == "live-prefix"
    assert "not a sealed" in mapping["limitations"][0]
    writer.finalize(completion="partial")


def test_replay_serve_cli_runs_bounded_real_loopback_service(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "cli.sova-trace"
    _trace(source)
    assert (
        main(
            [
                "replay",
                "serve",
                str(source),
                "--duration-seconds",
                "0.1",
            ]
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["loopbackOnly"] is True
    assert report["executesRecordedActions"] is False
    assert report["url"].startswith("http://127.0.0.1:")


def test_replay_service_configuration_and_lifecycle_fail_closed(tmp_path: Path) -> None:
    source = tmp_path / "lifecycle.sova-trace"
    _trace(source)
    for kwargs in (
        {"port": -1},
        {"port": 65_536},
        {"hold_seconds": 0.01},
        {"hold_seconds": 31},
        {"poll_seconds": 0.001},
        {"poll_seconds": 3},
    ):
        with pytest.raises(FormatError):
            ReplayServiceConfig(source, **kwargs)

    service = ReplayHTTPService(ReplayServiceConfig(source, hold_seconds=0.1))
    with pytest.raises(FormatError, match="not running"):
        _ = service.url
    service.start()
    try:
        with pytest.raises(FormatError, match="already running"):
            service.start()
    finally:
        service.stop()
    service.stop()

    with pytest.raises(FormatError, match="staging source is unavailable"):
        read_replay_snapshot(tmp_path / "missing.sova-trace")
    empty_staging = tmp_path / "empty.partial"
    empty_staging.mkdir()
    with pytest.raises(FormatError, match="event directory"):
        read_replay_snapshot(empty_staging)


def test_replay_reader_refuses_source_symlinks_without_following(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = (tmp_path / "linked.sova-trace").absolute()
    original = type(source).is_symlink

    def fake_is_symlink(path: Path) -> bool:
        return path == source or original(path)

    monkeypatch.setattr(type(source), "is_symlink", fake_is_symlink)
    with pytest.raises(FormatError, match="symlinks are refused"):
        read_replay_snapshot(source)


def test_replay_http_head_resume_keepalive_routes_and_client_limit(tmp_path: Path) -> None:
    source = tmp_path / "http.sova-trace"
    writer = TraceWriter(source)
    writer.append("run.started", {"step": 0})
    service = ReplayHTTPService(
        ReplayServiceConfig(source, max_clients=1, hold_seconds=0.1, poll_seconds=0.02)
    ).start()
    try:
        status, headers, body = _request(service.url, method="HEAD")
        assert status == 200 and body == b""
        assert headers["content-type"].startswith("text/html")
        status, headers, body = _request(service.url + "snapshot", method="HEAD")
        assert status == 200 and body == b""
        assert headers["content-type"] == "application/json"
        assert _request(service.url + "unknown")[0] == 404
        assert _request(service.url + "unknown", method="HEAD")[0] == 404
        assert _request(service.url + "events", extra_headers={"Last-Event-ID": "bad"})[0] == 400
        assert _request(service.url + "events?after=-2")[0] == 400
        assert _request(service.url + "events?after=50001")[0] == 400

        status, _headers, keepalive = _request(service.url + "events?after=0")
        assert status == 200 and keepalive == b": keepalive\n\n"
        # The response body can reach the client just before the handler's finally
        # block releases the slot. Wait for that release before deliberately
        # occupying the only slot to test the 503 path.
        assert service._clients.acquire(timeout=2)
        try:
            assert _request(service.url)[0] == 503
        finally:
            service._clients.release()
    finally:
        writer.finalize(completion="partial")
        service.stop()


def test_live_prefix_rejects_malformed_order_identity_parent_secret_and_bounds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    non_object = tmp_path / "non-object.sova-trace"
    segment, _rows = _live_rows(non_object, 1)
    segment.write_bytes(b"[]\n")
    with pytest.raises(FormatError, match="must be an object"):
        read_replay_snapshot(non_object)

    sequence_source = tmp_path / "sequence.sova-trace"
    segment, rows = _live_rows(sequence_source, 1)
    rows[0]["sequence"] = 1
    rows[0]["eventHash"] = event_hash(rows[0])
    _write_rows(segment, rows)
    with pytest.raises(FormatError, match="sequence"):
        read_replay_snapshot(sequence_source)

    duplicate_source = tmp_path / "duplicate.sova-trace"
    segment, rows = _live_rows(duplicate_source)
    rows[1]["id"] = rows[0]["id"]
    rows[1]["eventHash"] = event_hash(rows[1])
    _write_rows(segment, rows)
    with pytest.raises(FormatError, match="duplicated"):
        read_replay_snapshot(duplicate_source)

    parent_source = tmp_path / "parent.sova-trace"
    segment, rows = _live_rows(parent_source)
    rows[1]["parents"] = ["sova:event:00000000-0000-0000-0000-000000000000"]
    rows[1]["eventHash"] = event_hash(rows[1])
    _write_rows(segment, rows)
    with pytest.raises(FormatError, match="causal parent"):
        read_replay_snapshot(parent_source)

    secret_source = tmp_path / "secret.sova-trace"
    segment, rows = _live_rows(secret_source, 1)
    rows[0]["payload"] = {"apiKey": "synthetic-secret"}
    rows[0]["eventHash"] = event_hash(rows[0])
    _write_rows(segment, rows)
    with pytest.raises(FormatError, match="secret-shaped field"):
        read_replay_snapshot(secret_source)

    bounded_source = tmp_path / "bounded.sova-trace"
    _segment, _rows = _live_rows(bounded_source, 1)
    monkeypatch.setattr(replay_service, "_MAX_SOURCE_BYTES", 1)
    with pytest.raises(FormatError, match="256 MiB"):
        read_replay_snapshot(bounded_source)
    monkeypatch.setattr(replay_service, "_MAX_SOURCE_BYTES", 256 * 1024 * 1024)
    monkeypatch.setattr(replay_service, "_MAX_EVENT_BYTES", 1)
    with pytest.raises(FormatError, match="8 MiB"):
        read_replay_snapshot(bounded_source)
    monkeypatch.setattr(replay_service, "_MAX_EVENT_BYTES", 8 * 1024 * 1024)
    monkeypatch.setattr(replay_service, "_MAX_EVENTS", 0)
    with pytest.raises(FormatError, match="50,000"):
        read_replay_snapshot(bounded_source)

    sealed_source = tmp_path / "sealed-limit.sova-trace"
    _trace(sealed_source)
    with pytest.raises(FormatError, match="50,000"):
        read_replay_snapshot(sealed_source)
