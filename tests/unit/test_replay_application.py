# SPDX-License-Identifier: Apache-2.0
"""Evidence-native replay application and live-tail acceptance tests."""

from __future__ import annotations

import base64
import http.client
import io
import json
import struct
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import pytest

from sova.capsule import build_capsule, capsule_manifest_template
from sova.cli import main
from sova.formats import PackageReader, PackageWriter, canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.replay import (
    CapsuleReplaySelection,
    ReplayHTTPService,
    ReplayServiceConfig,
    read_replay_snapshot,
    render_capsule_timeline,
    render_timeline_html,
)
from sova.replay import render as replay_render
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


def _ebml_size(value: int) -> bytes:
    if value < 0x7F:
        return bytes((0x80 | value,))
    if value < 0x3FFF:
        return bytes((0x40 | (value >> 8), value & 0xFF))
    raise AssertionError


def _ebml(identifier: bytes, payload: bytes) -> bytes:
    return identifier + _ebml_size(len(payload)) + payload


def _synthetic_webm(*, duration_seconds: float = 12.0) -> bytes:
    info = _ebml(b"\x2a\xd7\xb1", (1_000_000).to_bytes(3, "big")) + _ebml(
        b"\x44\x89", struct.pack(">d", duration_seconds * 1000)
    )
    segment = b"".join(
        (
            _ebml(b"\x15\x49\xa9\x66", info),
            _ebml(b"\x16\x54\xae\x6b", b"\xae\x80"),
            _ebml(b"\x1f\x43\xb6\x75", b"\xe7\x81\x00"),
        )
    )
    return _ebml(b"\x1a\x45\xdf\xa3", b"") + _ebml(b"\x18\x53\x80\x67", segment)


def _synthetic_webm_timeline() -> bytes:
    info = _ebml(b"\x2a\xd7\xb1", (1_000_000).to_bytes(3, "big"))
    simple_block = b"\x81" + (2500).to_bytes(2, "big", signed=True) + b"\x80"
    grouped_block = b"\x81" + (3000).to_bytes(2, "big", signed=True) + b"\x80"
    cluster = b"".join(
        (
            _ebml(b"\xe7", (1000).to_bytes(2, "big")),
            _ebml(b"\xa3", simple_block),
            _ebml(b"\xa0", _ebml(b"\xec", b"ignored") + _ebml(b"\xa1", grouped_block)),
        )
    )
    segment = b"".join(
        (
            _ebml(b"\x15\x49\xa9\x66", info),
            _ebml(b"\x16\x54\xae\x6b", b"\xae\x80"),
            _ebml(b"\x1f\x43\xb6\x75", cluster),
        )
    )
    return _ebml(b"\x1a\x45\xdf\xa3", b"") + _ebml(b"\x18\x53\x80\x67", segment)


def _mp4_box(kind: bytes, payload: bytes) -> bytes:
    return (len(payload) + 8).to_bytes(4, "big") + kind + payload


def _mp4_extended_box(kind: bytes, payload: bytes) -> bytes:
    return b"\x00\x00\x00\x01" + kind + (len(payload) + 16).to_bytes(8, "big") + payload


def _mp4_to_end_box(kind: bytes, payload: bytes) -> bytes:
    return b"\x00\x00\x00\x00" + kind + payload


def _synthetic_mp4(*, duration_seconds: float = 12.0) -> bytes:
    timescale = 1000
    movie_header = (
        b"\x00\x00\x00\x00"
        + (0).to_bytes(4, "big")
        + (0).to_bytes(4, "big")
        + timescale.to_bytes(4, "big")
        + int(duration_seconds * timescale).to_bytes(4, "big")
    )
    return _mp4_box(b"ftyp", b"isom\x00\x00\x00\x00isom") + _mp4_box(
        b"moov", _mp4_box(b"mvhd", movie_header)
    )


def _synthetic_mp4_v1(*, duration_seconds: float = 13.25) -> bytes:
    timescale = 1000
    movie_header = (
        b"\x01\x00\x00\x00"
        + (0).to_bytes(8, "big")
        + (0).to_bytes(8, "big")
        + timescale.to_bytes(4, "big")
        + int(duration_seconds * timescale).to_bytes(8, "big")
    )
    return _mp4_box(b"ftyp", b"isom\x00\x00\x00\x00isom") + _mp4_extended_box(
        b"moov", _mp4_to_end_box(b"mvhd", movie_header)
    )


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


def test_static_replay_embeds_reviewed_browser_video_without_executing_trace_content(
    tmp_path: Path,
) -> None:
    source = tmp_path / "recorded.sova-trace"
    _trace(source)
    media = tmp_path / "browser-session.webm"
    payload = _synthetic_webm()
    media.write_bytes(payload)
    destination = tmp_path / "recorded-replay.html"

    render_timeline_html(source, destination, media=media)

    rendered = destination.read_text(encoding="utf-8")
    assert 'id="sessionVideo"' in rendered
    assert "Recorded browser session" in rendered
    assert "event-time synchronization is not attested" in rendered
    assert f"data:video/webm;base64,{base64.b64encode(payload).decode('ascii')}" in rendered
    assert "media-src 'self' data:" in rendered


def test_replay_cues_open_on_digest_bound_decisive_oracle_moment(tmp_path: Path) -> None:
    source = tmp_path / "decisive.sova-trace"
    writer = TraceWriter(source)
    event_id = writer.append("oracle.completed", {"status": "pass", "results": []})
    assert event_id is not None
    writer.finalize()
    video = tmp_path / "browser-session.webm"
    video.write_bytes(_synthetic_webm())
    cues = tmp_path / "replay-cues.json"
    cue_document = {
        "artifactType": "sova.replay-cues",
        "schemaVersion": "0.1.0",
        "mediaName": video.name,
        "mediaDigest": sha256_digest(video.read_bytes()),
        "synchronization": {
            "method": "same-host-monotonic-recorder-start-rpc-bound",
            "uncertaintyMs": "1.250",
            "frameTimestampAttested": False,
            "statement": "Fixture same-host monotonic synchronization bound.",
        },
        "cues": [
            {
                "id": "decisive-01",
                "label": "Exploit confirmed",
                "channel": "attempt-001",
                "eventId": event_id,
                "eventKind": "oracle.completed",
                "eventSequence": 0,
                "oracleStatus": "pass",
                "offsetSeconds": "4.500000",
                "chapterOffsetSeconds": "4.600000",
                "preRollSeconds": "2.000000",
                "postRollSeconds": "3.000000",
            }
        ],
    }
    cues.write_bytes(canonical_json_bytes(cue_document) + b"\n")
    destination = tmp_path / "decisive-replay.html"

    replay = render_timeline_html(source, destination, media=video, replay_cues=cues)

    rendered = destination.read_text(encoding="utf-8")
    assert 'id="breakpoint"' in rendered
    assert 'id="playDecisive"' in rendered
    assert '"defaultCueId":"decisive-01"' in rendered
    assert "same-host-monotonic-recorder-start-rpc-bound" in rendered
    assert "seekCue(cue,false)" in rendered
    assert replay["opensAtDecisiveMoment"] is True
    assert replay["decisiveCue"]["eventId"] == event_id
    assert replay["decisiveCueSource"] == "primary"
    assert replay["mediaDurationSeconds"] == "12.000000"

    manifest = capsule_manifest_template(
        title="Decisive replay", summary="Digest-bound replay cue fixture.", author="Tests"
    )
    manifest["license"] = "Apache-2.0"
    manifest["safety"]["impact"] = "none"
    capsule = tmp_path / "decisive.sova"
    build_capsule(
        capsule,
        manifest,
        attachments={video.name: video.read_bytes(), cues.name: cues.read_bytes()},
        traces=[source],
    )
    report = render_capsule_timeline(capsule, tmp_path / "capsule-decisive.html")
    assert report["opensAtDecisiveMoment"] is True
    assert report["replayCues"] is not None
    assert report["decisiveCue"]["eventId"] == event_id
    assert report["decisiveCueDurationBound"] is True


def test_replay_cues_default_to_the_selected_primary_trace(tmp_path: Path) -> None:
    discovery = tmp_path / "discovery.sova-trace"
    discovery_writer = TraceWriter(discovery)
    discovery_event = discovery_writer.append("oracle.completed", {"status": "pass", "results": []})
    assert discovery_event is not None
    discovery_writer.finalize()
    reproduction = tmp_path / "reproduction.sova-trace"
    reproduction_writer = TraceWriter(reproduction)
    reproduction_event = reproduction_writer.append(
        "oracle.completed", {"status": "pass", "results": []}
    )
    assert reproduction_event is not None
    reproduction_writer.finalize()
    video = tmp_path / "browser-session.webm"
    video.write_bytes(_synthetic_webm())
    cues = tmp_path / "replay-cues.json"
    cue_template = {
        "label": "Exploit confirmed",
        "eventKind": "oracle.completed",
        "eventSequence": 0,
        "oracleStatus": "pass",
        "preRollSeconds": "2.000000",
        "postRollSeconds": "3.000000",
    }
    cues.write_bytes(
        canonical_json_bytes(
            {
                "artifactType": "sova.replay-cues",
                "schemaVersion": "0.1.0",
                "mediaName": video.name,
                "mediaDigest": sha256_digest(video.read_bytes()),
                "synchronization": {
                    "method": "same-host-monotonic-recorder-start-rpc-bound",
                    "uncertaintyMs": "1.000",
                    "frameTimestampAttested": False,
                    "statement": "Fixture.",
                },
                "cues": [
                    {
                        **cue_template,
                        "id": "decisive-discovery",
                        "channel": "attempt-001",
                        "eventId": discovery_event,
                        "offsetSeconds": "4.000000",
                        "chapterOffsetSeconds": "4.100000",
                    },
                    {
                        **cue_template,
                        "id": "decisive-reproduction",
                        "channel": "reproduction",
                        "eventId": reproduction_event,
                        "offsetSeconds": "8.000000",
                        "chapterOffsetSeconds": "8.100000",
                    },
                ],
            }
        )
        + b"\n"
    )

    destination = tmp_path / "two-trace-replay.html"
    replay = render_timeline_html(
        reproduction,
        destination,
        comparison=discovery,
        media=video,
        replay_cues=cues,
    )

    rendered = destination.read_text(encoding="utf-8")
    assert '"defaultCueId":"decisive-reproduction"' in rendered
    assert replay["decisiveCueSource"] == "primary"


def test_comparison_only_decisive_cue_is_indexed_and_selected(tmp_path: Path) -> None:
    primary = tmp_path / "primary.sova-trace"
    _trace(primary)
    comparison = tmp_path / "comparison.sova-trace"
    writer = TraceWriter(comparison)
    event_id = writer.append("oracle.completed", {"status": "pass", "results": []})
    assert event_id is not None
    writer.finalize()
    video = tmp_path / "comparison.webm"
    video.write_bytes(_synthetic_webm())
    cues = tmp_path / "replay-cues.json"
    cues.write_bytes(
        canonical_json_bytes(
            {
                "artifactType": "sova.replay-cues",
                "schemaVersion": "0.1.0",
                "mediaName": video.name,
                "mediaDigest": sha256_digest(video.read_bytes()),
                "synchronization": {
                    "method": "same-host-monotonic-recorder-start-rpc-bound",
                    "uncertaintyMs": "1.000",
                    "frameTimestampAttested": False,
                    "statement": "Fixture.",
                },
                "cues": [
                    {
                        "id": "comparison-only",
                        "label": "Exploit confirmed",
                        "channel": "comparison",
                        "eventId": event_id,
                        "eventKind": "oracle.completed",
                        "eventSequence": 0,
                        "oracleStatus": "pass",
                        "offsetSeconds": "4.000000",
                        "chapterOffsetSeconds": "4.100000",
                        "preRollSeconds": "2.000000",
                        "postRollSeconds": "3.000000",
                    }
                ],
            }
        )
        + b"\n"
    )

    destination = tmp_path / "comparison-cue.html"
    replay = render_timeline_html(
        primary,
        destination,
        comparison=comparison,
        media=video,
        replay_cues=cues,
    )

    rendered = destination.read_text(encoding="utf-8")
    assert replay["opensAtDecisiveMoment"] is True
    assert replay["decisiveCueSource"] == "comparison"
    assert "comparison.forEach(e=>byId.set(e.id,e))" in rendered
    assert "showComparisonCue(event)" in rendered


def test_replay_cues_reject_empty_or_duplicate_indexes(tmp_path: Path) -> None:
    source = tmp_path / "cue-policy.sova-trace"
    writer = TraceWriter(source)
    event_id = writer.append("oracle.completed", {"status": "pass", "results": []})
    assert event_id is not None
    writer.finalize()
    video = tmp_path / "browser-session.webm"
    video.write_bytes(_synthetic_webm())
    cues = tmp_path / "replay-cues.json"
    document: dict[str, Any] = {
        "artifactType": "sova.replay-cues",
        "schemaVersion": "0.1.0",
        "mediaName": video.name,
        "mediaDigest": sha256_digest(video.read_bytes()),
        "synchronization": {
            "method": "same-host-monotonic-recorder-start-rpc-bound",
            "uncertaintyMs": "1.000",
            "frameTimestampAttested": False,
            "statement": "Fixture.",
        },
        "cues": [],
    }
    cues.write_bytes(canonical_json_bytes(document) + b"\n")
    with pytest.raises(FormatError, match="count"):
        render_timeline_html(source, tmp_path / "empty-cues.html", media=video, replay_cues=cues)

    cue = {
        "id": "duplicate",
        "label": "Exploit confirmed",
        "channel": "attempt-001",
        "eventId": event_id,
        "eventKind": "oracle.completed",
        "eventSequence": 0,
        "oracleStatus": "pass",
        "offsetSeconds": "4.000000",
        "chapterOffsetSeconds": "4.100000",
        "preRollSeconds": "2.000000",
        "postRollSeconds": "3.000000",
    }
    document["cues"] = [cue, dict(cue)]
    cues.write_bytes(canonical_json_bytes(document) + b"\n")
    with pytest.raises(FormatError, match="invalid decisive"):
        render_timeline_html(
            source,
            tmp_path / "duplicate-cues.html",
            media=video,
            replay_cues=cues,
        )

    document["cues"] = [{**cue, "id": "wrong-sequence", "eventSequence": 99}]
    cues.write_bytes(canonical_json_bytes(document) + b"\n")
    with pytest.raises(FormatError, match="invalid decisive"):
        render_timeline_html(
            source,
            tmp_path / "wrong-event-sequence.html",
            media=video,
            replay_cues=cues,
        )

    document["cues"] = [{**cue, "id": "noncanonical-time", "offsetSeconds": "4e0"}]
    cues.write_bytes(canonical_json_bytes(document) + b"\n")
    with pytest.raises(FormatError, match="invalid decisive"):
        render_timeline_html(
            source,
            tmp_path / "noncanonical-time.html",
            media=video,
            replay_cues=cues,
        )


def test_replay_cues_reject_wrong_media_binding(tmp_path: Path) -> None:
    source = tmp_path / "wrong-binding.sova-trace"
    writer = TraceWriter(source)
    event_id = writer.append("oracle.completed", {"status": "pass", "results": []})
    assert event_id is not None
    writer.finalize()
    video = tmp_path / "browser-session.webm"
    video.write_bytes(_synthetic_webm())
    cues = tmp_path / "replay-cues.json"
    cues.write_bytes(
        canonical_json_bytes(
            {
                "artifactType": "sova.replay-cues",
                "schemaVersion": "0.1.0",
                "mediaName": video.name,
                "mediaDigest": "sha256:" + "0" * 64,
                "synchronization": {
                    "method": "same-host-monotonic-recorder-start-rpc-bound",
                    "uncertaintyMs": "1.000",
                    "frameTimestampAttested": False,
                    "statement": "Fixture.",
                },
                "cues": [],
            }
        )
        + b"\n"
    )
    with pytest.raises(FormatError, match="not bound"):
        render_timeline_html(
            source,
            tmp_path / "wrong-binding.html",
            media=video,
            replay_cues=cues,
        )


def test_decisive_open_claim_requires_bounded_container_duration(tmp_path: Path) -> None:
    trace = tmp_path / "duration.sova-trace"
    writer = TraceWriter(trace)
    event_id = writer.append("oracle.completed", {"status": "pass", "results": []})
    assert event_id is not None
    writer.finalize()

    def cue_document(media: Path) -> dict[str, Any]:
        return {
            "artifactType": "sova.replay-cues",
            "schemaVersion": "0.1.0",
            "mediaName": media.name,
            "mediaDigest": sha256_digest(media.read_bytes()),
            "synchronization": {
                "method": "same-host-monotonic-recorder-start-rpc-bound",
                "uncertaintyMs": "1.000",
                "frameTimestampAttested": False,
                "statement": "Fixture.",
            },
            "cues": [
                {
                    "id": "duration-bound",
                    "label": "Exploit confirmed",
                    "channel": "primary",
                    "eventId": event_id,
                    "eventKind": "oracle.completed",
                    "eventSequence": 0,
                    "oracleStatus": "pass",
                    "offsetSeconds": "4.000000",
                    "chapterOffsetSeconds": "4.100000",
                    "preRollSeconds": "2.000000",
                    "postRollSeconds": "3.000000",
                }
            ],
        }

    malformed = tmp_path / "malformed.webm"
    malformed.write_bytes(b"\x1a\x45\xdf\xa3not-a-finalized-webm")
    cues = tmp_path / "malformed-cues.json"
    cues.write_bytes(canonical_json_bytes(cue_document(malformed)) + b"\n")
    report = render_timeline_html(
        trace,
        tmp_path / "malformed.html",
        media=malformed,
        replay_cues=cues,
    )
    assert report["decisiveCue"] is not None
    assert report["decisiveCueDurationBound"] is False
    assert report["opensAtDecisiveMoment"] is False

    too_short = tmp_path / "too-short.webm"
    too_short.write_bytes(_synthetic_webm(duration_seconds=1))
    cues.write_bytes(canonical_json_bytes(cue_document(too_short)) + b"\n")
    with pytest.raises(FormatError, match="outside the finalized media duration"):
        render_timeline_html(
            trace,
            tmp_path / "too-short.html",
            media=too_short,
            replay_cues=cues,
        )


def test_webm_duration_parser_accepts_finalized_blocks_and_rejects_bad_ebml() -> None:
    assert replay_render._webm_duration_seconds(_synthetic_webm_timeline()) == pytest.approx(4.0)

    duration32 = _ebml(b"\x2a\xd7\xb1", (1_000_000).to_bytes(3, "big")) + _ebml(
        b"\x44\x89", struct.pack(">f", 5000.0)
    )

    def webm(info: bytes, *, cluster: bytes = b"\xe7\x81\x00") -> bytes:
        segment = b"".join(
            (
                _ebml(b"\x15\x49\xa9\x66", info),
                _ebml(b"\x16\x54\xae\x6b", b"\xae\x80"),
                _ebml(b"\x1f\x43\xb6\x75", cluster),
            )
        )
        return _ebml(b"\x1a\x45\xdf\xa3", b"") + _ebml(b"\x18\x53\x80\x67", segment)

    assert replay_render._webm_duration_seconds(webm(duration32)) == pytest.approx(5.0)
    assert replay_render._ebml_vint(b"", 0, identifier=True) is None
    assert replay_render._ebml_vint(b"\x00", 0, identifier=True) is None
    assert replay_render._ebml_vint(b"\x40", 0, identifier=False) is None
    assert replay_render._ebml_vint(b"\xff", 0, identifier=False) == (None, 1)
    assert replay_render._ebml_elements(b"\x81\xff", 0, 2) == [(0x81, 2, 2)]
    assert replay_render._ebml_elements(b"\x00", 0, 1) is None
    assert replay_render._ebml_elements(b"\x81", 0, 1) is None
    assert replay_render._ebml_elements(b"\x81\x82\x00", 0, 3) is None

    header = _ebml(b"\x1a\x45\xdf\xa3", b"")
    segment_without_info = _ebml(
        b"\x18\x53\x80\x67",
        _ebml(b"\x16\x54\xae\x6b", b"\xae\x80") + _ebml(b"\x1f\x43\xb6\x75", b"\xe7\x81\x00"),
    )
    valid_info = _ebml(b"\x2a\xd7\xb1", (1_000_000).to_bytes(3, "big"))
    no_tracks = header + _ebml(
        b"\x18\x53\x80\x67",
        _ebml(b"\x15\x49\xa9\x66", duration32) + _ebml(b"\x1f\x43\xb6\x75", b"\xe7\x81\x00"),
    )
    malformed_info = webm(b"\x81")
    malformed_cluster = webm(valid_info, cluster=b"\x81")
    malformed_group = webm(
        valid_info,
        cluster=_ebml(b"\xe7", b"\x00") + _ebml(b"\xa0", b"\x81"),
    )
    invalid_scale = _ebml(b"\x2a\xd7\xb1", b"\x00") + _ebml(b"\x44\x89", struct.pack(">d", 1000.0))
    non_finite_duration = _ebml(b"\x2a\xd7\xb1", (1_000_000).to_bytes(3, "big")) + _ebml(
        b"\x44\x89", struct.pack(">d", float("nan"))
    )
    malformed_documents: tuple[bytes, ...] = (
        b"",
        header,
        header + _ebml(b"\x18\x53\x80\x67", b"\x81"),
        header + segment_without_info,
        no_tracks,
        malformed_info,
        malformed_cluster,
        malformed_group,
        webm(invalid_scale),
        webm(non_finite_duration),
        webm(valid_info),
    )
    assert all(replay_render._webm_duration_seconds(value) is None for value in malformed_documents)
    assert replay_render._block_relative_timecode(b"") is None
    assert replay_render._block_relative_timecode(b"\x81") is None


def test_mp4_duration_parser_accepts_v1_and_rejects_malformed_box_graphs() -> None:
    assert replay_render._mp4_duration_seconds(_synthetic_mp4()) == pytest.approx(12.0)
    assert replay_render._mp4_duration_seconds(_synthetic_mp4_v1()) == pytest.approx(13.25)

    ftyp = _mp4_box(b"ftyp", b"isom\x00\x00\x00\x00isom")
    version_zero = (
        b"\x00\x00\x00\x00"
        + (0).to_bytes(4, "big")
        + (0).to_bytes(4, "big")
        + (1000).to_bytes(4, "big")
        + (1000).to_bytes(4, "big")
    )
    malformed_documents = (
        b"\x00" * 7,
        b"\x00\x00\x00\x01ftyp\x00\x00\x00",
        b"\x00\x00\x00\x04ftyp",
        b"\x00\x00\x01\x00ftyp",
        _mp4_box(b"free", b"fixture"),
        ftyp,
        ftyp + _mp4_box(b"moov", b"") + _mp4_box(b"moov", b""),
        ftyp + _mp4_box(b"moov", b"\x00" * 7),
        ftyp + _mp4_box(b"moov", b""),
        ftyp + _mp4_box(b"moov", _mp4_box(b"mvhd", b"\x00" * 19)),
        ftyp
        + _mp4_box(
            b"moov",
            _mp4_box(b"mvhd", version_zero) + _mp4_box(b"mvhd", version_zero),
        ),
        ftyp + _mp4_box(b"moov", _mp4_box(b"mvhd", b"\x02" + b"\x00" * 31)),
        ftyp + _mp4_box(b"moov", _mp4_box(b"mvhd", b"\x01" + b"\x00" * 19)),
        ftyp
        + _mp4_box(
            b"moov",
            _mp4_box(b"mvhd", version_zero[:12] + b"\x00\x00\x00\x00" + version_zero[16:]),
        ),
        ftyp + _mp4_box(b"moov", _mp4_box(b"mvhd", version_zero[:16] + b"\x00" * 4)),
    )
    assert all(replay_render._mp4_duration_seconds(value) is None for value in malformed_documents)


def test_static_replay_refuses_empty_unsupported_and_linked_media(tmp_path: Path) -> None:
    source = tmp_path / "media-policy.sova-trace"
    _trace(source)
    empty = tmp_path / "empty.webm"
    empty.write_bytes(b"")
    unsupported = tmp_path / "recording.html"
    unsupported.write_text("not video", encoding="utf-8")
    mislabeled = tmp_path / "mislabeled.webm"
    mislabeled.write_bytes(b"not webm")

    with pytest.raises(FormatError, match="empty or exceeds"):
        render_timeline_html(source, tmp_path / "empty.html", media=empty)
    with pytest.raises(FormatError, match="WebM or MP4"):
        render_timeline_html(source, tmp_path / "unsupported.html", media=unsupported)
    with pytest.raises(FormatError, match="EBML signature"):
        render_timeline_html(source, tmp_path / "mislabeled.html", media=mislabeled)

    real = tmp_path / "real.webm"
    real.write_bytes(b"video")
    linked = tmp_path / "linked.webm"
    try:
        linked.symlink_to(real)
    except OSError:
        return
    with pytest.raises(FormatError, match="must not be a link"):
        render_timeline_html(source, tmp_path / "linked.html", media=linked)


def test_capsule_replay_selects_run_reproduction_and_embedded_video(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run = tmp_path / "run.sova-trace"
    reproduction = tmp_path / "reproduction.sova-trace"
    _trace(run)
    _trace(reproduction)
    video = _synthetic_webm()
    manifest = capsule_manifest_template(
        title="Recorded behavior", summary="Capsule-native replay fixture.", author="Tests"
    )
    manifest["license"] = "Apache-2.0"
    manifest["safety"]["impact"] = "none"
    capsule = tmp_path / "recorded.sova"
    build_capsule(
        capsule,
        manifest,
        attachments={"browser-session.webm": video},
        traces=[reproduction, run],
    )
    destination = tmp_path / "capsule-replay.html"

    assert main(["replay", "capsule", str(capsule), str(destination)]) == 0

    report = json.loads(capsys.readouterr().out)
    assert report["primaryTrace"] == "traces/run.sova-trace"
    assert report["comparisonTrace"] == "traces/reproduction.sova-trace"
    assert report["visualReplay"].startswith("blobs/sha256/")
    assert report["executesRecordedActions"] is False
    rendered = destination.read_text(encoding="utf-8")
    assert "Synchronized comparison" in rendered
    assert f"data:video/webm;base64,{base64.b64encode(video).decode('ascii')}" in rendered


def test_one_step_replay_derives_opens_and_reports_decisive_local_file(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trace = tmp_path / "reproduction.sova-trace"
    writer = TraceWriter(trace)
    event_id = writer.append("oracle.completed", {"status": "pass", "results": []})
    assert event_id is not None
    writer.finalize()
    video = _synthetic_webm()
    cue_document = {
        "artifactType": "sova.replay-cues",
        "schemaVersion": "0.1.0",
        "mediaName": "session.webm",
        "mediaDigest": sha256_digest(video),
        "synchronization": {
            "method": "same-host-monotonic-recorder-start-rpc-bound",
            "uncertaintyMs": "1.000",
            "frameTimestampAttested": False,
            "statement": "Fixture.",
        },
        "cues": [
            {
                "id": "decisive-reproduction",
                "label": "Exploit confirmed",
                "channel": "reproduction",
                "eventId": event_id,
                "eventKind": "oracle.completed",
                "eventSequence": 0,
                "oracleStatus": "pass",
                "offsetSeconds": "4.000000",
                "chapterOffsetSeconds": "4.100000",
                "preRollSeconds": "2.000000",
                "postRollSeconds": "3.000000",
            }
        ],
    }
    manifest = capsule_manifest_template(
        title="One-step replay", summary="CLI decisive replay fixture.", author="Tests"
    )
    manifest["license"] = "Apache-2.0"
    manifest["safety"]["impact"] = "none"
    capsule = tmp_path / "finding.sova"
    build_capsule(
        capsule,
        manifest,
        attachments={
            "session.webm": video,
            "replay-cues.json": canonical_json_bytes(cue_document),
        },
        traces=[trace],
    )
    opened: list[str] = []

    def open_local(uri: str, *, new: int, autoraise: bool) -> bool:
        assert new == 2
        assert autoraise is True
        opened.append(uri)
        return True

    monkeypatch.setattr("sova.cli.webbrowser.open", open_local)

    assert main(["replay", str(capsule)]) == 0
    report = json.loads(capsys.readouterr().out)
    expected = tmp_path / "finding-replay.html"
    assert report["destination"] == str(expected.resolve())
    assert report["localUri"] == expected.resolve().as_uri()
    assert report["openRequested"] is True
    assert report["opened"] is True
    assert report["opensAtDecisiveMoment"] is True
    assert report["decisiveCue"]["eventId"] == event_id
    assert report["decisiveCueSource"] == "primary"
    assert opened == [expected.resolve().as_uri()]
    assert expected.is_file()

    automated = tmp_path / "automation.html"
    assert (
        main(
            [
                "replay",
                "open",
                str(capsule),
                "--output",
                str(automated),
                "--no-open",
            ]
        )
        == 0
    )
    no_open_report = json.loads(capsys.readouterr().out)
    assert no_open_report["openRequested"] is False
    assert no_open_report["opened"] is None
    assert opened == [expected.resolve().as_uri()]


def test_capsule_replay_requires_explicit_choices_when_evidence_is_ambiguous(
    tmp_path: Path,
) -> None:
    traces = []
    for name in ("run.sova-trace", "alternate-a.sova-trace", "alternate-b.sova-trace"):
        path = tmp_path / name
        _trace(path)
        traces.append(path)
    manifest = capsule_manifest_template(
        title="Ambiguous evidence", summary="Selection fixture.", author="Tests"
    )
    manifest["license"] = "Apache-2.0"
    manifest["safety"]["impact"] = "none"
    capsule = tmp_path / "ambiguous.sova"
    build_capsule(capsule, manifest, traces=traces)

    with pytest.raises(FormatError, match="multiple comparison traces"):
        render_capsule_timeline(capsule, tmp_path / "ambiguous.html")

    report = render_capsule_timeline(
        capsule,
        tmp_path / "selected.html",
        selection=CapsuleReplaySelection(
            comparison_trace="traces/alternate-a.sova-trace", no_media=True
        ),
    )
    assert report["comparisonTrace"] == "traces/alternate-a.sova-trace"
    with pytest.raises(FormatError, match="source capsule"):
        render_capsule_timeline(capsule, capsule)


def test_capsule_replay_selection_and_missing_evidence_fail_closed(tmp_path: Path) -> None:
    manifest = capsule_manifest_template(
        title="Selection failures", summary="Exercise exact evidence choices.", author="Tests"
    )
    empty_capsule = tmp_path / "no-trace.sova"
    build_capsule(empty_capsule, manifest)
    with pytest.raises(FormatError, match="no verified trace"):
        render_capsule_timeline(empty_capsule, tmp_path / "no-trace.html")

    trace = tmp_path / "run.sova-trace"
    _trace(trace)
    capsule = tmp_path / "one-trace.sova"
    build_capsule(capsule, manifest, traces=[trace])
    with pytest.raises(FormatError, match="was not found"):
        render_capsule_timeline(
            capsule,
            tmp_path / "missing-selection.html",
            selection=CapsuleReplaySelection(primary_trace="traces/missing.sova-trace"),
        )
    with pytest.raises(FormatError, match="no-comparison"):
        render_capsule_timeline(
            capsule,
            tmp_path / "conflicting-comparison.html",
            selection=CapsuleReplaySelection(
                comparison_trace="traces/run.sova-trace", no_comparison=True
            ),
        )
    with pytest.raises(FormatError, match="no-media"):
        render_capsule_timeline(
            capsule,
            tmp_path / "conflicting-media.html",
            selection=CapsuleReplaySelection(media_object="blobs/missing", no_media=True),
        )
    with pytest.raises(FormatError, match="must be different"):
        render_capsule_timeline(
            capsule,
            tmp_path / "same-comparison.html",
            selection=CapsuleReplaySelection(
                primary_trace="traces/run.sova-trace",
                comparison_trace="traces/run.sova-trace",
            ),
        )

    report = render_capsule_timeline(
        capsule,
        tmp_path / "primary-only.html",
        selection=CapsuleReplaySelection(no_comparison=True, no_media=True),
    )
    assert report["comparisonTrace"] is None
    assert report["visualReplay"] is None


def test_capsule_replay_requires_explicit_media_and_refuses_bad_declared_type(
    tmp_path: Path,
) -> None:
    trace = tmp_path / "run.sova-trace"
    _trace(trace)
    manifest = capsule_manifest_template(
        title="Media selection", summary="Multiple recording fixture.", author="Tests"
    )
    capsule = tmp_path / "multiple-media.sova"
    build_capsule(
        capsule,
        manifest,
        traces=[trace],
        attachments={
            "first.webm": _synthetic_webm(),
            "second.webm": _synthetic_webm(duration_seconds=13),
        },
    )
    with pytest.raises(FormatError, match="multiple visual recordings"):
        render_capsule_timeline(capsule, tmp_path / "ambiguous-media.html")
    media_path = next(
        item.path
        for item in PackageReader(capsule).verify("sova.capsule")
        if item.role == "visual-replay"
    )
    report = render_capsule_timeline(
        capsule,
        tmp_path / "selected-media.html",
        selection=CapsuleReplaySelection(media_object=media_path),
    )
    assert report["visualReplay"] == media_path

    bad_capsule = tmp_path / "bad-declared-media.sova"
    writer = PackageWriter(manifest)
    writer.add_bytes(
        role="trace",
        path="traces/run.sova-trace",
        media_type="application/vnd.sova.trace+zip",
        data=trace.read_bytes(),
    )
    writer.add_bytes(
        role="visual-replay",
        path="blobs/sha256/bad-media",
        media_type="application/octet-stream",
        data=b"not declared as video",
    )
    writer.write(bad_capsule)
    with pytest.raises(FormatError, match="must declare video/webm or video/mp4"):
        render_capsule_timeline(bad_capsule, tmp_path / "bad-media.html")


def test_capsule_replay_rejects_ambiguous_and_mistyped_cue_indexes(tmp_path: Path) -> None:
    trace = tmp_path / "run.sova-trace"
    _trace(trace)
    manifest = capsule_manifest_template(
        title="Cue object policy", summary="Typed replay cue fixture.", author="Tests"
    )

    def writer_with_media() -> PackageWriter:
        writer = PackageWriter(manifest)
        writer.add_bytes(
            role="trace",
            path="traces/run.sova-trace",
            media_type="application/vnd.sova.trace+zip",
            data=trace.read_bytes(),
        )
        writer.add_bytes(
            role="visual-replay",
            path="evidence/session.webm",
            media_type="video/webm",
            data=_synthetic_webm(),
        )
        return writer

    ambiguous = tmp_path / "ambiguous-cues.sova"
    writer = writer_with_media()
    writer.add_bytes(
        role="replay-cues",
        path="evidence/first-replay-cues.json",
        media_type="application/json",
        data=b"{}",
    )
    writer.add_bytes(
        role="replay-cues",
        path="evidence/second-replay-cues.json",
        media_type="application/json",
        data=b"{}",
    )
    writer.write(ambiguous)
    with pytest.raises(FormatError, match="multiple replay cue indexes"):
        render_capsule_timeline(ambiguous, tmp_path / "ambiguous-cues.html")

    mistyped = tmp_path / "mistyped-cues.sova"
    writer = writer_with_media()
    writer.add_bytes(
        role="replay-cues",
        path="evidence/replay-cues.txt",
        media_type="text/plain",
        data=b"{}",
    )
    writer.write(mistyped)
    with pytest.raises(FormatError, match="must declare application/json"):
        render_capsule_timeline(mistyped, tmp_path / "mistyped-cues.html")


def test_replay_media_path_mp4_and_link_guards_are_deterministic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trace = tmp_path / "media-guards.sova-trace"
    _trace(trace)
    with pytest.raises(FormatError, match="regular file"):
        render_timeline_html(trace, tmp_path / "missing.html", media=tmp_path / "missing.webm")

    mp4 = tmp_path / "session.mp4"
    mp4.write_bytes(_synthetic_mp4())
    render_timeline_html(trace, tmp_path / "mp4.html", media=mp4)
    assert "data:video/mp4;base64" in (tmp_path / "mp4.html").read_text(encoding="utf-8")
    invalid_mp4 = tmp_path / "invalid.mp4"
    invalid_mp4.write_bytes(b"not an mp4")
    with pytest.raises(FormatError, match="ISO base signature"):
        render_timeline_html(trace, tmp_path / "invalid-mp4.html", media=invalid_mp4)

    linked = tmp_path / "forced-linked.webm"
    linked.write_bytes(b"\x1a\x45\xdf\xa3linked")
    original = type(linked).is_symlink

    def pretend_link(path: Path) -> bool:
        return path == linked or original(path)

    monkeypatch.setattr(type(linked), "is_symlink", pretend_link)
    with pytest.raises(FormatError, match="must not be a link"):
        render_timeline_html(trace, tmp_path / "forced-link.html", media=linked)


def test_replay_renderer_refuses_output_aliases_links_event_overflow_and_media_races(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.sova-trace"
    comparison = tmp_path / "comparison.sova-trace"
    _trace(source)
    _trace(comparison)

    with pytest.raises(FormatError, match="destination separate from every source trace"):
        render_timeline_html(source, source)
    with pytest.raises(FormatError, match="destination separate from every source trace"):
        render_timeline_html(source, comparison, comparison=comparison)

    destination = tmp_path / "linked-output.html"
    original_is_symlink = type(destination).is_symlink

    def pretend_output_link(path: Path) -> bool:
        return path == destination or original_is_symlink(path)

    with monkeypatch.context() as scoped:
        scoped.setattr(type(destination), "is_symlink", pretend_output_link)
        with pytest.raises(FormatError, match="must not be a symbolic link"):
            render_timeline_html(source, destination)

    with monkeypatch.context() as scoped:
        scoped.setattr(replay_render, "_MAX_RENDER_EVENTS", 1)
        with pytest.raises(FormatError, match="50,000-event"):
            render_timeline_html(source, tmp_path / "too-many-events.html")

    media = tmp_path / "changing.webm"
    payload = _synthetic_webm()
    media.write_bytes(payload)
    resolved_media = media.resolve()
    original_open = type(media).open

    def shortened_media(path: Path, *args: Any, **kwargs: Any) -> Any:
        if path == resolved_media:
            return io.BytesIO(payload[:-1])
        return original_open(path, *args, **kwargs)

    with monkeypatch.context() as scoped:
        scoped.setattr(type(media), "open", shortened_media)
        with pytest.raises(FormatError, match="changed during bounded rendering"):
            replay_render._reviewed_media(media)

    with monkeypatch.context() as scoped:
        scoped.setattr(replay_render, "_MAX_MEDIA_BYTES", len(payload) - 1)
        with pytest.raises(FormatError, match="128 MiB"):
            replay_render._reviewed_media(media)


def test_replay_cue_reader_rejects_missing_racing_and_malformed_indexes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    media_path = tmp_path / "session.webm"
    media_path.write_bytes(_synthetic_webm())
    media = replay_render._reviewed_media(media_path)
    assert media is not None
    cue_path = tmp_path / "replay-cues.json"
    cue_path.write_bytes(b"{}")

    with pytest.raises(FormatError, match="require reviewed visual media"):
        replay_render._reviewed_replay_cues(cue_path, None, {}, set())
    with pytest.raises(FormatError, match="regular non-link file"):
        replay_render._reviewed_replay_cues(tmp_path / "missing.json", media, {}, set())

    cue_path.write_bytes(b"")
    with pytest.raises(FormatError, match="256 KiB limit"):
        replay_render._reviewed_replay_cues(cue_path, media, {}, set())

    cue_path.write_bytes(b"{}")
    original_read_bytes = type(cue_path).read_bytes

    def shortened_index(path: Path) -> bytes:
        if path == cue_path:
            return b"{"
        return original_read_bytes(path)

    with monkeypatch.context() as scoped:
        scoped.setattr(type(cue_path), "read_bytes", shortened_index)
        with pytest.raises(FormatError, match="changed during bounded rendering"):
            replay_render._reviewed_replay_cues(cue_path, media, {}, set())

    cue_path.write_bytes(b"[]")
    with pytest.raises(FormatError, match="root must be an object"):
        replay_render._reviewed_replay_cues(cue_path, media, {}, set())

    base_document: dict[str, Any] = {
        "artifactType": "sova.replay-cues",
        "schemaVersion": "0.1.0",
        "mediaName": media_path.name,
        "mediaDigest": media["digest"],
        "synchronization": {
            "method": "same-host-monotonic-recorder-start-rpc-bound",
            "uncertaintyMs": "1.000",
            "frameTimestampAttested": False,
            "statement": "Fixture.",
        },
        "cues": [{}],
    }
    malformed_documents: tuple[dict[str, Any], ...] = (
        {},
        {**base_document, "synchronization": []},
        {
            **base_document,
            "synchronization": {
                **base_document["synchronization"],
                "uncertaintyMs": "not-canonical",
            },
        },
        base_document,
    )
    messages = (
        "unsupported replay cue document",
        "invalid cue synchronization metadata",
        "invalid cue synchronization bounds",
        "invalid decisive replay cue",
    )
    for document, message in zip(malformed_documents, messages, strict=True):
        cue_path.write_bytes(canonical_json_bytes(document))
        with pytest.raises(FormatError, match=message):
            replay_render._reviewed_replay_cues(cue_path, media, {}, set())


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
        ReplayServiceConfig(source, hold_seconds=2.0, poll_seconds=0.02)
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
