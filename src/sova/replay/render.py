# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: E501 - embedded HTML/JavaScript remains directly auditable
"""Inert, self-contained visual replay rendering."""

from __future__ import annotations

import base64
import html
import json
import math
import re
import struct
from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING, Any

from sova.formats import sha256_digest, strict_json_loads
from sova.formats.errors import FormatError
from sova.replay.model import ReplayMode
from sova.trace import TraceReader

if TYPE_CHECKING:
    from pathlib import Path

_MAX_RENDER_EVENTS = 50_000
_MAX_MEDIA_BYTES = 128 * 1024 * 1024
_MAX_REPLAY_CUES_BYTES = 256 * 1024
_MAX_REPLAY_CUES = 64
_MAX_CUE_UNCERTAINTY_MS = 60_000
_MAX_CUE_SECONDS = 86_400
_MIN_MP4_SIGNATURE_BYTES = 12
_MAX_EBML_VINT_BYTES = 8
_MAX_EBML_IDENTIFIER_BYTES = 4
_MAX_EBML_UNSIGNED_BYTES = 8
_EBML_FLOAT32_BYTES = 4
_EBML_FLOAT64_BYTES = 8
_EBML_HEADER_ID = 0x1A45DFA3
_EBML_SEGMENT_ID = 0x18538067
_EBML_INFO_ID = 0x1549A966
_EBML_TRACKS_ID = 0x1654AE6B
_EBML_CLUSTER_ID = 0x1F43B675
_EBML_TIMECODE_SCALE_ID = 0x2AD7B1
_EBML_DURATION_ID = 0x4489
_EBML_CLUSTER_TIMECODE_ID = 0xE7
_EBML_SIMPLE_BLOCK_ID = 0xA3
_EBML_BLOCK_GROUP_ID = 0xA0
_EBML_BLOCK_ID = 0xA1
_MP4_BOX_HEADER_BYTES = 8
_MP4_EXTENDED_BOX_HEADER_BYTES = 16
_MP4_MVHD_V0_BYTES = 20
_MP4_MVHD_V1_BYTES = 32
_CANONICAL_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)\.[0-9]+\Z")


def _ebml_vint(
    data: bytes,
    offset: int,
    *,
    identifier: bool,
) -> tuple[int | None, int] | None:
    """Read one bounded EBML identifier or size variable integer."""
    if offset >= len(data):
        return None
    first = data[offset]
    marker = 0x80
    length = 1
    while length <= _MAX_EBML_VINT_BYTES and not first & marker:
        marker >>= 1
        length += 1
    maximum = _MAX_EBML_IDENTIFIER_BYTES if identifier else _MAX_EBML_VINT_BYTES
    if marker == 0 or length > maximum or offset + length > len(data):
        return None
    value = first if identifier else first & (marker - 1)
    for byte in data[offset + 1 : offset + length]:
        value = (value << 8) | byte
    if not identifier and value == (1 << (7 * length)) - 1:
        return None, length
    return value, length


def _ebml_elements(
    data: bytes,
    start: int,
    stop: int,
) -> list[tuple[int, int, int]] | None:
    """Return the complete direct children of one bounded EBML master."""
    elements: list[tuple[int, int, int]] = []
    cursor = start
    while cursor < stop:
        identifier = _ebml_vint(data, cursor, identifier=True)
        if identifier is None:
            return None
        element_id, id_length = identifier
        if element_id is None:
            return None
        size = _ebml_vint(data, cursor + id_length, identifier=False)
        if size is None:
            return None
        payload_size, size_length = size
        payload_start = cursor + id_length + size_length
        payload_stop = stop if payload_size is None else payload_start + payload_size
        if payload_start > payload_stop or payload_stop > stop:
            return None
        elements.append((element_id, payload_start, payload_stop))
        if payload_stop <= cursor:
            return None
        cursor = payload_stop
    return elements if cursor == stop else None


def _webm_duration_seconds(data: bytes) -> float | None:  # noqa: PLR0911
    """Read a finalized WebM Segment/Info duration without a media dependency."""
    top = _ebml_elements(data, 0, len(data))
    if top is None or not top or top[0][0] != _EBML_HEADER_ID:
        return None
    segments = [item for item in top if item[0] == _EBML_SEGMENT_ID]
    if len(segments) != 1:
        return None
    segment_children = _ebml_elements(data, segments[0][1], segments[0][2])
    if segment_children is None:
        return None
    info_items = [item for item in segment_children if item[0] == _EBML_INFO_ID]
    if len(info_items) != 1:
        return None
    # A replay must contain actual track and cluster containers, not merely an
    # EBML signature and a forged duration scalar.
    if not any(item[0] == _EBML_TRACKS_ID for item in segment_children) or not any(
        item[0] == _EBML_CLUSTER_ID and item[2] > item[1] for item in segment_children
    ):
        return None
    info = _ebml_elements(data, info_items[0][1], info_items[0][2])
    if info is None:
        return None
    scale = 1_000_000
    duration: float | None = None
    for element_id, payload_start, payload_stop in info:
        payload = data[payload_start:payload_stop]
        if element_id == _EBML_TIMECODE_SCALE_ID and 1 <= len(payload) <= (
            _MAX_EBML_UNSIGNED_BYTES
        ):
            scale = int.from_bytes(payload, "big")
        elif element_id == _EBML_DURATION_ID and len(payload) in {
            _EBML_FLOAT32_BYTES,
            _EBML_FLOAT64_BYTES,
        }:
            duration = float(
                struct.unpack(">f" if len(payload) == _EBML_FLOAT32_BYTES else ">d", payload)[0]
            )
    if duration is None:
        final_timecode = _webm_final_timecode(data, segment_children)
        seconds = None if final_timecode is None else final_timecode * scale / 1_000_000_000
    else:
        seconds = duration * scale / 1_000_000_000
    if scale <= 0 or seconds is None or not math.isfinite(seconds) or seconds <= 0:
        return None
    return seconds


def _block_relative_timecode(payload: bytes) -> int | None:
    track = _ebml_vint(payload, 0, identifier=False)
    if track is None:
        return None
    _track_number, track_bytes = track
    if len(payload) < track_bytes + 2:
        return None
    return int.from_bytes(payload[track_bytes : track_bytes + 2], "big", signed=True)


def _webm_final_timecode(
    data: bytes,
    segment_children: list[tuple[int, int, int]],
) -> int | None:
    """Infer finalized duration from the last recorded block when Info omits it."""
    maximum: int | None = None
    for element_id, cluster_start, cluster_stop in segment_children:
        if element_id != _EBML_CLUSTER_ID:
            continue
        cluster = _ebml_elements(data, cluster_start, cluster_stop)
        if cluster is None:
            return None
        base = 0
        for child_id, payload_start, payload_stop in cluster:
            payload = data[payload_start:payload_stop]
            if child_id == _EBML_CLUSTER_TIMECODE_ID and 1 <= len(payload) <= (
                _MAX_EBML_UNSIGNED_BYTES
            ):
                base = int.from_bytes(payload, "big")
            elif child_id == _EBML_SIMPLE_BLOCK_ID:
                relative = _block_relative_timecode(payload)
                if relative is not None:
                    maximum = max(base + relative, maximum or 0)
            elif child_id == _EBML_BLOCK_GROUP_ID:
                group = _ebml_elements(data, payload_start, payload_stop)
                if group is None:
                    return None
                for group_id, block_start, block_stop in group:
                    if group_id != _EBML_BLOCK_ID:
                        continue
                    relative = _block_relative_timecode(data[block_start:block_stop])
                    if relative is not None:
                        maximum = max(base + relative, maximum or 0)
    return maximum if maximum is not None and maximum > 0 else None


def _mp4_boxes(data: bytes, start: int, stop: int) -> list[tuple[bytes, int, int]] | None:
    boxes: list[tuple[bytes, int, int]] = []
    cursor = start
    while cursor < stop:
        if stop - cursor < _MP4_BOX_HEADER_BYTES:
            return None
        size = int.from_bytes(data[cursor : cursor + 4], "big")
        box_type = data[cursor + 4 : cursor + 8]
        header = _MP4_BOX_HEADER_BYTES
        if size == 1:
            if stop - cursor < _MP4_EXTENDED_BOX_HEADER_BYTES:
                return None
            size = int.from_bytes(data[cursor + 8 : cursor + 16], "big")
            header = _MP4_EXTENDED_BOX_HEADER_BYTES
        elif size == 0:
            size = stop - cursor
        if size < header or cursor + size > stop:
            return None
        boxes.append((box_type, cursor + header, cursor + size))
        cursor += size
    return boxes if cursor == stop else None


def _mp4_duration_seconds(data: bytes) -> float | None:  # noqa: PLR0911
    top = _mp4_boxes(data, 0, len(data))
    if top is None or not any(item[0] == b"ftyp" for item in top):
        return None
    moov = [item for item in top if item[0] == b"moov"]
    if len(moov) != 1:
        return None
    children = _mp4_boxes(data, moov[0][1], moov[0][2])
    if children is None:
        return None
    mvhd = [item for item in children if item[0] == b"mvhd"]
    if len(mvhd) != 1:
        return None
    payload = data[mvhd[0][1] : mvhd[0][2]]
    if len(payload) < _MP4_MVHD_V0_BYTES:
        return None
    version = payload[0]
    if version == 0 and len(payload) >= _MP4_MVHD_V0_BYTES:
        timescale = int.from_bytes(payload[12:16], "big")
        duration = int.from_bytes(payload[16:20], "big")
    elif version == 1 and len(payload) >= _MP4_MVHD_V1_BYTES:
        timescale = int.from_bytes(payload[20:24], "big")
        duration = int.from_bytes(payload[24:32], "big")
    else:
        return None
    if timescale <= 0 or duration <= 0:
        return None
    seconds = duration / timescale
    return seconds if math.isfinite(seconds) and seconds > 0 else None


def _reviewed_media(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    if path.is_symlink():
        raise FormatError("SOVA-REPLAY-MEDIA-PATH", "replay media must not be a link")
    resolved = path.resolve()
    if not resolved.is_file():
        raise FormatError("SOVA-REPLAY-MEDIA-PATH", "replay media must be a regular file")
    media_type = {".webm": "video/webm", ".mp4": "video/mp4"}.get(resolved.suffix.casefold())
    if media_type is None:
        raise FormatError("SOVA-REPLAY-MEDIA-TYPE", "replay media must be WebM or MP4")
    size = resolved.stat().st_size
    if size <= 0 or size > _MAX_MEDIA_BYTES:
        raise FormatError(
            "SOVA-REPLAY-MEDIA-LIMIT",
            "replay media is empty or exceeds the 128 MiB local renderer budget",
        )
    with resolved.open("rb") as handle:
        data = handle.read(_MAX_MEDIA_BYTES + 1)
    if len(data) != size or len(data) > _MAX_MEDIA_BYTES:
        raise FormatError(
            "SOVA-REPLAY-MEDIA-LIMIT",
            "replay media changed during bounded rendering",
        )
    if media_type == "video/webm" and not data.startswith(b"\x1a\x45\xdf\xa3"):
        raise FormatError("SOVA-REPLAY-MEDIA-TYPE", "WebM media has no EBML signature")
    if media_type == "video/mp4" and (len(data) < _MIN_MP4_SIGNATURE_BYTES or data[4:8] != b"ftyp"):
        raise FormatError("SOVA-REPLAY-MEDIA-TYPE", "MP4 media has no ISO base signature")
    duration = (
        _webm_duration_seconds(data) if media_type == "video/webm" else _mp4_duration_seconds(data)
    )
    return {
        "name": resolved.name,
        "mediaType": media_type,
        "digest": sha256_digest(data),
        "dataUrl": f"data:{media_type};base64,{base64.b64encode(data).decode('ascii')}",
        "durationSeconds": None if duration is None else f"{duration:.6f}",
        "synchronization": "session-level-recording-not-event-time-attested",
    }


def _bounded_number(value: Any, maximum: int) -> bool:
    if not isinstance(value, str) or _CANONICAL_DECIMAL.fullmatch(value) is None:
        return False
    try:
        decimal = Decimal(value)
    except InvalidOperation:
        return False
    return decimal.is_finite() and Decimal(0) <= decimal <= Decimal(maximum)


def _reviewed_replay_cues(  # noqa: PLR0912, PLR0915 - fail-closed validation
    path: Path | None,
    media: dict[str, Any] | None,
    event_index: dict[str, dict[str, Any]],
    primary_event_ids: set[str],
) -> dict[str, Any] | None:
    if path is None:
        return None
    if media is None:
        raise FormatError("SOVA-REPLAY-CUES-MEDIA", "replay cues require reviewed visual media")
    if path.is_symlink() or not path.resolve().is_file():
        raise FormatError("SOVA-REPLAY-CUES-PATH", "replay cues must be a regular non-link file")
    size = path.stat().st_size
    if size <= 0 or size > _MAX_REPLAY_CUES_BYTES:
        raise FormatError("SOVA-REPLAY-CUES-LIMIT", "replay cues exceed the 256 KiB limit")
    raw = path.read_bytes()
    if len(raw) != size or len(raw) > _MAX_REPLAY_CUES_BYTES:
        raise FormatError(
            "SOVA-REPLAY-CUES-LIMIT",
            "replay cues changed during bounded rendering",
        )
    value = strict_json_loads(raw)
    if not isinstance(value, dict):
        raise FormatError("SOVA-REPLAY-CUES-FORMAT", "replay cue root must be an object")
    required = {
        "artifactType",
        "schemaVersion",
        "mediaName",
        "mediaDigest",
        "synchronization",
        "cues",
    }
    if (
        set(value) != required
        or value.get("artifactType") != "sova.replay-cues"
        or value.get("schemaVersion") != "0.1.0"
    ):
        raise FormatError("SOVA-REPLAY-CUES-FORMAT", "unsupported replay cue document")
    if value.get("mediaDigest") != media["digest"]:
        raise FormatError(
            "SOVA-REPLAY-CUES-MEDIA",
            "replay cues are not bound to the selected visual recording",
        )
    synchronization = value.get("synchronization")
    if not isinstance(synchronization, dict) or set(synchronization) != {
        "method",
        "uncertaintyMs",
        "frameTimestampAttested",
        "statement",
    }:
        raise FormatError("SOVA-REPLAY-CUES-FORMAT", "invalid cue synchronization metadata")
    uncertainty = synchronization.get("uncertaintyMs")
    if (
        not _bounded_number(uncertainty, _MAX_CUE_UNCERTAINTY_MS)
        or synchronization.get("method") != "same-host-monotonic-recorder-start-rpc-bound"
        or synchronization.get("frameTimestampAttested") is not False
        or not isinstance(synchronization.get("statement"), str)
    ):
        raise FormatError("SOVA-REPLAY-CUES-FORMAT", "invalid cue synchronization bounds")
    cues = value.get("cues")
    if not isinstance(cues, list) or not 1 <= len(cues) <= _MAX_REPLAY_CUES:
        raise FormatError("SOVA-REPLAY-CUES-LIMIT", "replay cue count is invalid")
    reviewed: list[dict[str, Any]] = []
    cue_ids: set[str] = set()
    cue_fields = {
        "id",
        "label",
        "channel",
        "eventId",
        "eventKind",
        "eventSequence",
        "oracleStatus",
        "offsetSeconds",
        "chapterOffsetSeconds",
        "preRollSeconds",
        "postRollSeconds",
    }
    for cue in cues:
        if not isinstance(cue, dict) or set(cue) != cue_fields:
            raise FormatError("SOVA-REPLAY-CUES-FORMAT", "invalid decisive replay cue")
        event_id = cue.get("eventId")
        numeric = (
            cue.get("offsetSeconds"),
            cue.get("chapterOffsetSeconds"),
            cue.get("preRollSeconds"),
            cue.get("postRollSeconds"),
        )
        cue_id = cue.get("id")
        event_sequence = cue.get("eventSequence")
        recorded_event = event_index.get(event_id) if isinstance(event_id, str) else None
        recorded_payload = (
            recorded_event.get("payload") if isinstance(recorded_event, dict) else None
        )
        media_duration_raw = media.get("durationSeconds")
        media_duration = (
            Decimal(media_duration_raw)
            if isinstance(media_duration_raw, str)
            and _bounded_number(media_duration_raw, _MAX_CUE_SECONDS)
            else None
        )
        cue_offset = (
            Decimal(str(cue.get("offsetSeconds")))
            if _bounded_number(cue.get("offsetSeconds"), _MAX_CUE_SECONDS)
            else None
        )
        chapter_offset = (
            Decimal(str(cue.get("chapterOffsetSeconds")))
            if _bounded_number(cue.get("chapterOffsetSeconds"), _MAX_CUE_SECONDS)
            else None
        )
        if (
            not isinstance(cue_id, str)
            or not cue_id
            or cue_id in cue_ids
            or not isinstance(event_id, str)
            or recorded_event is None
            or cue.get("eventKind") != "oracle.completed"
            or cue.get("oracleStatus") != "pass"
            or not all(_bounded_number(item, _MAX_CUE_SECONDS) for item in numeric)
            or not all(
                isinstance(cue.get(key), str) and cue.get(key) for key in ("label", "channel")
            )
            or isinstance(event_sequence, bool)
            or not isinstance(event_sequence, int)
            or event_sequence < 0
            or recorded_event.get("kind") != "oracle.completed"
            or recorded_event.get("sequence") != event_sequence
            or not isinstance(recorded_payload, dict)
            or recorded_payload.get("status") != "pass"
        ):
            raise FormatError("SOVA-REPLAY-CUES-FORMAT", "invalid decisive replay cue values")
        if media_duration is not None and (
            cue_offset is None
            or chapter_offset is None
            or cue_offset >= media_duration
            or chapter_offset >= media_duration
        ):
            raise FormatError(
                "SOVA-REPLAY-CUES-DURATION",
                "decisive replay cue falls outside the finalized media duration",
            )
        cue_ids.add(cue_id)
        reviewed.append(dict(cue))
    default_cue = next(
        (cue for cue in reviewed if cue["eventId"] in primary_event_ids),
        reviewed[0],
    )
    duration_bound = media_duration is not None
    return {
        "synchronization": dict(synchronization),
        "cues": reviewed,
        "defaultCueId": default_cue["id"],
        "defaultCueSource": (
            "primary" if default_cue["eventId"] in primary_event_ids else "comparison"
        ),
        "durationBound": duration_bound,
    }


def _safe_json(value: Any) -> str:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def replay_document(payload: dict[str, Any]) -> str:
    """Return the dependency-free replay application for already verified data.

    Recorded values are embedded as escaped JSON and are inserted into the DOM
    only through ``textContent`` or safe element properties. Nothing from a
    trace is interpreted as HTML or executable code.
    """
    title = html.escape(str(payload["source"]))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src 'self' data:; media-src 'self' data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'">
<meta name="referrer" content="no-referrer"><title>SOVA Replay — {title}</title><style>
:root{{--ink:#eaf2f8;--muted:#89a1b5;--panel:#0b1724;--line:#1d3448;--cyan:#5ce1e6;--amber:#ffc66d;--red:#ff7b86;--green:#66dda5;--bg:#050b12;color-scheme:dark;background:var(--bg);color:var(--ink);font:14px/1.45 Inter,ui-sans-serif,system-ui,sans-serif}}
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(circle at 20% -10%,#12314a 0,transparent 36rem),var(--bg)}}button,input,select{{font:inherit}}button,select,input[type=search]{{color:var(--ink);background:#0d2030;border:1px solid #29485f;border-radius:8px}}button{{padding:.55rem .8rem;cursor:pointer}}button:hover,button:focus-visible{{border-color:var(--cyan);outline:none}}button.active{{background:#155167;border-color:var(--cyan)}}
header{{position:sticky;top:0;z-index:9;display:flex;justify-content:space-between;gap:1rem;align-items:center;padding:1rem 1.4rem;background:rgba(5,11,18,.92);border-bottom:1px solid var(--line);backdrop-filter:blur(14px)}}.brand{{display:flex;gap:.75rem;align-items:center}}.mark{{display:grid;place-items:center;width:38px;height:38px;border:1px solid var(--cyan);border-radius:50%;color:var(--cyan);font-weight:800}}h1{{font-size:1rem;letter-spacing:.16em;margin:0}}.sub{{color:var(--muted);font-size:.78rem}}.status{{display:flex;gap:.55rem;align-items:center}}.dot{{width:8px;height:8px;border-radius:50%;background:var(--amber);box-shadow:0 0 12px currentColor}}.dot.sealed{{background:var(--green)}}
main{{max-width:1500px;margin:auto;padding:1.2rem}}.warning{{padding:.7rem 1rem;border:1px solid #5c4927;background:#211a0e;color:var(--amber);border-radius:10px}}.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:.75rem;margin:1rem 0}}.metric{{background:linear-gradient(145deg,#0d1b29,#09131e);border:1px solid var(--line);border-radius:12px;padding:.8rem 1rem}}.metric b{{display:block;font-size:1.15rem}}.metric span{{color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.09em}}
.visual{{margin:1rem 0;padding:1rem;background:var(--panel);border:1px solid var(--line);border-radius:12px}}.visual-head{{display:flex;justify-content:space-between;gap:1rem;align-items:center;margin-bottom:.7rem}}.visual video{{display:block;width:100%;max-height:66vh;background:#000;border-radius:9px}}.visual-note{{color:var(--amber);font-size:.78rem}}
.controls{{display:grid;grid-template-columns:auto auto minmax(180px,1fr) auto minmax(180px,320px);gap:.65rem;align-items:center;padding:1rem;background:var(--panel);border:1px solid var(--line);border-radius:12px}}#scrub{{width:100%;accent-color:var(--cyan)}}select{{padding:.5rem}}input[type=search]{{padding:.55rem .7rem;width:100%}}.filters{{display:flex;gap:.45rem;flex-wrap:wrap;margin:.8rem 0}}.filters button{{padding:.35rem .65rem;font-size:.78rem}}
.workspace{{display:grid;grid-template-columns:minmax(0,2.1fr) minmax(300px,.9fr);gap:1rem}}.tracks,.detail{{background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}}.tracks-head,.detail-head{{display:flex;justify-content:space-between;align-items:center;padding:.75rem 1rem;border-bottom:1px solid var(--line)}}.tracks-body{{max-height:62vh;overflow:auto}}.lane{{display:grid;grid-template-columns:150px minmax(600px,1fr);min-height:50px;border-bottom:1px solid #122638}}.lane-label{{position:sticky;left:0;z-index:2;display:flex;align-items:center;padding:.6rem .8rem;color:var(--muted);background:#091522;border-right:1px solid var(--line);overflow-wrap:anywhere}}.rail{{position:relative;margin:.55rem .8rem;background:linear-gradient(90deg,#102236,#173149);height:30px;border-radius:7px;min-width:560px}}.event-dot{{position:absolute;top:7px;translate:-50% 0;width:15px;height:15px;padding:0;border:2px solid #07111b;border-radius:50%;background:var(--cyan);box-shadow:0 0 0 1px #4a899b}}.event-dot.selected{{background:white;box-shadow:0 0 0 3px var(--cyan)}}.event-dot.redacted{{background:var(--amber)}}.event-dot.error{{background:var(--red)}}.event-dot.decisive{{background:var(--green);box-shadow:0 0 0 3px rgba(102,221,165,.32)}}
.breakpoint{{display:grid;grid-template-columns:1fr auto;gap:1rem;align-items:center;margin:1rem 0;padding:1rem 1.1rem;border:1px solid #2b8665;border-radius:12px;background:linear-gradient(100deg,rgba(31,105,77,.32),rgba(11,23,36,.92))}}.breakpoint h2{{margin:.15rem 0;color:var(--green)}}.breakpoint .cue-data{{color:var(--muted);overflow-wrap:anywhere}}.breakpoint button{{border-color:#3db884;background:#123c31}}
.detail-body{{padding:1rem;max-height:62vh;overflow:auto}}.kicker{{color:var(--cyan);font-size:.75rem;letter-spacing:.12em;text-transform:uppercase}}h2{{font-size:1.15rem;margin:.35rem 0}}.meta{{color:var(--muted);overflow-wrap:anywhere}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#07111b;border:1px solid #172d40;padding:.85rem;border-radius:9px;max-height:280px;overflow:auto}}.links{{display:flex;gap:.4rem;flex-wrap:wrap}}.links button{{font-size:.72rem;padding:.28rem .5rem}}.comparison{{margin-top:1rem;padding-top:1rem;border-top:1px solid var(--line)}}.empty{{padding:2rem;color:var(--muted)}}
@media(max-width:900px){{.controls{{grid-template-columns:auto auto 1fr}}.controls input[type=search]{{grid-column:1/-1}}.workspace{{grid-template-columns:1fr}}.lane{{grid-template-columns:105px minmax(480px,1fr)}}header{{position:static}}}}
@media(prefers-reduced-motion:reduce){{*{{scroll-behavior:auto!important;transition:none!important}}}}
</style></head><body>
<header><div class="brand"><div class="mark" aria-hidden="true">S</div><div><h1>SOVA REPLAY</h1><div class="sub">observable evidence navigator</div></div></div><div class="status"><span class="dot" id="statusDot"></span><span id="statusText">loading</span></div></header>
<main><p class="warning">Inert playback only. Recorded actions, payloads, links, and tools are never executed by this page.</p>
<section class="metrics" aria-label="Trace summary"><div class="metric"><b id="eventCount">0</b><span>events</span></div><div class="metric"><b id="laneCount">0</b><span>sensor lanes</span></div><div class="metric"><b id="actorCount">0</b><span>actors</span></div><div class="metric"><b id="redactionCount">0</b><span>redactions</span></div><div class="metric"><b id="duration">0</b><span>observed span</span></div></section>
<section class="breakpoint" id="breakpoint" hidden><div><div class="kicker">Decisive evidence</div><h2 id="cueLabel">Exploit confirmed</h2><div class="cue-data" id="cueData"></div></div><button id="playDecisive" type="button">▶ Play decisive moment</button></section>
<section class="visual" id="visual" hidden><div class="visual-head"><div><b>Recorded browser session</b><div class="sub" id="mediaMeta"></div></div><span class="visual-note" id="mediaNote">Session-level visual evidence; event-time synchronization is not attested.</span></div><video id="sessionVideo" controls preload="metadata"></video></section>
<section class="controls" aria-label="Playback controls"><button id="play" type="button">▶ Play</button><select id="speed" aria-label="Playback speed"><option value="0.5">0.5x</option><option value="1" selected>1x</option><option value="2">2x</option><option value="4">4x</option><option value="8">8x</option></select><input id="scrub" type="range" min="0" value="0" aria-label="Event position"><output id="position">0 / 0</output><input id="search" type="search" maxlength="128" placeholder="Filter kind, actor, phase, target…" aria-label="Search events"></section>
<div class="filters" id="filters" aria-label="Sensor family filters"></div>
<section class="workspace"><div class="tracks"><div class="tracks-head"><b>Sensor lanes</b><span class="sub" id="sourceMeta"></span></div><div class="tracks-body" id="lanes"></div></div>
<aside class="detail"><div class="detail-head"><b>Evidence detail</b><span class="sub" id="sequence"></span></div><div class="detail-body" id="detail"><p class="empty">Select an event.</p></div></aside></section>
</main><script type="application/json" id="sova-data">{_safe_json(payload)}</script><script>
'use strict';
const data=JSON.parse(document.getElementById('sova-data').textContent);let events=[...data.events],comparison=[...data.comparisonEvents],visible=[],selectedFamily='all',selectedIndex=0,timer=null,activeCue=null,cueStop=null;
const byId=new Map();const scrub=document.getElementById('scrub');const play=document.getElementById('play');const search=document.getElementById('search');
function text(node,value){{document.getElementById(node).textContent=String(value)}}
function family(e){{return e.kind.split('.')[0]}}
function time(e){{return Number(e.monotonicNs)||e.sequence}}
function range(source){{if(!source.length)return [0,1];let lo=Infinity,hi=-Infinity;source.forEach(e=>{{const value=time(e);lo=Math.min(lo,value);hi=Math.max(hi,value)}});return [lo,hi===lo?lo+1:hi]}}
function pct(e,source){{const [lo,hi]=range(source);return Math.max(0,Math.min(100,(time(e)-lo)*100/(hi-lo)))}}
function duration(){{const [lo,hi]=range(events);const ns=hi-lo;return ns>1e9?(ns/1e9).toFixed(2)+' s':ns>1e6?(ns/1e6).toFixed(2)+' ms':ns+' ns'}}
function matches(e){{const q=search.value.trim().toLowerCase();return (selectedFamily==='all'||family(e)===selectedFamily)&&(!q||[e.kind,e.phase,e.actor.name,e.actor.id,e.target.name,e.target.id].some(v=>String(v).toLowerCase().includes(q)))}}
function families(){{return ['all',...new Set(events.map(family))]}}
function selectEvent(event){{const index=visible.findIndex(e=>e.id===event.id);if(index>=0){{selectedIndex=index;scrub.value=String(index);draw()}}}}
function linkButton(id){{const b=document.createElement('button');b.type='button';b.textContent=id;b.onclick=()=>{{const e=byId.get(id);if(e){{selectedFamily='all';search.value='';drawFilters();apply();selectEvent(e)}}}};return b}}
function detailBlock(event,label){{const wrap=document.createElement('section');const kick=document.createElement('div');kick.className='kicker';kick.textContent=label;const h=document.createElement('h2');h.textContent=event.kind;const meta=document.createElement('p');meta.className='meta';meta.textContent=`${{event.wallTime}} · ${{event.actor.name}} → ${{event.target.name}} · ${{event.phase}}`;const pre=document.createElement('pre');pre.textContent=JSON.stringify(event.payload,null,2);wrap.append(kick,h,meta,pre);const relations=[...(event.parents||[]),...(event.links||[]).map(x=>x.eventId).filter(Boolean)];if(relations.length){{const title=document.createElement('p');title.className='kicker';title.textContent='Recorded causal / correlation links';const links=document.createElement('div');links.className='links';relations.forEach(id=>links.appendChild(linkButton(id)));wrap.append(title,links)}}return wrap}}
function nearest(event){{if(!comparison.length)return null;const [alo,ahi]=range(events),[blo,bhi]=range(comparison),fraction=(time(event)-alo)/(ahi-alo);const target=blo+fraction*(bhi-blo);return comparison.reduce((best,item)=>Math.abs(time(item)-target)<Math.abs(time(best)-target)?item:best)}}
function drawDetail(event){{const box=document.getElementById('detail');box.replaceChildren();if(!event){{const p=document.createElement('p');p.className='empty';p.textContent='No event matches the active filters.';box.appendChild(p);return}}box.appendChild(detailBlock(event,'Original evidence'));const other=nearest(event);if(other){{const section=detailBlock(other,'Synchronized comparison');section.className='comparison';box.appendChild(section)}}}}
function drawLanes(){{const box=document.getElementById('lanes');box.replaceChildren();const groups=new Map();const decisive=new Set((data.replayCues?.cues||[]).map(c=>c.eventId));visible.forEach(e=>{{const key=family(e);if(!groups.has(key))groups.set(key,[]);groups.get(key).push(e)}});for(const [name,items] of groups){{const lane=document.createElement('div');lane.className='lane';const label=document.createElement('div');label.className='lane-label';label.textContent=`${{name}} · ${{items.length}}`;const rail=document.createElement('div');rail.className='rail';items.forEach(e=>{{const b=document.createElement('button');b.type='button';b.className='event-dot'+((e.redactions||[]).length?' redacted':'')+(e.kind.startsWith('error.')?' error':'')+(decisive.has(e.id)?' decisive':'');b.style.left=pct(e,events)+'%';b.title=`${{e.sequence}} ${{e.kind}}`;b.setAttribute('aria-label',b.title);b.dataset.eventId=e.id;b.onclick=()=>selectEvent(e);rail.appendChild(b)}});lane.append(label,rail);box.appendChild(lane)}}text('laneCount',groups.size)}}
function updateSelection(){{document.querySelectorAll('.event-dot.selected').forEach(n=>n.classList.remove('selected'));const e=visible[selectedIndex];if(e){{const node=document.querySelector(`[data-event-id="${{CSS.escape(e.id)}}"]`);if(node)node.classList.add('selected')}}}}
function draw(){{if(selectedIndex>=visible.length)selectedIndex=Math.max(0,visible.length-1);const e=visible[selectedIndex];scrub.max=String(Math.max(0,visible.length-1));scrub.value=String(selectedIndex);text('position',visible.length?`${{selectedIndex+1}} / ${{visible.length}}`:'0 / 0');text('sequence',e?`sequence ${{e.sequence}}`:'');drawDetail(e);updateSelection()}}
function apply(){{visible=events.filter(matches);selectedIndex=0;drawLanes();draw()}}
function drawFilters(){{const box=document.getElementById('filters');box.replaceChildren();families().forEach(name=>{{const b=document.createElement('button');b.type='button';b.textContent=name;b.className=name===selectedFamily?'active':'';b.onclick=()=>{{selectedFamily=name;drawFilters();apply()}};box.appendChild(b)}})}}
function summary(){{events.forEach(e=>byId.set(e.id,e));comparison.forEach(e=>byId.set(e.id,e));text('eventCount',events.length);text('actorCount',new Set(events.map(e=>e.actor.id)).size);text('redactionCount',events.reduce((n,e)=>n+(e.redactions||[]).length,0));text('duration',duration());text('sourceMeta',`${{data.source}}${{data.comparison?' ↔ '+data.comparison:''}}`);const sealed=data.completion==='sealed';document.getElementById('statusDot').classList.toggle('sealed',sealed);text('statusText',sealed?'integrity-checked sealed trace':data.liveEndpoint?'live unsealed tail':'integrity-checked playback')}}
function cueById(id){{return (data.replayCues?.cues||[]).find(c=>c.id===id)||null}}
function showComparisonCue(event){{const box=document.getElementById('detail');box.replaceChildren();box.appendChild(detailBlock(event,'Decisive comparison evidence'));text('sequence',`comparison sequence ${{event.sequence}}`)}}
function showCue(cue){{if(!cue)return;activeCue=cue;const breakpoint=document.getElementById('breakpoint');breakpoint.hidden=false;breakpoint.dataset.cueId=cue.id;breakpoint.dataset.cueSource=data.replayCues.defaultCueSource;text('cueLabel',cue.label);const sync=data.replayCues.synchronization;text('cueData',`${{cue.channel}} · trace sequence ${{cue.eventSequence}} · oracle ${{cue.oracleStatus}} · video ${{Number(cue.offsetSeconds).toFixed(3)}}s ± ${{Number(sync.uncertaintyMs).toFixed(3)}}ms`);selectedFamily='all';search.value='';drawFilters();apply();const event=byId.get(cue.eventId);if(event){{if(events.some(item=>item.id===event.id))selectEvent(event);else showComparisonCue(event)}}}}
function seekCue(cue,playWindow){{if(!cue||!data.media)return;const video=document.getElementById('sessionVideo');const start=Math.max(0,Number(cue.offsetSeconds)-Number(cue.preRollSeconds));const declaredDuration=Number(data.media.durationSeconds);const requestedStop=Number(cue.offsetSeconds)+Number(cue.postRollSeconds);const stopAt=Number.isFinite(declaredDuration)&&declaredDuration>0?Math.min(declaredDuration,requestedStop):requestedStop;const finish=()=>{{video.pause();video.dataset.decisiveState='complete';if(cueStop){{video.removeEventListener('timeupdate',cueStop);video.removeEventListener('ended',finish);cueStop=null}}}};const seek=()=>{{video.currentTime=Math.min(start,Number.isFinite(video.duration)?Math.max(0,video.duration-.05):start);video.dataset.decisiveStart=String(start);video.dataset.decisiveStop=String(stopAt);video.dataset.decisiveState='ready';if(playWindow){{cueStop=()=>{{if(video.currentTime>=stopAt)finish()}};video.addEventListener('timeupdate',cueStop);video.addEventListener('ended',finish);video.play().then(()=>{{video.dataset.decisiveState='playing'}}).catch(()=>{{video.dataset.decisiveState='blocked'}})}}}};if(video.readyState>=1)seek();else video.addEventListener('loadedmetadata',seek,{{once:true}});showCue(cue)}}
function focusDefaultCue(){{const cue=cueById(data.replayCues?.defaultCueId);if(cue)seekCue(cue,false)}}
function loadMedia(){{if(!data.media)return;const panel=document.getElementById('visual');const video=document.getElementById('sessionVideo');panel.hidden=false;video.src=data.media.dataUrl;text('mediaMeta',`${{data.media.name}} · ${{data.media.digest}}${{data.media.durationSeconds?' · '+data.media.durationSeconds+' s':''}}`);if(data.replayCues){{const sync=data.replayCues.synchronization;text('mediaNote',data.replayCues.durationBound?`Oracle-synchronized, duration-bounded cue · ${{sync.method}} · ± ${{Number(sync.uncertaintyMs).toFixed(3)}} ms; frame timestamps are not cryptographically attested.`:'Cue indexed, but finalized media duration is unavailable; exact-open status is withheld.')}}}}
function stop(){{if(timer)clearInterval(timer);timer=null;play.textContent='▶ Play'}}
function start(){{stop();play.textContent='❚❚ Pause';const speed=Number(document.getElementById('speed').value);timer=setInterval(()=>{{if(selectedIndex>=visible.length-1){{stop();return}}selectedIndex+=1;draw()}},Math.max(45,650/speed))}}
play.onclick=()=>timer?stop():start();scrub.oninput=()=>{{stop();selectedIndex=Number(scrub.value);draw()}};search.oninput=apply;document.getElementById('speed').onchange=()=>{{if(timer)start()}};document.getElementById('playDecisive').onclick=()=>{{if(activeCue)seekCue(activeCue,true)}};
function addLive(raw){{if(!raw||byId.has(raw.id))return;events.push(raw);events.sort((a,b)=>a.sequence-b.sequence);summary();drawFilters();apply()}}
if(data.liveEndpoint){{const stream=new EventSource(data.liveEndpoint);stream.addEventListener('trace-event',e=>{{try{{addLive(JSON.parse(e.data))}}catch(_error){{text('statusText','invalid live event refused')}}}});stream.addEventListener('sealed',()=>{{data.completion='sealed';summary();stream.close()}});stream.onerror=()=>{{if(data.completion!=='sealed')text('statusText','live tail reconnecting')}}}}
summary();loadMedia();drawFilters();apply();focusDefaultCue();
</script></body></html>"""


def render_timeline_html(  # noqa: PLR0913 - evidence choices remain explicit
    source: Path,
    destination: Path,
    *,
    comparison: Path | None = None,
    counterfactual: str | None = None,
    media: Path | None = None,
    replay_cues: Path | None = None,
) -> dict[str, Any]:
    """Write a rich offline replay application that never executes trace payloads."""
    source_paths = {source.resolve()}
    if comparison is not None:
        source_paths.add(comparison.resolve())
    if destination.resolve() in source_paths:
        raise FormatError(
            "SOVA-REPLAY-IMMUTABLE-SOURCE",
            "visual playback requires a destination separate from every source trace",
        )
    if destination.is_symlink():
        raise FormatError(
            "SOVA-REPLAY-DESTINATION",
            "visual replay destination must not be a symbolic link",
        )
    primary = TraceReader(source)
    primary.verify()
    events = primary.events()
    secondary_events: list[dict[str, Any]] = []
    if comparison is not None:
        secondary = TraceReader(comparison)
        secondary.verify()
        secondary_events = secondary.events()
    if len(events) + len(secondary_events) > _MAX_RENDER_EVENTS:
        raise FormatError(
            "SOVA-REPLAY-RENDER-LIMIT",
            "visual replay exceeds the bounded 50,000-event local renderer",
        )
    reviewed_media = _reviewed_media(media)
    all_events = [*events, *secondary_events]
    event_index: dict[str, dict[str, Any]] = {}
    for event in all_events:
        event_id = event.get("id")
        if not isinstance(event_id, str):
            continue
        existing = event_index.get(event_id)
        if existing is not None and existing != event:
            raise FormatError(
                "SOVA-REPLAY-CUES-EVENT",
                "replay traces contain an ambiguous duplicate event identifier",
            )
        event_index[event_id] = event
    primary_event_ids = {
        str(event.get("id")) for event in events if isinstance(event.get("id"), str)
    }
    reviewed_cues = _reviewed_replay_cues(
        replay_cues,
        reviewed_media,
        event_index,
        primary_event_ids,
    )
    if reviewed_media is not None and reviewed_cues is not None:
        reviewed_media["synchronization"] = reviewed_cues["synchronization"]["method"]
    payload = {
        "mode": ReplayMode.PLAYBACK.value,
        "source": source.name,
        "comparison": None if comparison is None else comparison.name,
        "counterfactual": counterfactual,
        "events": events,
        "comparisonEvents": secondary_events,
        "completion": "sealed",
        "liveEndpoint": None,
        "warning": "Inert playback only. No recorded action is executed.",
        "media": reviewed_media,
        "replayCues": reviewed_cues,
    }
    destination.write_text(replay_document(payload), encoding="utf-8", newline="\n")
    default_cue = None
    if reviewed_cues is not None:
        default_cue = next(
            cue for cue in reviewed_cues["cues"] if cue["id"] == reviewed_cues["defaultCueId"]
        )
    duration_bound = bool(reviewed_cues is not None and reviewed_cues["durationBound"])
    return {
        "artifactType": "sova.timeline-replay",
        "schemaVersion": "0.1.0",
        "destination": str(destination.resolve()),
        "visualReplay": None if reviewed_media is None else reviewed_media["name"],
        "mediaDurationSeconds": (
            None if reviewed_media is None else reviewed_media["durationSeconds"]
        ),
        "decisiveCue": default_cue,
        "decisiveCueSource": (None if reviewed_cues is None else reviewed_cues["defaultCueSource"]),
        "decisiveCueDurationBound": duration_bound,
        "opensAtDecisiveMoment": bool(default_cue is not None and duration_bound),
        "executesRecordedActions": False,
    }


__all__ = ["render_timeline_html", "replay_document"]
