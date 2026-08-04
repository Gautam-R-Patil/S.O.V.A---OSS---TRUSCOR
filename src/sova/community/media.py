# SPDX-License-Identifier: Apache-2.0
"""Dependency-free, redaction-first Y4M replay clip rendering."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.trace.redaction import Redactor

if TYPE_CHECKING:
    from pathlib import Path

_WIDTH = 320
_HEIGHT = 180
_FPS = 5
_MAX_EVENTS = 12
_REPEAT_FRAMES = 5
_SAFE_TEXT = re.compile(r"[^A-Z0-9 .:/_-]+")

# Five-by-seven bitmap font. Unknown glyphs are rendered as boxes, never silently omitted.
_FONT_ROWS = {
    "A": ("01110", "10001", "10001", "11111", "10001", "10001", "10001"),
    "B": ("11110", "10001", "10001", "11110", "10001", "10001", "11110"),
    "C": ("01111", "10000", "10000", "10000", "10000", "10000", "01111"),
    "D": ("11110", "10001", "10001", "10001", "10001", "10001", "11110"),
    "E": ("11111", "10000", "10000", "11110", "10000", "10000", "11111"),
    "F": ("11111", "10000", "10000", "11110", "10000", "10000", "10000"),
    "G": ("01111", "10000", "10000", "10111", "10001", "10001", "01111"),
    "H": ("10001", "10001", "10001", "11111", "10001", "10001", "10001"),
    "I": ("11111", "00100", "00100", "00100", "00100", "00100", "11111"),
    "J": ("00111", "00010", "00010", "00010", "10010", "10010", "01100"),
    "K": ("10001", "10010", "10100", "11000", "10100", "10010", "10001"),
    "L": ("10000", "10000", "10000", "10000", "10000", "10000", "11111"),
    "M": ("10001", "11011", "10101", "10101", "10001", "10001", "10001"),
    "N": ("10001", "11001", "10101", "10011", "10001", "10001", "10001"),
    "O": ("01110", "10001", "10001", "10001", "10001", "10001", "01110"),
    "P": ("11110", "10001", "10001", "11110", "10000", "10000", "10000"),
    "Q": ("01110", "10001", "10001", "10001", "10101", "10010", "01101"),
    "R": ("11110", "10001", "10001", "11110", "10100", "10010", "10001"),
    "S": ("01111", "10000", "10000", "01110", "00001", "00001", "11110"),
    "T": ("11111", "00100", "00100", "00100", "00100", "00100", "00100"),
    "U": ("10001", "10001", "10001", "10001", "10001", "10001", "01110"),
    "V": ("10001", "10001", "10001", "10001", "10001", "01010", "00100"),
    "W": ("10001", "10001", "10001", "10101", "10101", "11011", "10001"),
    "X": ("10001", "10001", "01010", "00100", "01010", "10001", "10001"),
    "Y": ("10001", "10001", "01010", "00100", "00100", "00100", "00100"),
    "Z": ("11111", "00001", "00010", "00100", "01000", "10000", "11111"),
    "0": ("01110", "10001", "10011", "10101", "11001", "10001", "01110"),
    "1": ("00100", "01100", "00100", "00100", "00100", "00100", "01110"),
    "2": ("01110", "10001", "00001", "00010", "00100", "01000", "11111"),
    "3": ("11110", "00001", "00001", "01110", "00001", "00001", "11110"),
    "4": ("00010", "00110", "01010", "10010", "11111", "00010", "00010"),
    "5": ("11111", "10000", "10000", "11110", "00001", "00001", "11110"),
    "6": ("01110", "10000", "10000", "11110", "10001", "10001", "01110"),
    "7": ("11111", "00001", "00010", "00100", "01000", "01000", "01000"),
    "8": ("01110", "10001", "10001", "01110", "10001", "10001", "01110"),
    "9": ("01110", "10001", "10001", "01111", "00001", "00001", "01110"),
    ".": ("00000", "00000", "00000", "00000", "00000", "00110", "00110"),
    ":": ("00000", "00110", "00110", "00000", "00110", "00110", "00000"),
    "-": ("00000", "00000", "00000", "11111", "00000", "00000", "00000"),
    "/": ("00001", "00010", "00010", "00100", "01000", "01000", "10000"),
    "_": ("00000", "00000", "00000", "00000", "00000", "00000", "11111"),
    " ": ("00000",) * 7,
}
_UNKNOWN = ("11111", "10001", "10101", "10101", "10101", "10001", "11111")


@dataclass(frozen=True, slots=True)
class ReplayFrame:
    event_kind: str
    caption: str


@dataclass(frozen=True, slots=True)
class ReplayClipSpec:
    finding_class: str
    artifact_link: str
    verification_link: str
    frames: tuple[ReplayFrame, ...]
    component_name: str | None = None
    disclosure_cleared: bool = False

    def __post_init__(self) -> None:
        if self.finding_class not in {"simulation", "bundled-target", "real-disclosed-finding"}:
            raise FormatError("SOVA-REPLAY-CLASS", "replay finding class is invalid")
        if not self.artifact_link or not self.verification_link or not self.frames:
            raise FormatError("SOVA-REPLAY-METADATA", "replay links and frames are required")
        if len(self.frames) > _MAX_EVENTS:
            raise FormatError("SOVA-REPLAY-LIMIT", "replay clip has too many events")
        if self.finding_class == "real-disclosed-finding" and not self.disclosure_cleared:
            raise FormatError("SOVA-REPLAY-DISCLOSURE", "real finding lacks disclosure clearance")
        if self.component_name is not None and not self.disclosure_cleared:
            raise FormatError("SOVA-REPLAY-DISCLOSURE", "component naming lacks clearance")


def _safe_caption(value: str) -> tuple[str, bool]:
    redacted, records = Redactor().redact(value)
    if records:
        return "REDACTED", True
    if not isinstance(redacted, str):
        raise FormatError("SOVA-REPLAY-CAPTION", "caption redaction changed its type")
    sanitized = _SAFE_TEXT.sub("?", redacted.upper()).strip()
    return (sanitized[:36] or "EVENT"), False


def _pixel(y_plane: bytearray, x: int, y: int, scale: int) -> None:
    for dy in range(scale):
        for dx in range(scale):
            px, py = x + dx, y + dy
            if 0 <= px < _WIDTH and 0 <= py < _HEIGHT:
                y_plane[py * _WIDTH + px] = 235


def _text(y_plane: bytearray, value: str, *, top: int, scale: int) -> None:
    cell = 6 * scale
    visible = value[: _WIDTH // cell]
    left = max(0, (_WIDTH - len(visible) * cell) // 2)
    for index, character in enumerate(visible):
        rows = _FONT_ROWS.get(character, _UNKNOWN)
        for row, pattern in enumerate(rows):
            for column, bit in enumerate(pattern):
                if bit == "1":
                    _pixel(y_plane, left + index * cell + column * scale, top + row * scale, scale)


def render_replay_clip(specification: ReplayClipSpec, destination: Path) -> dict[str, Any]:
    """Render metadata-only captions; event payload content is never placed in the clip."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    header = f"YUV4MPEG2 W{_WIDTH} H{_HEIGHT} F{_FPS}:1 Ip A1:1 C420jpeg\n".encode()
    chroma = bytes([128]) * ((_WIDTH // 2) * (_HEIGHT // 2))
    redaction_count = 0
    with destination.open("wb") as handle:
        handle.write(header)
        for index, frame in enumerate(specification.frames, 1):
            caption, redacted = _safe_caption(frame.caption)
            redaction_count += int(redacted)
            kind, kind_redacted = _safe_caption(frame.event_kind.replace(".", " "))
            redaction_count += int(kind_redacted)
            y_plane = bytearray([22]) * (_WIDTH * _HEIGHT)
            _text(y_plane, "SOVA REPLAY", top=24, scale=3)
            _text(y_plane, f"EVENT {index:03d}", top=72, scale=2)
            _text(y_plane, kind, top=105, scale=2)
            _text(y_plane, caption, top=135, scale=1)
            for _ in range(_REPEAT_FRAMES):
                handle.write(b"FRAME\n")
                handle.write(y_plane)
                handle.write(chroma)
                handle.write(chroma)
    digest = sha256_digest(destination.read_bytes())
    sidecar = {
        "artifactType": "sova.replay-clip",
        "schemaVersion": "0.1.0",
        "mediaType": "video/x-yuv4mpeg",
        "mediaDigest": digest,
        "durationSeconds": str(len(specification.frames)),
        "findingClass": specification.finding_class,
        "component": specification.component_name,
        "disclosureCleared": specification.disclosure_cleared,
        "artifactLink": specification.artifact_link,
        "verificationLink": specification.verification_link,
        "renderPolicy": "metadata-captions-only-no-event-payloads",
        "redactedCaptionCount": redaction_count,
    }
    sidecar_path = destination.with_suffix(destination.suffix + ".json")
    sidecar_path.write_bytes(canonical_json_bytes(sidecar) + b"\n")
    return sidecar
