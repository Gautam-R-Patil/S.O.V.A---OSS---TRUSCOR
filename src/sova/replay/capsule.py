# SPDX-License-Identifier: Apache-2.0
"""Render verified capsule evidence without exposing an extraction workflow."""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sova.formats import ContentDescriptor, PackageReader
from sova.formats.errors import FormatError
from sova.replay.render import render_timeline_html


@dataclass(frozen=True, slots=True)
class CapsuleReplaySelection:
    """Optional exact object choices for capsules with multiple evidence sets."""

    primary_trace: str | None = None
    comparison_trace: str | None = None
    media_object: str | None = None
    no_comparison: bool = False
    no_media: bool = False


def _selected_descriptor(
    descriptors: list[ContentDescriptor],
    *,
    role: str,
    requested_path: str | None,
) -> ContentDescriptor | None:
    candidates = [item for item in descriptors if item.role == role]
    if requested_path is None:
        return None
    matches = [item for item in candidates if item.path == requested_path]
    if len(matches) != 1:
        raise FormatError(
            "SOVA-REPLAY-CAPSULE-SELECTION",
            f"{role} object was not found at the exact declared package path",
            details={"requested": requested_path, "available": [item.path for item in candidates]},
        )
    return matches[0]


def _trace_priority(descriptor: ContentDescriptor) -> tuple[int, str]:
    name = Path(descriptor.path).name.casefold()
    if name == "run.sova-trace":
        return 0, descriptor.path
    if name == "reproduction.sova-trace":
        return 1, descriptor.path
    return 2, descriptor.path


def _choose_evidence(
    descriptors: list[ContentDescriptor],
    selection: CapsuleReplaySelection,
) -> tuple[
    ContentDescriptor,
    ContentDescriptor | None,
    ContentDescriptor | None,
    ContentDescriptor | None,
]:
    traces = sorted((item for item in descriptors if item.role == "trace"), key=_trace_priority)
    if not traces:
        raise FormatError(
            "SOVA-REPLAY-CAPSULE-TRACE",
            "capsule contains no verified trace object to replay",
        )
    primary = (
        _selected_descriptor(descriptors, role="trace", requested_path=selection.primary_trace)
        or traces[0]
    )
    remaining = [item for item in traces if item.path != primary.path]
    comparison: ContentDescriptor | None = None
    if not selection.no_comparison:
        comparison = _selected_descriptor(
            descriptors, role="trace", requested_path=selection.comparison_trace
        )
        if comparison is not None and comparison.path == primary.path:
            raise FormatError(
                "SOVA-REPLAY-CAPSULE-SELECTION",
                "primary and comparison trace objects must be different",
            )
        if comparison is None:
            if len(remaining) > 1:
                raise FormatError(
                    "SOVA-REPLAY-CAPSULE-AMBIGUOUS-TRACE",
                    "capsule contains multiple comparison traces; select one explicitly",
                    details={"available": [item.path for item in remaining]},
                )
            comparison = remaining[0] if remaining else None

    media_candidates = [item for item in descriptors if item.role == "visual-replay"]
    media: ContentDescriptor | None = None
    if not selection.no_media:
        media = _selected_descriptor(
            descriptors, role="visual-replay", requested_path=selection.media_object
        )
        if media is None:
            if len(media_candidates) > 1:
                raise FormatError(
                    "SOVA-REPLAY-CAPSULE-AMBIGUOUS-MEDIA",
                    "capsule contains multiple visual recordings; select one explicitly",
                    details={"available": [item.path for item in media_candidates]},
                )
            media = media_candidates[0] if media_candidates else None
    cue_candidates = [item for item in descriptors if item.role == "replay-cues"]
    if len(cue_candidates) > 1:
        raise FormatError(
            "SOVA-REPLAY-CAPSULE-AMBIGUOUS-CUES",
            "capsule contains multiple replay cue indexes",
            details={"available": [item.path for item in cue_candidates]},
        )
    cues = cue_candidates[0] if cue_candidates and media is not None else None
    return primary, comparison, media, cues


def render_capsule_timeline(
    capsule: Path,
    destination: Path,
    *,
    selection: CapsuleReplaySelection | None = None,
) -> dict[str, Any]:
    """Render selected verified capsule evidence as one inert self-contained page.

    Package members are read by descriptor and materialized only in a temporary
    directory. No archive path is extracted and no recorded content is executed.
    """
    if destination.resolve() == capsule.resolve():
        raise FormatError(
            "SOVA-REPLAY-IMMUTABLE-SOURCE",
            "capsule replay requires a destination separate from its source capsule",
        )
    selected = selection or CapsuleReplaySelection()
    if selected.no_comparison and selected.comparison_trace is not None:
        raise FormatError(
            "SOVA-REPLAY-CAPSULE-SELECTION",
            "comparison selection and no-comparison cannot be requested together",
        )
    if selected.no_media and selected.media_object is not None:
        raise FormatError(
            "SOVA-REPLAY-CAPSULE-SELECTION",
            "media selection and no-media cannot be requested together",
        )

    reader = PackageReader(capsule)
    descriptors = reader.verify("sova.capsule")
    primary, comparison, media, cues = _choose_evidence(
        descriptors,
        selected,
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="sova-capsule-replay-") as temporary:
        root = Path(temporary)
        primary_path = root / "primary.sova-trace"
        primary_path.write_bytes(reader.read_object(primary))
        comparison_path: Path | None = None
        if comparison is not None:
            comparison_path = root / "comparison.sova-trace"
            comparison_path.write_bytes(reader.read_object(comparison))
        media_path: Path | None = None
        if media is not None:
            extension = {"video/webm": ".webm", "video/mp4": ".mp4"}.get(media.mediaType)
            if extension is None:
                raise FormatError(
                    "SOVA-REPLAY-MEDIA-TYPE",
                    "visual-replay object must declare video/webm or video/mp4",
                )
            media_path = root / f"session{extension}"
            media_path.write_bytes(reader.read_object(media))
        cue_path: Path | None = None
        if cues is not None:
            if cues.mediaType != "application/json":
                raise FormatError(
                    "SOVA-REPLAY-CUES-TYPE",
                    "replay-cues object must declare application/json",
                )
            cue_path = root / "replay-cues.json"
            cue_path.write_bytes(reader.read_object(cues))
        timeline = render_timeline_html(
            primary_path,
            destination,
            comparison=comparison_path,
            media=media_path,
            replay_cues=cue_path,
        )
    return {
        "artifactType": "sova.capsule-replay",
        "schemaVersion": "0.1.0",
        "capsule": str(capsule),
        "destination": str(destination.resolve()),
        "primaryTrace": primary.path,
        "comparisonTrace": None if comparison is None else comparison.path,
        "visualReplay": None if media is None else media.path,
        "replayCues": None if cues is None else cues.path,
        "decisiveCue": timeline["decisiveCue"],
        "decisiveCueSource": timeline["decisiveCueSource"],
        "decisiveCueDurationBound": timeline["decisiveCueDurationBound"],
        "mediaDurationSeconds": timeline["mediaDurationSeconds"],
        "opensAtDecisiveMoment": timeline["opensAtDecisiveMoment"],
        "executesRecordedActions": False,
    }


__all__ = ["CapsuleReplaySelection", "render_capsule_timeline"]
