# SPDX-License-Identifier: Apache-2.0
"""Render verified capsule evidence without exposing an extraction workflow."""

from __future__ import annotations

import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from sova.formats import ContentDescriptor, PackageReader, strict_json_loads
from sova.formats.errors import FormatError
from sova.replay.render import render_timeline_html


@dataclass(frozen=True, slots=True)
class CapsuleReplaySelection:
    """Optional exact object choices for capsules with multiple evidence sets."""

    primary_trace: str | None = None
    comparison_trace: str | None = None
    media_object: str | None = None
    surface: str | None = None
    no_comparison: bool = False
    no_media: bool = False
    nested_capsule: str | None = None


@dataclass(frozen=True, slots=True)
class _CueMediaPair:
    cue: ContentDescriptor
    media: ContentDescriptor
    surface: str


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
    if name in {"run.sova-trace", "primary.sova-trace"}:
        return 0, descriptor.path
    if name == "reproduction.sova-trace":
        return 1, descriptor.path
    return 2, descriptor.path


def _media_surface(descriptor: ContentDescriptor) -> str:
    return (
        "computer"
        if descriptor.mediaType == "application/vnd.sova.window-frames+zip"
        else "browser"
    )


def _cue_media_pairs(
    reader: PackageReader,
    cues: list[ContentDescriptor],
    media: list[ContentDescriptor],
) -> list[_CueMediaPair]:
    """Bind every primary cue index to exactly one visual object by digest."""
    if len(cues) > len(media):
        raise FormatError(
            "SOVA-REPLAY-CAPSULE-AMBIGUOUS-CUES",
            "capsule contains multiple replay cue indexes for too few visual recordings",
            details={"available": [item.path for item in cues]},
        )
    paired: list[_CueMediaPair] = []
    paired_media: set[str] = set()
    for cue in sorted(cues, key=lambda item: item.path):
        if cue.mediaType != "application/json":
            raise FormatError(
                "SOVA-REPLAY-CUES-TYPE",
                "replay-cues object must declare application/json",
            )
        document = strict_json_loads(reader.read_object(cue))
        if not isinstance(document, dict):
            raise FormatError("SOVA-REPLAY-CUES-FORMAT", "replay cue root must be an object")
        media_digest = document.get("mediaDigest")
        matched = [item for item in media if item.digest == media_digest]
        if len(matched) != 1:
            raise FormatError(
                "SOVA-REPLAY-CAPSULE-CUES-MEDIA",
                "replay cue index does not bind exactly one visual recording",
                details={"cue": cue.path, "mediaDigest": media_digest},
            )
        selected_media = matched[0]
        if selected_media.digest in paired_media:
            raise FormatError(
                "SOVA-REPLAY-CAPSULE-AMBIGUOUS-CUES",
                "capsule contains multiple replay cue indexes for one visual recording",
                details={"media": selected_media.path},
            )
        inferred_surface = _media_surface(selected_media)
        declared_surface = document.get("surface")
        if declared_surface is not None and declared_surface not in {"browser", "computer"}:
            raise FormatError("SOVA-REPLAY-CUES-FORMAT", "unsupported replay cue surface")
        if declared_surface is not None and declared_surface != inferred_surface:
            raise FormatError(
                "SOVA-REPLAY-CAPSULE-CUE-SURFACE",
                "replay cue surface conflicts with its bound visual media type",
                details={
                    "declared": declared_surface,
                    "inferred": inferred_surface,
                    "media": selected_media.path,
                },
            )
        paired_media.add(selected_media.digest)
        paired.append(_CueMediaPair(cue, selected_media, declared_surface or inferred_surface))
    return paired


def _choose_evidence(  # noqa: PLR0912 - explicit fail-closed selection branches
    reader: PackageReader,
    descriptors: list[ContentDescriptor],
    selection: CapsuleReplaySelection,
) -> tuple[
    ContentDescriptor,
    ContentDescriptor | None,
    ContentDescriptor | None,
    ContentDescriptor | None,
    str | None,
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
    cue_candidates = [item for item in descriptors if item.role == "replay-cues"]
    media: ContentDescriptor | None = None
    cues: ContentDescriptor | None = None
    surface: str | None = None
    if not selection.no_media:
        cue_pairs = _cue_media_pairs(reader, cue_candidates, media_candidates)
        media = _selected_descriptor(
            descriptors, role="visual-replay", requested_path=selection.media_object
        )
        if media is not None:
            pair = next((item for item in cue_pairs if item.media.digest == media.digest), None)
            cues = None if pair is None else pair.cue
            surface = _media_surface(media) if pair is None else pair.surface
            if selection.surface is not None and surface != selection.surface:
                raise FormatError(
                    "SOVA-REPLAY-CAPSULE-SELECTION",
                    "selected visual replay does not match the requested surface",
                    details={"requested": selection.surface, "selected": surface},
                )
        elif selection.surface is not None:
            matching = [item for item in cue_pairs if item.surface == selection.surface]
            if len(matching) != 1:
                raise FormatError(
                    "SOVA-REPLAY-CAPSULE-AMBIGUOUS-MEDIA",
                    "requested replay surface does not identify exactly one cue-bound recording",
                    details={
                        "requestedSurface": selection.surface,
                        "available": [item.media.path for item in matching],
                    },
                )
            pair = matching[0]
            media, cues, surface = pair.media, pair.cue, pair.surface
        elif cue_pairs:
            pair = min(
                cue_pairs,
                key=lambda item: (0 if item.surface == "browser" else 1, item.media.path),
            )
            media, cues, surface = pair.media, pair.cue, pair.surface
        else:
            if len(media_candidates) > 1:
                raise FormatError(
                    "SOVA-REPLAY-CAPSULE-AMBIGUOUS-MEDIA",
                    "capsule contains multiple visual recordings; select one explicitly",
                    details={"available": [item.path for item in media_candidates]},
                )
            media = media_candidates[0] if media_candidates else None
            surface = None if media is None else _media_surface(media)
    return primary, comparison, media, cues, surface


def render_capsule_timeline(  # noqa: PLR0915 - verified materialization is explicit
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
    if selected.surface not in {None, "browser", "computer"}:
        raise FormatError(
            "SOVA-REPLAY-CAPSULE-SELECTION",
            "replay surface must be browser or computer",
        )
    if selected.no_media and selected.surface is not None:
        raise FormatError(
            "SOVA-REPLAY-CAPSULE-SELECTION",
            "surface selection and no-media cannot be requested together",
        )

    reader = PackageReader(capsule)
    descriptors = reader.verify("sova.capsule")
    nested_candidates = sorted(
        (item for item in descriptors if item.role == "capsule"),
        key=lambda item: item.path,
    )
    nested = _selected_descriptor(
        descriptors,
        role="capsule",
        requested_path=selected.nested_capsule,
    )
    if (
        nested is None
        and nested_candidates
        and selected.primary_trace is None
        and selected.media_object is None
        and not any(item.role in {"visual-replay", "replay-cues"} for item in descriptors)
    ):
        nested = nested_candidates[0]
    if nested is not None:
        with tempfile.TemporaryDirectory(prefix="sova-nested-capsule-replay-") as temporary:
            nested_path = Path(temporary) / "finding.sova"
            nested_path.write_bytes(reader.read_object(nested))
            PackageReader(nested_path).verify("sova.capsule")
            report = render_capsule_timeline(
                nested_path,
                destination,
                selection=replace(selected, nested_capsule=None),
            )
        report["capsule"] = str(capsule)
        report["nestedCapsule"] = nested.path
        report["nestedCapsuleDigest"] = nested.digest
        report["selectionMode"] = (
            "explicit-nested" if selected.nested_capsule is not None else "automatic-finding"
        )
        return report
    primary, comparison, media, cues, surface = _choose_evidence(
        reader,
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
            extension = {
                "video/webm": ".webm",
                "video/mp4": ".mp4",
                "application/vnd.sova.window-frames+zip": ".sovaframes",
            }.get(media.mediaType)
            if extension is None:
                raise FormatError(
                    "SOVA-REPLAY-MEDIA-TYPE",
                    (
                        "visual-replay object must declare video/webm or video/mp4, "
                        "or SOVA window frames"
                    ),
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
        "visualReplaySurface": surface,
        "replayCues": None if cues is None else cues.path,
        "decisiveCue": timeline["decisiveCue"],
        "decisiveCueSource": timeline["decisiveCueSource"],
        "decisiveCueDurationBound": timeline["decisiveCueDurationBound"],
        "mediaDurationSeconds": timeline["mediaDurationSeconds"],
        "opensAtDecisiveMoment": timeline["opensAtDecisiveMoment"],
        "executesRecordedActions": False,
        "nestedCapsule": None,
        "selectionMode": "direct",
    }


__all__ = ["CapsuleReplaySelection", "render_capsule_timeline"]
