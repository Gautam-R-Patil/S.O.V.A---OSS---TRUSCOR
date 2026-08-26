# SPDX-License-Identifier: Apache-2.0
"""Contribution gate must scan decompressed `.sova`/`.sova-trace` archive
content, not just raw (compressed) file bytes, for secrets and executables."""

from __future__ import annotations

import io
import re
import zipfile
from typing import TYPE_CHECKING

import pytest

from sova.capsule import CaptureProfile, DomainProfile, build_capsule, capsule_manifest_template
from sova.formats.errors import FormatError
from sova.registry.contribution import preview_contribution
from sova.trace import TraceWriter

if TYPE_CHECKING:
    from pathlib import Path

_CONTRIBUTOR = {"name": "Test Contributor", "identity": "test@example.invalid"}


def _specification(*paths: Path) -> dict[str, object]:
    return {
        "items": [str(path) for path in paths],
        "contributor": _CONTRIBUTOR,
        "license": "Apache-2.0",
        "gates": {
            "humanReviewed": True,
            "publicDisclosureAllowed": True,
            "authorizationRedacted": True,
            "provenanceComplete": True,
            "separateCorpusReuseConsent": True,
        },
    }


def test_clean_capsule_passes_the_archive_scan(tmp_path: Path) -> None:
    manifest = capsule_manifest_template(
        title="Clean fixture capsule",
        summary="Nothing secret here.",
        author="test",
        domain_profile=DomainProfile.EVALUATION,
        capture_profile=CaptureProfile.LITE,
    )
    capsule = tmp_path / "clean.sova"
    build_capsule(capsule, manifest)
    preview = preview_contribution(_specification(capsule))
    assert preview["items"][0]["safetyScanClean"] is True


def test_clean_trace_passes_the_archive_scan(tmp_path: Path) -> None:
    trace_path = tmp_path / "clean.sova-trace"
    writer = TraceWriter(trace_path)
    writer.append("run.started", {"note": "clean"}, phase="fixture")
    writer.finalize(completion="completed")
    preview = preview_contribution(_specification(trace_path))
    assert preview["items"][0]["safetyScanClean"] is True


def test_secret_shaped_content_inside_a_capsule_member_is_detected(tmp_path: Path) -> None:
    manifest = capsule_manifest_template(
        title="Secret fixture capsule",
        summary="password=hunter2hunter2hunter2",
        author="test",
        domain_profile=DomainProfile.EVALUATION,
        capture_profile=CaptureProfile.LITE,
    )
    capsule = tmp_path / "secret.sova"
    build_capsule(capsule, manifest)
    with pytest.raises(FormatError, match="credential-shaped"):
        preview_contribution(_specification(capsule))


def test_secret_shaped_content_is_undetectable_without_the_archive_scan(tmp_path: Path) -> None:
    """Regression guard: proves the raw-byte scan alone (pre-fix behavior)
    would have missed this, so the archive-member scan is load-bearing."""
    manifest = capsule_manifest_template(
        title="Secret fixture capsule",
        summary="password=hunter2hunter2hunter2",
        author="test",
        domain_profile=DomainProfile.EVALUATION,
        capture_profile=CaptureProfile.LITE,
    )
    capsule = tmp_path / "secret.sova"
    build_capsule(capsule, manifest)
    secret_pattern = re.compile(
        rb"(?i)[\"']?(api[_-]?key|authorization|cookie|credential|password|secret|token)"
        rb"[\"']?\s*[:=]\s*[\"']?[^\s,;\"']{8,}"
    )
    assert secret_pattern.search(capsule.read_bytes()) is None


def test_executable_payload_inside_an_archive_member_is_rejected(tmp_path: Path) -> None:
    malicious = tmp_path / "malicious.sova"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("payload.exe", b"MZ" + b"\x00" * 64)
    malicious.write_bytes(buffer.getvalue())
    with pytest.raises(FormatError, match=r"not a valid archive|forbidden"):
        preview_contribution(_specification(malicious))


def test_a_non_zip_file_with_a_sova_suffix_fails_closed(tmp_path: Path) -> None:
    fake = tmp_path / "notreally.sova"
    fake.write_bytes(b"not a zip file at all")
    with pytest.raises(FormatError, match="not a valid archive"):
        preview_contribution(_specification(fake))
