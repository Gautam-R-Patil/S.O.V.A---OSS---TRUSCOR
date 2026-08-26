# SPDX-License-Identifier: Apache-2.0
"""Local-only git-PR contribution fallback: no push, no PR, ever."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from sova.capsule import CaptureProfile, DomainProfile, build_capsule, capsule_manifest_template
from sova.formats.errors import FormatError
from sova.registry.contribution import prepare_contribution
from sova.registry.pr_contribution import prepare_pr_contribution

if TYPE_CHECKING:
    from pathlib import Path


def _fixture_capsule(path: Path) -> Path:
    manifest = capsule_manifest_template(
        title="PR fixture capsule",
        summary="Minimal capsule for PR-instruction tests.",
        author="test",
        domain_profile=DomainProfile.EVALUATION,
        capture_profile=CaptureProfile.LITE,
    )
    build_capsule(path, manifest)
    return path


def _staged(tmp_path: Path) -> Path:
    capsule = _fixture_capsule(tmp_path / "source.sova")
    specification = {
        "items": [str(capsule)],
        "contributor": {"name": "Test Contributor", "identity": "test@example.invalid"},
        "license": "Apache-2.0",
        "gates": {
            "humanReviewed": True,
            "publicDisclosureAllowed": True,
            "authorizationRedacted": True,
            "provenanceComplete": True,
            "separateCorpusReuseConsent": True,
        },
    }
    destination = tmp_path / "staged"
    prepare_contribution(specification, destination, confirmed=True)
    return destination


def test_prepare_pr_contribution_never_touches_git_or_network(tmp_path: Path) -> None:
    destination = _staged(tmp_path)
    result = prepare_pr_contribution(destination)
    assert result["pushed"] is False
    assert result["pullRequestOpened"] is False
    assert result["branch"].startswith("contribute/")
    instructions_path = destination / "PR_INSTRUCTIONS.md"
    assert instructions_path.is_file()
    text = instructions_path.read_text(encoding="utf-8")
    assert "has **not** been pushed or opened" in text
    assert "git push" in text  # instructions are printed, not executed


def test_prepare_pr_contribution_requires_existing_staging(tmp_path: Path) -> None:
    with pytest.raises(FormatError, match="staged contribution"):
        prepare_pr_contribution(tmp_path / "never-staged")


def test_prepare_pr_contribution_rejects_an_empty_title(tmp_path: Path) -> None:
    destination = _staged(tmp_path)
    with pytest.raises(FormatError, match="bounded non-empty"):
        prepare_pr_contribution(destination, title="")


def test_branch_names_are_filesystem_and_git_safe(tmp_path: Path) -> None:
    destination = _staged(tmp_path)
    result = prepare_pr_contribution(destination)
    branch = result["branch"]
    assert " " not in branch
    assert all(char.isalnum() or char in "-_./" for char in branch)
