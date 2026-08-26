# SPDX-License-Identifier: Apache-2.0
"""Signed playbook contribution and existing Registry staging integration."""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from typing import TYPE_CHECKING

import pytest

from sova.formats.errors import FormatError
from sova.methodology import load_builtin_library
from sova.methodology.contribution import (
    build_playbook_submission,
    prepare_playbook_contribution,
    verify_playbook_submission,
)
from sova.trace import generate_ed25519_keypair

if TYPE_CHECKING:
    from pathlib import Path


def _specification() -> dict[str, object]:
    return {
        "contributor": {"name": "Local reviewer", "identity": "local:reviewer"},
        "license": "Apache-2.0",
        "gates": {
            "humanReviewed": True,
            "publicDisclosureAllowed": True,
            "authorizationRedacted": True,
            "provenanceComplete": True,
            "separateCorpusReuseConsent": False,
        },
    }


def test_submission_verifies_and_tampering_fails() -> None:
    playbook = load_builtin_library().playbooks[0]
    keypair = generate_ed25519_keypair()
    submission = build_playbook_submission(
        playbook,
        keypair.private_key,
        keypair.public_key,
    )
    assert verify_playbook_submission(submission) == playbook
    assert submission["trustPolicy"] == "included-key-integrity-only"
    assert submission["review"]["publisherIdentityEstablished"] is False

    tampered = copy.deepcopy(submission)
    tampered["playbookDigest"] = "sha256:" + "0" * 64
    with pytest.raises(FormatError, match="digest"):
        verify_playbook_submission(tampered)

    moving_mapping = replace(
        playbook.mappings[0],
        catalog_version="latest",
        url="https://example.invalid/catalog/latest/reference",
    )
    moving_playbook = replace(
        playbook,
        mappings=(moving_mapping, *playbook.mappings[1:]),
    )
    with pytest.raises(FormatError, match="version-pinned"):
        build_playbook_submission(
            moving_playbook,
            keypair.private_key,
            keypair.public_key,
        )


def test_contribution_reuses_registry_review_without_external_side_effects(
    tmp_path: Path,
) -> None:
    playbook = load_builtin_library().playbooks[0]
    keypair = generate_ed25519_keypair()
    destination = tmp_path / "staged"
    receipt = prepare_playbook_contribution(
        playbook,
        _specification(),
        keypair.private_key,
        keypair.public_key,
        destination,
        confirmed=True,
    )
    assert receipt["uploadPerformed"] is False
    assert receipt["pullRequestCreated"] is False
    assert receipt["externalMessageSent"] is False
    assert receipt["publisherIdentityEstablished"] is False
    registry = json.loads(
        (destination / "registry-staging" / "contribution.json").read_text(encoding="utf-8")
    )
    assert registry["acceptedForLocalStaging"] is True
    assert registry["humanModerationRequired"] is True
    assert len(registry["items"]) == 2


def test_contribution_requires_confirmation_and_matching_license(tmp_path: Path) -> None:
    playbook = load_builtin_library().playbooks[0]
    keypair = generate_ed25519_keypair()
    with pytest.raises(FormatError, match="confirmation"):
        prepare_playbook_contribution(
            playbook,
            _specification(),
            keypair.private_key,
            keypair.public_key,
            tmp_path / "unconfirmed",
            confirmed=False,
        )
    wrong_license = _specification()
    wrong_license["license"] = "MIT"
    with pytest.raises(FormatError, match="license"):
        prepare_playbook_contribution(
            playbook,
            wrong_license,
            keypair.private_key,
            keypair.public_key,
            tmp_path / "wrong-license",
            confirmed=True,
        )
