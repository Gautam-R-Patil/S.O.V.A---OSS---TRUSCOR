# SPDX-License-Identifier: Apache-2.0
"""Signed, versioned playbook contribution staging through the existing Registry gate."""

from __future__ import annotations

import base64
import binascii
import re
import shutil
from typing import TYPE_CHECKING, Any

from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads, validate_document
from sova.formats.errors import FormatError
from sova.methodology.contracts import SUBMISSION_SCHEMA_VERSION, Playbook
from sova.methodology.library import playbook_from_mapping
from sova.registry.contribution import prepare_contribution
from sova.trace import sign_dsse_payload, verify_dsse_payload
from sova.trace.integrity import Ed25519Keypair

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

PLAYBOOK_PAYLOAD_TYPE = "application/vnd.sova.playbook+json"
_RAW_ED25519_KEY_BYTES = 32
_UNPINNED_VERSION = re.compile(
    r"(?:^|[-_. ])(?:latest|current|head|main|master|unversioned)(?:$|[-_. ])",
    re.IGNORECASE,
)
_MOVING_REFERENCE_PATH = re.compile(r"/(?:latest|current|head|main|master)(?:/|$)", re.IGNORECASE)


def build_playbook_submission(
    playbook: Playbook,
    private_key: bytes,
    public_key: bytes,
) -> dict[str, Any]:
    """Create a DSSE submission whose included key proves integrity, not identity."""
    if len(private_key) != _RAW_ED25519_KEY_BYTES or len(public_key) != _RAW_ED25519_KEY_BYTES:
        raise FormatError(
            "SOVA-PLAYBOOK-SIGNING-KEY", "playbook signing keys must be raw Ed25519 bytes"
        )
    validate_document(playbook.to_mapping(), "sova.playbook")
    if any(
        _UNPINNED_VERSION.search(mapping.catalog_version)
        or _MOVING_REFERENCE_PATH.search(mapping.url)
        for mapping in playbook.mappings
    ):
        raise FormatError(
            "SOVA-PLAYBOOK-MAPPING-PIN",
            "signed playbook submissions require version-pinned mapping references",
        )
    payload = canonical_json_bytes(playbook.to_mapping())
    key_id = sha256_digest(public_key)
    keypair = Ed25519Keypair(private_key, public_key, key_id)
    envelope = sign_dsse_payload(PLAYBOOK_PAYLOAD_TYPE, payload, keypair)
    submission = {
        "artifactType": "sova.playbook-submission",
        "schemaVersion": SUBMISSION_SCHEMA_VERSION,
        "playbookDigest": playbook.digest,
        "envelope": envelope,
        "publicKey": {
            "algorithm": "ed25519",
            "keyid": key_id,
            "raw": base64.b64encode(public_key).decode("ascii"),
        },
        "trustPolicy": "included-key-integrity-only",
        "review": {
            "schemaValid": True,
            "semanticValid": True,
            "provenancePresent": True,
            "evidenceLimitsPresent": True,
            "mappingLinksPinned": True,
            "humanReviewRequired": True,
            "acceptedForLocalStaging": True,
            "publisherIdentityEstablished": False,
        },
    }
    verify_playbook_submission(submission)
    return submission


def verify_playbook_submission(document: dict[str, Any]) -> Playbook:
    """Verify structure, included-key signature, canonical payload, and playbook semantics."""
    validate_document(document, "sova.playbook-submission")
    public_key = _decode_base64(document["publicKey"]["raw"])
    if len(public_key) != _RAW_ED25519_KEY_BYTES or document["publicKey"]["keyid"] != sha256_digest(
        public_key
    ):
        raise FormatError("SOVA-PLAYBOOK-SIGNING-KEY", "submission public key is invalid")
    payload = verify_dsse_payload(
        document["envelope"],
        public_key,
        expected_payload_type=PLAYBOOK_PAYLOAD_TYPE,
    )
    parsed = strict_json_loads(payload)
    if not isinstance(parsed, dict):
        raise FormatError("SOVA-PLAYBOOK-SUBMISSION", "signed playbook root must be an object")
    validate_document(parsed, "sova.playbook")
    playbook = playbook_from_mapping(parsed)
    if payload != canonical_json_bytes(playbook.to_mapping()):
        raise FormatError("SOVA-PLAYBOOK-SUBMISSION", "signed playbook is not canonical")
    if document["playbookDigest"] != playbook.digest:
        raise FormatError("SOVA-PLAYBOOK-SUBMISSION", "playbook digest does not match")
    return playbook


def prepare_playbook_contribution(  # noqa: PLR0913 - review inputs remain explicit
    playbook: Playbook,
    specification: Mapping[str, Any],
    private_key: bytes,
    public_key: bytes,
    destination: Path,
    *,
    confirmed: bool,
) -> dict[str, Any]:
    """Stage signed playbook material and reuse the Registry review pipeline without upload."""
    if set(specification) != {"contributor", "license", "gates"}:
        raise FormatError(
            "SOVA-PLAYBOOK-CONTRIBUTION-SPEC",
            "playbook contribution specification fields are missing or unknown",
        )
    if specification.get("license") != playbook.provenance.license_expression:
        raise FormatError(
            "SOVA-PLAYBOOK-CONTRIBUTION-LICENSE",
            "contribution license must match the playbook provenance license",
        )
    final = destination.resolve()
    if final.exists():
        raise FormatError("SOVA-PLAYBOOK-CONTRIBUTION-DESTINATION", "destination must not exist")
    final.parent.mkdir(parents=True, exist_ok=True)
    staging = final.with_name(f".{final.name}.partial")
    if staging.exists():
        raise FormatError(
            "SOVA-PLAYBOOK-CONTRIBUTION-STAGING", "partial destination already exists"
        )
    staging.mkdir()
    try:
        reviewed = staging / "reviewed"
        reviewed.mkdir()
        playbook_path = reviewed / "playbook.json"
        submission_path = reviewed / "submission.json"
        submission = build_playbook_submission(playbook, private_key, public_key)
        playbook_path.write_bytes(canonical_json_bytes(playbook.to_mapping()) + b"\n")
        submission_path.write_bytes(canonical_json_bytes(submission) + b"\n")
        registry_specification = {
            **dict(specification),
            "items": [str(playbook_path), str(submission_path)],
        }
        registry_result = prepare_contribution(
            registry_specification,
            staging / "registry-staging",
            confirmed=confirmed,
        )
        receipt = {
            "artifactType": "sova.playbook-contribution-staging",
            "schemaVersion": SUBMISSION_SCHEMA_VERSION,
            "playbookDigest": playbook.digest,
            "submissionDigest": sha256_digest(canonical_json_bytes(submission)),
            "registryContribution": registry_result,
            "humanModerationRequired": True,
            "publisherIdentityEstablished": False,
            "uploadPerformed": False,
            "pullRequestCreated": False,
            "externalMessageSent": False,
        }
        (staging / "receipt.json").write_bytes(canonical_json_bytes(receipt) + b"\n")
        staging.replace(final)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    else:
        return receipt


def _decode_base64(value: Any) -> bytes:
    if not isinstance(value, str):
        raise FormatError("SOVA-PLAYBOOK-SUBMISSION", "public key must be base64 text")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise FormatError("SOVA-PLAYBOOK-SUBMISSION", "public key base64 is invalid") from error


__all__ = [
    "PLAYBOOK_PAYLOAD_TYPE",
    "build_playbook_submission",
    "prepare_playbook_contribution",
    "verify_playbook_submission",
]
