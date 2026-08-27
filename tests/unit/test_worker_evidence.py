# SPDX-License-Identifier: Apache-2.0
"""Controller-side hostile guest evidence validation tests."""

from __future__ import annotations

import json
import stat
import zipfile
from io import BytesIO

import pytest

from sova.formats import FormatError, canonical_json_bytes, sha256_digest, validate_document
from sova.trace.integrity import (
    Ed25519Keypair,
    generate_ed25519_keypair,
    sign_dsse_payload,
    verify_dsse_payload,
)
from sova.worker.brokers import NetworkFlowReceipt
from sova.worker.evidence import (
    CONTROLLER_EVIDENCE_MEDIA_TYPE,
    GUEST_OUTPUT_MEDIA_TYPE,
    validate_and_sign_guest_evidence,
)
from tests.support.worker import guest_keypair, worker_manifest


def _artifact() -> bytes:
    receipt = NetworkFlowReceipt(
        job_id="job:p5-fixture",
        sequence=1,
        observed_at="2026-08-27T10:01:00Z",
        hostname="example.com",
        port=443,
        protocol="tcp",
        pinned_addresses=("1.1.1.1",),
        resolved_addresses=("1.1.1.1",),
        selected_address="1.1.1.1",
        requested_bytes=100,
        decision="allowed",
        reason="policy-and-budgets-satisfied",
    )
    return canonical_json_bytes(receipt.to_mapping())


def _bundle_from_manifest(
    guest_key: Ed25519Keypair,
    manifest: object,
    files: dict[str, bytes],
    *,
    signed_payload: bytes | None = None,
) -> bytes:
    manifest_bytes = canonical_json_bytes(manifest)
    envelope = sign_dsse_payload(
        GUEST_OUTPUT_MEDIA_TYPE,
        manifest_bytes if signed_payload is None else signed_payload,
        guest_key,
    )
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", manifest_bytes)
        archive.writestr("manifest.dsse.json", canonical_json_bytes(envelope))
        for name, raw in files.items():
            archive.writestr(name, raw)
    return stream.getvalue()


def _bundle(guest_key: Ed25519Keypair, *, artifact: bytes | None = None) -> bytes:
    artifact_bytes = _artifact() if artifact is None else artifact
    manifest = {
        "artifactType": "sova.worker-guest-output-manifest",
        "schemaVersion": "0.1.0",
        "jobId": "job:p5-fixture",
        "artifacts": [
            {
                "name": "artifacts/network.json",
                "digest": sha256_digest(artifact_bytes),
                "size": len(artifact_bytes),
                "mediaType": "application/json",
                "schemaId": "sova.worker-network-receipt",
            }
        ],
    }
    manifest["contentDigest"] = sha256_digest(canonical_json_bytes(manifest))
    return _bundle_from_manifest(guest_key, manifest, {"artifacts/network.json": artifact_bytes})


def test_controller_validates_guest_bundle_and_signs_derived_report() -> None:
    guest = guest_keypair()
    controller = generate_ed25519_keypair()
    package = validate_and_sign_guest_evidence(
        _bundle(guest), worker_manifest(guest), guest.public_key, controller
    )
    validate_document(package.report)
    payload = verify_dsse_payload(
        package.controller_envelope,
        controller.public_key,
        expected_payload_type=CONTROLLER_EVIDENCE_MEDIA_TYPE,
    )
    assert payload == canonical_json_bytes(package.report)
    assert package.report["claims"]["guestVerdictsTrusted"] is False
    assert package.artifact("artifacts/network.json") == _artifact()


def test_controller_rejects_wrong_guest_key_and_secret_leak() -> None:
    guest = guest_keypair()
    wrong = guest_keypair()
    controller = generate_ed25519_keypair()
    with pytest.raises(FormatError, match="does not match"):
        validate_and_sign_guest_evidence(
            _bundle(guest), worker_manifest(guest), wrong.public_key, controller
        )
    with pytest.raises(FormatError, match="redaction value"):
        validate_and_sign_guest_evidence(
            _bundle(guest),
            worker_manifest(guest),
            guest.public_key,
            controller,
            redaction_values=(b"example.com",),
        )


def test_controller_rejects_path_traversal_symlink_and_output_bomb() -> None:
    guest = guest_keypair()
    controller = generate_ed25519_keypair()
    attacks: list[bytes] = []
    traversal = BytesIO()
    with zipfile.ZipFile(traversal, "w") as archive:
        archive.writestr("../escape", b"x")
    attacks.append(traversal.getvalue())
    symlink = BytesIO()
    with zipfile.ZipFile(symlink, "w") as archive:
        info = zipfile.ZipInfo("artifacts/link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, "../../host")
    attacks.append(symlink.getvalue())
    bomb = BytesIO()
    with zipfile.ZipFile(bomb, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("artifacts/bomb", b"0" * 200_000)
    attacks.append(bomb.getvalue())
    for attack in attacks:
        with pytest.raises(FormatError):
            validate_and_sign_guest_evidence(
                attack, worker_manifest(guest), guest.public_key, controller
            )


def test_controller_rejects_unsigned_mutation_and_undeclared_member() -> None:
    guest = guest_keypair()
    controller = generate_ed25519_keypair()
    original = _bundle(guest)
    source = zipfile.ZipFile(BytesIO(original), "r")
    mutated = BytesIO()
    with source, zipfile.ZipFile(mutated, "w") as target:
        for info in source.infolist():
            raw = source.read(info)
            if info.filename == "manifest.json":
                document = json.loads(raw)
                document["jobId"] = "job:mutated"
                raw = canonical_json_bytes(document)
            target.writestr(info.filename, raw)
        target.writestr("artifacts/undeclared.json", b"{}")
    with pytest.raises(FormatError):
        validate_and_sign_guest_evidence(
            mutated.getvalue(), worker_manifest(guest), guest.public_key, controller
        )


def test_evidence_package_lookup_rejects_unknown_artifact() -> None:
    guest = guest_keypair()
    controller = generate_ed25519_keypair()
    package = validate_and_sign_guest_evidence(
        _bundle(guest), worker_manifest(guest), guest.public_key, controller
    )
    with pytest.raises(KeyError):
        package.artifact("missing")


def test_archive_preflight_rejects_empty_bad_zip_missing_controls_and_duplicates() -> None:
    guest = guest_keypair()
    controller = generate_ed25519_keypair()
    manifest = worker_manifest(guest)
    attacks = [b"", b"not-a-zip"]
    missing = BytesIO()
    with zipfile.ZipFile(missing, "w") as archive:
        archive.writestr("artifact.json", b"{}")
    attacks.append(missing.getvalue())
    duplicate = BytesIO()
    with zipfile.ZipFile(duplicate, "w") as archive:
        archive.writestr("manifest.json", b"{}")
        archive.writestr("MANIFEST.JSON", b"{}")
    attacks.append(duplicate.getvalue())
    for attack in attacks:
        with pytest.raises(FormatError):
            validate_and_sign_guest_evidence(attack, manifest, guest.public_key, controller)


def _valid_manifest(artifact: bytes) -> dict[str, object]:
    document: dict[str, object] = {
        "artifactType": "sova.worker-guest-output-manifest",
        "schemaVersion": "0.1.0",
        "jobId": "job:p5-fixture",
        "artifacts": [
            {
                "name": "artifacts/network.json",
                "digest": sha256_digest(artifact),
                "size": len(artifact),
                "mediaType": "application/json",
                "schemaId": "sova.worker-network-receipt",
            }
        ],
    }
    document["contentDigest"] = sha256_digest(canonical_json_bytes(document))
    return document


def _redigest(document: dict[str, object]) -> None:
    document.pop("contentDigest", None)
    document["contentDigest"] = sha256_digest(canonical_json_bytes(document))


def test_guest_manifest_rejects_root_digest_signature_job_and_artifact_shape() -> None:
    guest = guest_keypair()
    controller = generate_ed25519_keypair()
    contract = worker_manifest(guest)
    artifact = _artifact()
    invalid_digest = _valid_manifest(artifact)
    invalid_digest["contentDigest"] = sha256_digest(b"wrong")
    wrong_job = _valid_manifest(artifact)
    wrong_job["jobId"] = "job:other"
    _redigest(wrong_job)
    wrong_fields = _valid_manifest(artifact)
    wrong_fields["extra"] = True
    _redigest(wrong_fields)
    wrong_artifacts = _valid_manifest(artifact)
    wrong_artifacts["artifacts"] = "invalid"
    _redigest(wrong_artifacts)
    non_object_artifact = _valid_manifest(artifact)
    non_object_artifact["artifacts"] = ["invalid"]
    _redigest(non_object_artifact)
    attacks = (
        _bundle_from_manifest(guest, [], {}),
        _bundle_from_manifest(guest, invalid_digest, {"artifacts/network.json": artifact}),
        _bundle_from_manifest(
            guest,
            _valid_manifest(artifact),
            {"artifacts/network.json": artifact},
            signed_payload=b"{}",
        ),
        _bundle_from_manifest(guest, wrong_job, {"artifacts/network.json": artifact}),
        _bundle_from_manifest(guest, wrong_fields, {"artifacts/network.json": artifact}),
        _bundle_from_manifest(guest, wrong_artifacts, {}),
        _bundle_from_manifest(guest, non_object_artifact, {}),
    )
    for attack in attacks:
        with pytest.raises(FormatError):
            validate_and_sign_guest_evidence(attack, contract, guest.public_key, controller)


def test_guest_artifact_descriptor_rejects_field_type_membership_digest_and_schema() -> None:
    guest = guest_keypair()
    controller = generate_ed25519_keypair()
    contract = worker_manifest(guest)
    artifact = _artifact()
    base = _valid_manifest(artifact)
    descriptor = dict(base["artifacts"][0])  # type: ignore[index]
    descriptors: list[tuple[dict[str, object], dict[str, bytes]]] = []
    bad_fields = dict(descriptor)
    bad_fields["extra"] = True
    descriptors.append((bad_fields, {"artifacts/network.json": artifact}))
    bad_type = dict(descriptor)
    bad_type["size"] = True
    descriptors.append((bad_type, {"artifacts/network.json": artifact}))
    missing = dict(descriptor)
    missing["name"] = "artifacts/missing.json"
    descriptors.append((missing, {"artifacts/network.json": artifact}))
    bad_digest = dict(descriptor)
    bad_digest["digest"] = sha256_digest(b"wrong")
    descriptors.append((bad_digest, {"artifacts/network.json": artifact}))
    bad_schema = dict(descriptor)
    bad_schema["schemaId"] = "sova.evidence"
    descriptors.append((bad_schema, {"artifacts/network.json": artifact}))
    invalid_json = dict(descriptor)
    invalid_json["digest"] = sha256_digest(b"{}")
    invalid_json["size"] = 2
    descriptors.append((invalid_json, {"artifacts/network.json": b"{}"}))
    for candidate, files in descriptors:
        manifest = _valid_manifest(artifact)
        manifest["artifacts"] = [candidate]
        _redigest(manifest)
        with pytest.raises(FormatError):
            validate_and_sign_guest_evidence(
                _bundle_from_manifest(guest, manifest, files),
                contract,
                guest.public_key,
                controller,
            )


def test_guest_manifest_rejects_duplicate_declarations() -> None:
    guest = guest_keypair()
    controller = generate_ed25519_keypair()
    artifact = _artifact()
    manifest = _valid_manifest(artifact)
    descriptor = dict(manifest["artifacts"][0])  # type: ignore[index]
    manifest["artifacts"] = [descriptor, descriptor]
    _redigest(manifest)
    with pytest.raises(FormatError, match="declared twice"):
        validate_and_sign_guest_evidence(
            _bundle_from_manifest(guest, manifest, {"artifacts/network.json": artifact}),
            worker_manifest(guest),
            guest.public_key,
            controller,
        )
