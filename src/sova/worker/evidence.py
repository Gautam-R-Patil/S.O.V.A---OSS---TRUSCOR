# SPDX-License-Identifier: Apache-2.0
"""Controller-side validation and signing of hostile-guest evidence bundles."""

from __future__ import annotations

import stat
import zipfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import PurePosixPath
from typing import Any

from sova.formats import (
    canonical_json_bytes,
    sha256_digest,
    strict_json_loads,
    validate_document,
)
from sova.formats.errors import FormatError
from sova.trace.integrity import Ed25519Keypair, sign_dsse_payload, verify_dsse_payload
from sova.worker.contracts import ContentReference, WorkerJobManifest

GUEST_OUTPUT_MEDIA_TYPE = "application/vnd.sova.worker-guest-output+json"
CONTROLLER_EVIDENCE_MEDIA_TYPE = "application/vnd.sova.worker-evidence-report+json"
MAX_ARCHIVE_MEMBERS = 1024
MAX_COMPRESSION_RATIO = 100
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
_CONTROL_FILES = {"manifest.json", "manifest.dsse.json"}


@dataclass(frozen=True, slots=True)
class ControllerEvidencePackage:
    report: dict[str, Any]
    controller_envelope: dict[str, Any]
    artifacts: tuple[tuple[ContentReference, bytes], ...]

    def artifact(self, name: str) -> bytes:
        try:
            return next(value for reference, value in self.artifacts if reference.name == name)
        except StopIteration as error:
            raise KeyError(name) from error


def _safe_member_name(info: zipfile.ZipInfo) -> str:
    name = info.filename
    path = PurePosixPath(name)
    if (
        not name
        or "\x00" in name
        or "\\" in name
        or ":" in name
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or str(path) != name
    ):
        raise FormatError("SOVA-WORKER-EVIDENCE-PATH", "archive member path is unsafe")
    mode = info.external_attr >> 16
    file_type = stat.S_IFMT(mode)
    if info.is_dir() or stat.S_ISLNK(mode) or file_type not in {0, stat.S_IFREG}:
        raise FormatError(
            "SOVA-WORKER-EVIDENCE-FILE-TYPE",
            "directories, links, devices, and special archive members are forbidden",
        )
    if info.flag_bits & 0x1:
        raise FormatError("SOVA-WORKER-EVIDENCE-ENCRYPTED", "encrypted members are forbidden")
    if info.file_size > MAX_MANIFEST_BYTES and name in _CONTROL_FILES:
        raise FormatError("SOVA-WORKER-EVIDENCE-MANIFEST-SIZE", "control file exceeds policy")
    ratio = info.file_size / max(info.compress_size, 1)
    if ratio > MAX_COMPRESSION_RATIO:
        raise FormatError("SOVA-WORKER-EVIDENCE-COMPRESSION", "compression ratio exceeds policy")
    return name


def _read_archive(bundle: bytes, *, maximum_output_bytes: int) -> dict[str, bytes]:
    if not bundle or len(bundle) > maximum_output_bytes:
        raise FormatError("SOVA-WORKER-EVIDENCE-BUNDLE-SIZE", "bundle size exceeds job policy")
    try:
        archive = zipfile.ZipFile(BytesIO(bundle), mode="r")
    except (OSError, zipfile.BadZipFile) as error:
        raise FormatError("SOVA-WORKER-EVIDENCE-ZIP", "guest bundle is not a valid ZIP") from error
    with archive:
        infos = archive.infolist()
        if len(infos) > MAX_ARCHIVE_MEMBERS:
            raise FormatError("SOVA-WORKER-EVIDENCE-MEMBER-LIMIT", "too many archive members")
        names: set[str] = set()
        normalized_names: set[str] = set()
        total = 0
        result: dict[str, bytes] = {}
        for info in infos:
            name = _safe_member_name(info)
            folded = name.casefold()
            if name in names or folded in normalized_names:
                raise FormatError("SOVA-WORKER-EVIDENCE-DUPLICATE", "duplicate archive member")
            names.add(name)
            normalized_names.add(folded)
            total += info.file_size
            if total > maximum_output_bytes:
                raise FormatError(
                    "SOVA-WORKER-EVIDENCE-OUTPUT-BOMB",
                    "expanded guest output exceeds the job byte budget",
                )
            try:
                result[name] = archive.read(info)
            except (OSError, RuntimeError, zipfile.BadZipFile) as error:
                raise FormatError(
                    "SOVA-WORKER-EVIDENCE-ZIP", "archive member could not be read"
                ) from error
    if not _CONTROL_FILES.issubset(result):
        raise FormatError(
            "SOVA-WORKER-EVIDENCE-CONTROL", "signed manifest control files are required"
        )
    return result


def _object(raw: bytes, role: str) -> dict[str, Any]:
    value = strict_json_loads(raw, max_bytes=MAX_MANIFEST_BYTES, max_items=20_000)
    if not isinstance(value, dict):
        raise FormatError("SOVA-WORKER-EVIDENCE-JSON", f"{role} root must be an object")
    return value


def _validate_manifest_digest(manifest: dict[str, Any]) -> None:
    claimed = manifest.get("contentDigest")
    if not isinstance(claimed, str):
        raise FormatError("SOVA-WORKER-EVIDENCE-DIGEST", "manifest digest is missing")
    unsigned = dict(manifest)
    del unsigned["contentDigest"]
    if claimed != sha256_digest(canonical_json_bytes(unsigned)):
        raise FormatError("SOVA-WORKER-EVIDENCE-DIGEST", "manifest digest is invalid")


def _declared_artifacts(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    expected = {"artifactType", "schemaVersion", "jobId", "artifacts", "contentDigest"}
    if set(manifest) != expected:
        raise FormatError(
            "SOVA-WORKER-EVIDENCE-MANIFEST", "manifest contains missing or unexpected fields"
        )
    if manifest.get("artifactType") != "sova.worker-guest-output-manifest":
        raise FormatError("SOVA-WORKER-EVIDENCE-MANIFEST", "guest manifest type is invalid")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise FormatError("SOVA-WORKER-EVIDENCE-MANIFEST", "artifacts must be an array")
    if len(artifacts) > MAX_ARCHIVE_MEMBERS - len(_CONTROL_FILES):
        raise FormatError("SOVA-WORKER-EVIDENCE-MEMBER-LIMIT", "too many declared artifacts")
    if not all(isinstance(item, dict) for item in artifacts):
        raise FormatError("SOVA-WORKER-EVIDENCE-MANIFEST", "artifact entry must be an object")
    return artifacts


def validate_and_sign_guest_evidence(
    bundle: bytes,
    manifest_contract: WorkerJobManifest,
    guest_public_key: bytes,
    controller_keypair: Ed25519Keypair,
    *,
    redaction_values: tuple[bytes, ...] = (),
) -> ControllerEvidencePackage:
    """Validate hostile output entirely in memory and sign only controller-derived facts."""
    if sha256_digest(guest_public_key) != manifest_contract.guest_output_key_digest:
        raise FormatError(
            "SOVA-WORKER-EVIDENCE-KEY", "guest output key does not match the job manifest"
        )
    members = _read_archive(bundle, maximum_output_bytes=manifest_contract.limits.output_bytes)
    manifest = _object(members["manifest.json"], "guest manifest")
    _validate_manifest_digest(manifest)
    envelope = _object(members["manifest.dsse.json"], "guest signature")
    signed_payload = verify_dsse_payload(
        envelope,
        guest_public_key,
        expected_payload_type=GUEST_OUTPUT_MEDIA_TYPE,
    )
    if signed_payload != canonical_json_bytes(manifest):
        raise FormatError(
            "SOVA-WORKER-EVIDENCE-SIGNATURE", "signature does not bind the canonical manifest"
        )
    if manifest.get("jobId") != manifest_contract.job_id:
        raise FormatError("SOVA-WORKER-EVIDENCE-JOB", "guest output binds another job")
    artifacts = _declared_artifacts(manifest)
    declared_names: set[str] = set()
    accepted: list[tuple[ContentReference, bytes]] = []
    validation_records: list[dict[str, Any]] = []
    for item in artifacts:
        if set(item) != {"name", "digest", "size", "mediaType", "schemaId"}:
            raise FormatError(
                "SOVA-WORKER-EVIDENCE-MANIFEST", "artifact descriptor fields are invalid"
            )
        name = item.get("name")
        digest = item.get("digest")
        size = item.get("size")
        media_type = item.get("mediaType")
        schema_id = item.get("schemaId")
        if (
            not isinstance(name, str)
            or not name.startswith("artifacts/")
            or not isinstance(digest, str)
            or isinstance(size, bool)
            or not isinstance(size, int)
            or not isinstance(media_type, str)
            or not isinstance(schema_id, str)
        ):
            raise FormatError(
                "SOVA-WORKER-EVIDENCE-MANIFEST", "artifact descriptor types are invalid"
            )
        if name in declared_names:
            raise FormatError("SOVA-WORKER-EVIDENCE-DUPLICATE", "artifact is declared twice")
        declared_names.add(name)
        try:
            raw = members[name]
        except KeyError as error:
            raise FormatError(
                "SOVA-WORKER-EVIDENCE-MISSING", "declared artifact is missing"
            ) from error
        reference = ContentReference(name, digest, size, media_type)
        if reference.size != len(raw) or reference.digest != sha256_digest(raw):
            raise FormatError("SOVA-WORKER-EVIDENCE-DIGEST", "artifact size or digest is invalid")
        if schema_id not in manifest_contract.output_schema_ids:
            raise FormatError(
                "SOVA-WORKER-EVIDENCE-SCHEMA", "artifact schema is outside job authority"
            )
        if any(secret and secret in raw for secret in redaction_values):
            raise FormatError(
                "SOVA-WORKER-EVIDENCE-SECRET", "artifact contains a controller redaction value"
            )
        document = _object(raw, "evidence artifact")
        validate_document(document, schema_id)
        accepted.append((reference, raw))
        validation_records.append(
            {
                **reference.to_mapping(),
                "schemaId": schema_id,
                "schemaValidated": True,
                "redactionValidated": True,
            }
        )
    payload_names = set(members) - _CONTROL_FILES
    if payload_names != declared_names:
        raise FormatError(
            "SOVA-WORKER-EVIDENCE-UNDECLARED", "bundle contains undeclared artifact content"
        )
    report: dict[str, Any] = {
        "artifactType": "sova.worker-evidence-report",
        "schemaVersion": "0.1.0",
        "jobId": manifest_contract.job_id,
        "jobManifestDigest": manifest_contract.digest,
        "guestBundleDigest": sha256_digest(bundle),
        "guestManifestDigest": sha256_digest(canonical_json_bytes(manifest)),
        "guestOutputKeyDigest": manifest_contract.guest_output_key_digest,
        "artifacts": validation_records,
        "validation": {
            "archiveValidatedInMemory": True,
            "pathsAndFileTypesValidated": True,
            "sizesAndDigestsValidated": True,
            "schemasValidated": True,
            "guestSignatureValidated": True,
            "redactionValidated": True,
        },
        "claims": {
            "guestVerdictsTrusted": False,
            "controllerSigningKeyPresentInGuest": False,
            "absenceOfVulnerabilitiesProven": False,
        },
    }
    report["contentDigest"] = sha256_digest(canonical_json_bytes(report))
    controller_envelope = sign_dsse_payload(
        CONTROLLER_EVIDENCE_MEDIA_TYPE,
        canonical_json_bytes(report),
        controller_keypair,
    )
    return ControllerEvidencePackage(report, controller_envelope, tuple(accepted))


__all__ = [
    "CONTROLLER_EVIDENCE_MEDIA_TYPE",
    "GUEST_OUTPUT_MEDIA_TYPE",
    "ControllerEvidencePackage",
    "validate_and_sign_guest_evidence",
]
