# SPDX-License-Identifier: Apache-2.0
"""Strict untrusted-input parsing for worker job manifests."""

from __future__ import annotations

from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads, validate_document
from sova.formats.errors import FormatError
from sova.worker.contracts import (
    ContentReference,
    NetworkRule,
    ResourceLimits,
    SecretGrant,
    SecretKind,
    WorkerBackend,
    WorkerJobManifest,
)


def _object(value: Any, role: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FormatError("SOVA-WORKER-INPUT-TYPE", f"{role} must be an object")
    return value


def _array(value: Any, role: str) -> list[Any]:
    if not isinstance(value, list):
        raise FormatError("SOVA-WORKER-INPUT-TYPE", f"{role} must be an array")
    return value


def _string(value: Any, role: str) -> str:
    if not isinstance(value, str):
        raise FormatError("SOVA-WORKER-INPUT-TYPE", f"{role} must be a string")
    return value


def _integer(value: Any, role: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise FormatError("SOVA-WORKER-INPUT-TYPE", f"{role} must be an integer")
    return value


def _content(value: Any) -> ContentReference:
    item = _object(value, "content reference")
    return ContentReference(
        name=_string(item.get("name"), "content name"),
        digest=_string(item.get("digest"), "content digest"),
        size=_integer(item.get("size"), "content size"),
        media_type=_string(item.get("mediaType"), "content media type"),
    )


def _network_rule(value: Any) -> NetworkRule:
    item = _object(value, "network rule")
    addresses = _array(item.get("initialAddresses"), "initial addresses")
    return NetworkRule(
        hostname=_string(item.get("hostname"), "network hostname"),
        port=_integer(item.get("port"), "network port"),
        protocol=_string(item.get("protocol"), "network protocol"),
        initial_addresses=tuple(_string(address, "network address") for address in addresses),
        allow_private=item.get("allowPrivate") is True,
    )


def _secret_grant(value: Any) -> SecretGrant:
    item = _object(value, "secret grant")
    try:
        kind = SecretKind(_string(item.get("kind"), "secret kind"))
    except ValueError as error:
        raise FormatError("SOVA-WORKER-INPUT-ENUM", "secret kind is unsupported") from error
    return SecretGrant(
        name=_string(item.get("name"), "secret name"),
        audience=_string(item.get("audience"), "secret audience"),
        expires_at=_string(item.get("expiresAt"), "secret expiry"),
        kind=kind,
        maximum_uses=_integer(item.get("maximumUses"), "secret maximum uses"),
    )


def _limits(value: Any) -> ResourceLimits:
    item = _object(value, "resource limits")
    return ResourceLimits(
        vcpu_count=_integer(item.get("vcpuCount"), "vCPU count"),
        memory_mib=_integer(item.get("memoryMiB"), "memory MiB"),
        timeout_seconds=_integer(item.get("timeoutSeconds"), "timeout"),
        output_bytes=_integer(item.get("outputBytes"), "output bytes"),
        writable_disk_bytes=_integer(item.get("writableDiskBytes"), "writable disk bytes"),
        process_limit=_integer(item.get("processLimit"), "process limit"),
        open_file_limit=_integer(item.get("openFileLimit"), "open-file limit"),
        network_connection_limit=_integer(
            item.get("networkConnectionLimit"), "network connection limit"
        ),
        network_bytes=_integer(item.get("networkBytes"), "network bytes"),
    )


def job_manifest_from_mapping(document: dict[str, Any]) -> WorkerJobManifest:
    """Validate schema, content digest, and typed invariants for a worker job."""
    validate_document(document, "sova.worker-job-manifest")
    unsigned = dict(document)
    claimed = _string(unsigned.pop("contentDigest", None), "manifest content digest")
    if claimed != sha256_digest(canonical_json_bytes(unsigned)):
        raise FormatError("SOVA-WORKER-INPUT-DIGEST", "manifest content digest is invalid")
    bindings = _object(document.get("bindings"), "manifest bindings")
    boot = _object(document.get("boot"), "manifest boot")
    try:
        backend = WorkerBackend(_string(document.get("backend"), "worker backend"))
    except ValueError as error:
        raise FormatError("SOVA-WORKER-INPUT-ENUM", "worker backend is unsupported") from error
    return WorkerJobManifest(
        job_id=_string(document.get("jobId"), "job identifier"),
        issued_at=_string(document.get("issuedAt"), "job issue time"),
        expires_at=_string(document.get("expiresAt"), "job expiry time"),
        target_profile_digest=_string(bindings.get("targetProfileDigest"), "target profile digest"),
        authorization_decision_digest=_string(
            bindings.get("authorizationDecisionDigest"), "authorization decision digest"
        ),
        methodology_plan_digest=_string(
            bindings.get("methodologyPlanDigest"), "methodology plan digest"
        ),
        guest_output_key_digest=_string(
            bindings.get("guestOutputKeyDigest"), "guest output key digest"
        ),
        guest_kernel=_content(boot.get("guestKernel")),
        root_filesystem=_content(boot.get("rootFilesystem")),
        writable_layer_seed=_content(boot.get("writableLayerSeed")),
        inputs=tuple(_content(value) for value in _array(document.get("inputs"), "inputs")),
        network_rules=tuple(
            _network_rule(value) for value in _array(document.get("networkRules"), "network rules")
        ),
        secret_grants=tuple(
            _secret_grant(value) for value in _array(document.get("secretGrants"), "secret grants")
        ),
        output_schema_ids=tuple(
            _string(value, "output schema")
            for value in _array(document.get("outputSchemaIds"), "output schemas")
        ),
        limits=_limits(document.get("limits")),
        backend=backend,
    )


def read_worker_job_manifest(raw: bytes) -> WorkerJobManifest:
    """Read a bounded canonical manifest from an untrusted transport payload."""
    document = strict_json_loads(raw, max_bytes=2 * 1024 * 1024, max_items=50_000)
    return job_manifest_from_mapping(_object(document, "worker manifest"))


__all__ = ["job_manifest_from_mapping", "read_worker_job_manifest"]
