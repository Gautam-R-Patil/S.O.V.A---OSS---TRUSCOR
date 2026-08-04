# SPDX-License-Identifier: Apache-2.0
"""Executor-independent target descriptions for the supported integration surfaces."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

_ID = re.compile(r"^[a-z0-9][a-z0-9._:/-]{0,190}$")
_SENSITIVE_KEY = re.compile(
    r"(?:token|secret|password|credential|cookie|authorization|api[_-]?key)",
    re.IGNORECASE,
)


class TargetKind(StrEnum):
    MCP_SERVER = "mcp-server"
    LOCAL_PROCESS = "local-process"
    REST_API = "rest-api"
    BROWSER_AGENT = "browser-agent"
    COMPUTER_AGENT = "computer-agent"
    FRAMEWORK = "framework"
    MULTI_AGENT = "multi-agent"
    TRACE_ONLY = "trace-only"


_REQUIRED_CAPABILITIES: dict[TargetKind, frozenset[str]] = {
    TargetKind.MCP_SERVER: frozenset({"protocol.mcp"}),
    TargetKind.LOCAL_PROCESS: frozenset({"process.invoke"}),
    TargetKind.REST_API: frozenset({"protocol.http"}),
    TargetKind.BROWSER_AGENT: frozenset({"browser.observe"}),
    TargetKind.COMPUTER_AGENT: frozenset({"computer.observe"}),
    TargetKind.FRAMEWORK: frozenset({"manifest.inspect"}),
    TargetKind.MULTI_AGENT: frozenset({"inter-agent.observe"}),
    TargetKind.TRACE_ONLY: frozenset({"trace.import"}),
}


@dataclass(frozen=True, slots=True)
class TargetManifest:
    """Portable intent and observation surface; mechanics remain executor-owned."""

    identifier: str
    kind: TargetKind
    version: str
    capabilities: tuple[str, ...]
    authorization_scope: str
    configuration: dict[str, Any]

    def __post_init__(self) -> None:
        if not _ID.fullmatch(self.identifier):
            raise FormatError("SOVA-TARGET-ID", "target identifier is invalid")
        if not self.version or not self.authorization_scope:
            raise FormatError("SOVA-TARGET-METADATA", "target version and authority are required")
        if any(not _ID.fullmatch(item) for item in self.capabilities):
            raise FormatError("SOVA-TARGET-CAPABILITY", "target capability is invalid")
        _reject_sensitive_configuration(self.configuration)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.target-manifest",
            "schemaVersion": "0.1.0",
            "identifier": self.identifier,
            "kind": self.kind.value,
            "version": self.version,
            "capabilities": sorted(self.capabilities),
            "authorizationScope": self.authorization_scope,
            "configuration": self.configuration,
        }

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))


def _reject_sensitive_configuration(value: Any, path: str = "$.configuration") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise FormatError("SOVA-TARGET-CONFIG", "target configuration keys must be strings")
            if _SENSITIVE_KEY.search(key):
                raise FormatError(
                    "SOVA-TARGET-SECRET",
                    "target manifests cannot embed or name secret-bearing configuration",
                    path=f"{path}.{key}",
                )
            _reject_sensitive_configuration(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_sensitive_configuration(child, f"{path}[{index}]")


def target_manifest_from_mapping(value: dict[str, Any]) -> TargetManifest:
    """Construct a strict target manifest from untrusted JSON."""
    required = {
        "artifactType",
        "schemaVersion",
        "identifier",
        "kind",
        "version",
        "capabilities",
        "authorizationScope",
        "configuration",
    }
    if set(value) != required:
        raise FormatError(
            "SOVA-TARGET-FIELDS",
            "target manifest has missing or unknown fields",
            details={"fields": sorted(value)},
        )
    if value.get("artifactType") != "sova.target-manifest" or value.get("schemaVersion") != "0.1.0":
        raise FormatError(
            "SOVA-TARGET-VERSION", "target artifact type or schema version is unsupported"
        )
    capabilities = value.get("capabilities")
    configuration = value.get("configuration")
    if not isinstance(capabilities, list) or not all(
        isinstance(item, str) for item in capabilities
    ):
        raise FormatError("SOVA-TARGET-CAPABILITY", "target capabilities must be a string array")
    if not isinstance(configuration, dict):
        raise FormatError("SOVA-TARGET-CONFIG", "target configuration must be an object")
    try:
        kind = TargetKind(str(value.get("kind")))
    except ValueError as error:
        raise FormatError("SOVA-TARGET-KIND", "target kind is unsupported") from error
    return TargetManifest(
        str(value.get("identifier", "")),
        kind,
        str(value.get("version", "")),
        tuple(capabilities),
        str(value.get("authorizationScope", "")),
        configuration,
    )


def validate_target_manifest(manifest: TargetManifest) -> dict[str, Any]:
    required = _REQUIRED_CAPABILITIES[manifest.kind]
    missing = sorted(required - set(manifest.capabilities))
    trace_only_safe = manifest.kind != TargetKind.TRACE_ONLY or set(manifest.capabilities) == {
        "trace.import"
    }
    return {
        "artifactType": "sova.target-conformance",
        "targetDigest": manifest.digest,
        "accepted": not missing and trace_only_safe,
        "missingCapabilities": missing,
        "traceOnlyExecutionDisabled": trace_only_safe,
        "executorMechanicsEmbedded": False,
    }


__all__ = [
    "TargetKind",
    "TargetManifest",
    "target_manifest_from_mapping",
    "validate_target_manifest",
]
