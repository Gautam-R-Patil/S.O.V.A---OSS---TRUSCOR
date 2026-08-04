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
        if self.configuration.get("secret") is not None:
            raise FormatError("SOVA-TARGET-SECRET", "target manifests cannot embed secret values")

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
