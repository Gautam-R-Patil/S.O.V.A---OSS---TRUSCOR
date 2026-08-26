# SPDX-License-Identifier: Apache-2.0
"""Versioned, secret-free contracts for composite universal target intake."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, TypeVar
from urllib.parse import parse_qsl, urlsplit

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.targets import TargetManifest, target_manifest_from_mapping

PROFILE_SCHEMA_VERSION = "0.1.0"

_ID = re.compile(r"^[a-z0-9][a-z0-9._:/-]{0,190}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MEDIA_TYPE = re.compile(r"^[a-z0-9][a-z0-9.+-]{0,126}/[a-z0-9][a-z0-9.+-]{0,126}$")
_SECRET_REFERENCE = re.compile(r"^sova-secret:[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_SENSITIVE_KEY = re.compile(
    r"(?:^|[_-])(?:api[_-]?key|authorization|cookie|credential|password|secret|session|token)(?:$|[_-])",
    re.IGNORECASE,
)
_SECRET_VALUE = re.compile(
    r"(?:-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|"
    r"\b(?:Bearer|Basic)\s+[A-Za-z0-9+/_.=-]{8,}|"
    r"\bsk-[A-Za-z0-9_-]{20,}|\bgh[pousr]_[A-Za-z0-9_]{20,}|"
    r"\bxox[baprs]-[A-Za-z0-9-]{20,}|\bAKIA[A-Z0-9]{16}\b)",
    re.IGNORECASE,
)
_MAX_TEXT = 4096
_CONTROL_CHARACTER_LIMIT = 0x20
_T = TypeVar("_T")


class ProfileTargetKind(StrEnum):
    """Target classes that may coexist in one composite profile."""

    WEB = "web"
    API = "api"
    NETWORK = "network"
    SOURCE = "source"
    PACKAGE = "package"
    OCI = "oci"
    DESKTOP = "desktop"
    AI_MODEL = "ai-model"
    AGENT = "agent"
    MCP = "mcp"
    A2A = "a2a"
    THIRD_PARTY = "third-party-service"


class InputKind(StrEnum):
    """Supported supplied/static/passive/active input representations."""

    HTML = "html"
    WEB_INVENTORY = "web-inventory"
    HAR = "har"
    OPENAPI = "openapi"
    GRAPHQL_SCHEMA = "graphql-schema"
    GRPC_DESCRIPTOR = "grpc-descriptor"
    POSTMAN = "postman"
    SOURCE_TREE = "source-tree"
    ARCHIVE = "archive"
    SBOM = "sbom"
    LOCKFILE = "lockfile"
    OCI_MANIFEST = "oci-manifest"
    OCI_CONFIG = "oci-config"
    OCI_INVENTORY = "oci-inventory"
    NETWORK_INVENTORY = "network-inventory"
    TLS_REPORT = "tls-report"
    PROCESS_INVENTORY = "process-inventory"
    ACCESSIBILITY_TREE = "accessibility-tree"
    AGENT_MANIFEST = "agent-manifest"
    MCP_MANIFEST = "mcp-manifest"
    A2A_CARD = "a2a-card"
    RUNTIME_OBSERVATIONS = "runtime-observations"


class SourceClass(StrEnum):
    """How the supplied material was produced."""

    SUPPLIED = "supplied"
    STATIC = "static"
    PASSIVE = "passive"
    ACTIVE = "active"


class EntryPointKind(StrEnum):
    """Portable non-secret seeds for discovery."""

    URL = "url"
    API = "api"
    HOST = "host"
    CIDR = "cidr"
    PACKAGE = "package"
    PROCESS = "process"
    AGENT = "agent"
    MCP = "mcp"
    A2A = "a2a"


def _validated_identifier(value: str, *, code: str, role: str) -> str:
    if _ID.fullmatch(value) is None:
        raise FormatError(code, f"{role} identifier is invalid")
    return value


def _validated_text(value: str, *, code: str, role: str, allow_empty: bool = False) -> str:
    if (
        (not value and not allow_empty)
        or len(value) > _MAX_TEXT
        or any(ord(character) < _CONTROL_CHARACTER_LIMIT for character in value)
    ):
        raise FormatError(code, f"{role} text is invalid")
    if _SECRET_VALUE.search(value):
        raise FormatError(code, f"{role} contains secret-shaped material")
    return value


def _validate_safe_value(value: Any, *, path: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise FormatError(
                    "SOVA-INTAKE-SAFE-VALUE", "configuration keys must be strings", path=path
                )
            if _SENSITIVE_KEY.search(key):
                raise FormatError(
                    "SOVA-INTAKE-SECRET",
                    "target profiles cannot embed or name secret-bearing configuration",
                    path=f"{path}.{key}",
                )
            _validate_safe_value(child, path=f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _validate_safe_value(child, path=f"{path}[{index}]")
        return
    if isinstance(value, str):
        _validated_text(value, code="SOVA-INTAKE-SECRET", role=path, allow_empty=True)
        return
    if value is not None and not isinstance(value, (bool, int)):
        raise FormatError("SOVA-INTAKE-SAFE-VALUE", "unsupported configuration value", path=path)


def _validate_entry_locator(kind: EntryPointKind, locator: str) -> None:
    _validated_text(locator, code="SOVA-INTAKE-ENTRYPOINT", role="entrypoint")
    if kind in {EntryPointKind.URL, EntryPointKind.API, EntryPointKind.MCP, EntryPointKind.A2A}:
        parsed = urlsplit(locator)
        if parsed.scheme not in {"http", "https", "ws", "wss", "grpc", "grpcs"}:
            raise FormatError("SOVA-INTAKE-ENTRYPOINT", "network entrypoint scheme is unsupported")
        if parsed.hostname is None or parsed.username is not None or parsed.password is not None:
            raise FormatError(
                "SOVA-INTAKE-ENTRYPOINT", "network entrypoint requires a host and no user info"
            )
        for name, value in parse_qsl(parsed.query, keep_blank_values=True):
            if value or _SENSITIVE_KEY.search(name):
                raise FormatError(
                    "SOVA-INTAKE-ENTRYPOINT",
                    "portable entrypoints cannot embed query values or secret-like query names",
                )
    elif kind == EntryPointKind.CIDR:
        try:
            ipaddress.ip_network(locator, strict=False)
        except ValueError as error:
            raise FormatError("SOVA-INTAKE-ENTRYPOINT", "CIDR entrypoint is invalid") from error
    elif kind == EntryPointKind.HOST:
        if "/" in locator or "\\" in locator or "@" in locator:
            raise FormatError("SOVA-INTAKE-ENTRYPOINT", "host entrypoint is invalid")


@dataclass(frozen=True, slots=True)
class EntryPoint:
    """One inert, non-credential discovery seed."""

    id: str
    kind: EntryPointKind
    locator: str
    target_kinds: tuple[ProfileTargetKind, ...]

    def __post_init__(self) -> None:
        _validated_identifier(self.id, code="SOVA-INTAKE-ENTRYPOINT", role="entrypoint")
        _validate_entry_locator(self.kind, self.locator)
        if not self.target_kinds or len(set(self.target_kinds)) != len(self.target_kinds):
            raise FormatError(
                "SOVA-INTAKE-ENTRYPOINT", "entrypoint target kinds must be non-empty and unique"
            )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind.value,
            "locator": self.locator,
            "targetKinds": [item.value for item in self.target_kinds],
        }


@dataclass(frozen=True, slots=True)
class InputDescriptor:
    """Content-addressed material supplied separately from the portable profile."""

    id: str
    kind: InputKind
    source_class: SourceClass
    logical_locator: str
    media_type: str
    expected_digest: str
    required: bool = True

    def __post_init__(self) -> None:
        _validated_identifier(self.id, code="SOVA-INTAKE-INPUT", role="input")
        _validated_text(
            self.logical_locator,
            code="SOVA-INTAKE-INPUT",
            role="input logical locator",
        )
        if (
            "/" in self.logical_locator
            or "\\" in self.logical_locator
            or self.logical_locator in {".", ".."}
        ):
            raise FormatError(
                "SOVA-INTAKE-INPUT", "input logical locator must be one portable name"
            )
        if _MEDIA_TYPE.fullmatch(self.media_type) is None:
            raise FormatError("SOVA-INTAKE-INPUT", "input media type is invalid")
        if _DIGEST.fullmatch(self.expected_digest) is None:
            raise FormatError("SOVA-INTAKE-INPUT", "input requires an exact SHA-256 digest")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind.value,
            "sourceClass": self.source_class.value,
            "logicalLocator": self.logical_locator,
            "mediaType": self.media_type,
            "expectedDigest": self.expected_digest,
            "required": self.required,
        }


@dataclass(frozen=True, slots=True)
class CredentialReference:
    """Opaque secret broker reference; never a provider variable name or value."""

    reference: str
    purpose: str
    scopes: tuple[str, ...]
    required: bool = False

    def __post_init__(self) -> None:
        if _SECRET_REFERENCE.fullmatch(self.reference) is None:
            raise FormatError(
                "SOVA-INTAKE-CREDENTIAL-REFERENCE",
                "credential reference must use the sova-secret: opaque form",
            )
        _validated_text(
            self.purpose,
            code="SOVA-INTAKE-CREDENTIAL-REFERENCE",
            role="credential purpose",
        )
        if not self.scopes or len(set(self.scopes)) != len(self.scopes):
            raise FormatError(
                "SOVA-INTAKE-CREDENTIAL-REFERENCE",
                "credential scopes must be non-empty and unique",
            )
        for scope in self.scopes:
            _validated_identifier(
                scope, code="SOVA-INTAKE-CREDENTIAL-REFERENCE", role="credential scope"
            )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "reference": self.reference,
            "purpose": self.purpose,
            "scopes": sorted(self.scopes),
            "required": self.required,
        }


@dataclass(frozen=True, slots=True)
class EnvironmentConstraint:
    """Portable environment requirement without host paths or executable handles."""

    id: str
    platform: str
    architecture: str | None
    requirements: tuple[str, ...]

    def __post_init__(self) -> None:
        _validated_identifier(self.id, code="SOVA-INTAKE-ENVIRONMENT", role="environment")
        _validated_text(self.platform, code="SOVA-INTAKE-ENVIRONMENT", role="environment platform")
        if self.architecture is not None:
            _validated_text(
                self.architecture,
                code="SOVA-INTAKE-ENVIRONMENT",
                role="environment architecture",
            )
        if len(set(self.requirements)) != len(self.requirements):
            raise FormatError("SOVA-INTAKE-ENVIRONMENT", "environment requirements must be unique")
        for requirement in self.requirements:
            _validated_text(
                requirement,
                code="SOVA-INTAKE-ENVIRONMENT",
                role="environment requirement",
            )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "platform": self.platform,
            "architecture": self.architecture,
            "requirements": sorted(self.requirements),
        }


@dataclass(frozen=True, slots=True)
class TargetProfile:
    """Composite, content-addressed target intake contract."""

    identifier: str
    version: str
    title: str
    target_kinds: tuple[ProfileTargetKind, ...]
    authorization_scope: str
    entrypoints: tuple[EntryPoint, ...] = ()
    inputs: tuple[InputDescriptor, ...] = ()
    credential_references: tuple[CredentialReference, ...] = ()
    environments: tuple[EnvironmentConstraint, ...] = ()
    constraints: dict[str, Any] = field(default_factory=dict)
    provenance: tuple[dict[str, Any], ...] = ()
    legacy_target_manifest: TargetManifest | None = None
    extensions: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _validated_identifier(self.identifier, code="SOVA-INTAKE-PROFILE", role="profile")
        _validated_text(self.version, code="SOVA-INTAKE-PROFILE", role="profile version")
        _validated_text(self.title, code="SOVA-INTAKE-PROFILE", role="profile title")
        _validated_text(
            self.authorization_scope,
            code="SOVA-INTAKE-PROFILE",
            role="authorization scope",
        )
        if not self.target_kinds or len(set(self.target_kinds)) != len(self.target_kinds):
            raise FormatError(
                "SOVA-INTAKE-PROFILE", "profile target kinds must be non-empty and unique"
            )
        for role, values in (
            ("entrypoint", [item.id for item in self.entrypoints]),
            ("input", [item.id for item in self.inputs]),
            ("environment", [item.id for item in self.environments]),
            ("credential reference", [item.reference for item in self.credential_references]),
        ):
            if len(set(values)) != len(values):
                raise FormatError("SOVA-INTAKE-PROFILE", f"{role} values must be unique")
        if any(
            kind not in self.target_kinds
            for entrypoint in self.entrypoints
            for kind in entrypoint.target_kinds
        ):
            raise FormatError(
                "SOVA-INTAKE-PROFILE",
                "entrypoint target kind is not declared by the profile",
            )
        if self.legacy_target_manifest is not None and (
            self.legacy_target_manifest.authorization_scope != self.authorization_scope
        ):
            raise FormatError(
                "SOVA-INTAKE-PROFILE",
                "legacy target manifest authority must exactly match the profile",
            )
        _validate_safe_value(self.constraints, path="$.constraints")
        _validate_safe_value(list(self.provenance), path="$.provenance")
        _validate_safe_value(self.extensions, path="$.extensions")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.target-profile",
            "schemaVersion": PROFILE_SCHEMA_VERSION,
            "identifier": self.identifier,
            "version": self.version,
            "title": self.title,
            "targetKinds": [item.value for item in self.target_kinds],
            "authorizationScope": self.authorization_scope,
            "controlEvidenceRequired": True,
            "entrypoints": [item.to_mapping() for item in self.entrypoints],
            "inputs": [item.to_mapping() for item in self.inputs],
            "credentialReferences": [item.to_mapping() for item in self.credential_references],
            "environments": [item.to_mapping() for item in self.environments],
            "constraints": self.constraints,
            "provenance": list(self.provenance),
            "legacyTargetManifest": (
                None
                if self.legacy_target_manifest is None
                else self.legacy_target_manifest.to_mapping()
            ),
            "extensions": self.extensions,
        }

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))


def target_profile_from_mapping(value: dict[str, Any]) -> TargetProfile:
    """Parse an exact profile contract from untrusted JSON."""
    required = {
        "artifactType",
        "schemaVersion",
        "identifier",
        "version",
        "title",
        "targetKinds",
        "authorizationScope",
        "controlEvidenceRequired",
        "entrypoints",
        "inputs",
        "credentialReferences",
        "environments",
        "constraints",
        "provenance",
        "legacyTargetManifest",
        "extensions",
    }
    if set(value) != required:
        raise FormatError(
            "SOVA-INTAKE-PROFILE-FIELDS",
            "target profile has missing or unknown fields",
            details={"fields": sorted(value)},
        )
    if (
        value.get("artifactType") != "sova.target-profile"
        or value.get("schemaVersion") != PROFILE_SCHEMA_VERSION
        or value.get("controlEvidenceRequired") is not True
    ):
        raise FormatError(
            "SOVA-INTAKE-PROFILE-VERSION",
            "target profile type, schema version, or control requirement is unsupported",
        )
    raw_target_kinds = _object_list(value, "targetKinds", item_type=str)
    raw_entrypoints = _mapping_list(value, "entrypoints")
    raw_inputs = _mapping_list(value, "inputs")
    raw_credentials = _mapping_list(value, "credentialReferences")
    raw_environments = _mapping_list(value, "environments")
    raw_provenance = _mapping_list(value, "provenance")
    constraints = value.get("constraints")
    extensions = value.get("extensions")
    if not isinstance(constraints, dict) or not isinstance(extensions, dict):
        raise FormatError(
            "SOVA-INTAKE-PROFILE-FIELDS", "constraints and extensions must be objects"
        )
    try:
        target_kinds = tuple(ProfileTargetKind(str(item)) for item in raw_target_kinds)
        entrypoints = tuple(
            EntryPoint(
                id=_required_string(item, "id"),
                kind=EntryPointKind(_required_string(item, "kind")),
                locator=_required_string(item, "locator"),
                target_kinds=tuple(
                    ProfileTargetKind(str(kind))
                    for kind in _object_list(item, "targetKinds", item_type=str)
                ),
            )
            for item in raw_entrypoints
        )
        inputs = tuple(
            InputDescriptor(
                id=_required_string(item, "id"),
                kind=InputKind(_required_string(item, "kind")),
                source_class=SourceClass(_required_string(item, "sourceClass")),
                logical_locator=_required_string(item, "logicalLocator"),
                media_type=_required_string(item, "mediaType"),
                expected_digest=_required_string(item, "expectedDigest"),
                required=_required_bool(item, "required"),
            )
            for item in raw_inputs
        )
        credentials = tuple(
            CredentialReference(
                reference=_required_string(item, "reference"),
                purpose=_required_string(item, "purpose"),
                scopes=tuple(_object_list(item, "scopes", item_type=str)),
                required=_required_bool(item, "required"),
            )
            for item in raw_credentials
        )
        environments = tuple(
            EnvironmentConstraint(
                id=_required_string(item, "id"),
                platform=_required_string(item, "platform"),
                architecture=_optional_string(item, "architecture"),
                requirements=tuple(_object_list(item, "requirements", item_type=str)),
            )
            for item in raw_environments
        )
    except ValueError as error:
        raise FormatError(
            "SOVA-INTAKE-PROFILE-ENUM", "target profile contains an unsupported enum value"
        ) from error
    legacy = value.get("legacyTargetManifest")
    if legacy is not None and not isinstance(legacy, dict):
        raise FormatError(
            "SOVA-INTAKE-PROFILE-FIELDS", "legacy target manifest must be an object or null"
        )
    return TargetProfile(
        identifier=_required_string(value, "identifier"),
        version=_required_string(value, "version"),
        title=_required_string(value, "title"),
        target_kinds=target_kinds,
        authorization_scope=_required_string(value, "authorizationScope"),
        entrypoints=entrypoints,
        inputs=inputs,
        credential_references=credentials,
        environments=environments,
        constraints=constraints,
        provenance=tuple(raw_provenance),
        legacy_target_manifest=None if legacy is None else target_manifest_from_mapping(legacy),
        extensions=extensions,
    )


def validate_target_profile(profile: TargetProfile) -> dict[str, Any]:
    """Return a deterministic conformance report without loading any target material."""
    input_kinds = {item.kind for item in profile.inputs}
    required_inputs = {item.id for item in profile.inputs if item.required}
    declared_surfaces = set(profile.target_kinds)
    supported = _target_kinds_supported_by_inputs(input_kinds, profile.entrypoints)
    missing_evidence = sorted(item.value for item in declared_surfaces - supported)
    return {
        "artifactType": "sova.target-profile-conformance",
        "schemaVersion": PROFILE_SCHEMA_VERSION,
        "profileDigest": profile.digest,
        "accepted": True,
        "declaredTargetKinds": sorted(item.value for item in declared_surfaces),
        "requiredInputIds": sorted(required_inputs),
        "targetKindsWithoutDiscoveryMaterial": missing_evidence,
        "partialDiscoveryExpected": bool(missing_evidence),
        "controlEvidenceRequired": True,
        "secretMaterialEmbedded": False,
        "executorMechanicsEmbedded": False,
    }


def target_profile_template(
    *,
    identifier: str,
    title: str,
    target_kinds: tuple[ProfileTargetKind, ...],
    authorization_scope: str,
) -> TargetProfile:
    """Create a valid empty profile that makes incomplete discovery explicit."""
    return TargetProfile(
        identifier=identifier,
        version=PROFILE_SCHEMA_VERSION,
        title=title,
        target_kinds=target_kinds,
        authorization_scope=authorization_scope,
        constraints={
            "networkCollectionDefault": "disabled",
            "effectfulCollectionRequiresFreshAuthorization": True,
        },
        provenance=(
            {
                "source": "operator-authored",
                "evidenceClass": "declared",
            },
        ),
    )


def _target_kinds_supported_by_inputs(
    kinds: set[InputKind], entrypoints: tuple[EntryPoint, ...]
) -> set[ProfileTargetKind]:
    supported = {kind for entrypoint in entrypoints for kind in entrypoint.target_kinds}
    mapping = {
        InputKind.HTML: {ProfileTargetKind.WEB},
        InputKind.WEB_INVENTORY: {ProfileTargetKind.WEB},
        InputKind.HAR: {ProfileTargetKind.WEB, ProfileTargetKind.API},
        InputKind.OPENAPI: {ProfileTargetKind.API},
        InputKind.GRAPHQL_SCHEMA: {ProfileTargetKind.API},
        InputKind.GRPC_DESCRIPTOR: {ProfileTargetKind.API},
        InputKind.POSTMAN: {ProfileTargetKind.API},
        InputKind.SOURCE_TREE: {ProfileTargetKind.SOURCE, ProfileTargetKind.PACKAGE},
        InputKind.ARCHIVE: {ProfileTargetKind.SOURCE, ProfileTargetKind.PACKAGE},
        InputKind.SBOM: {ProfileTargetKind.PACKAGE, ProfileTargetKind.OCI},
        InputKind.LOCKFILE: {ProfileTargetKind.PACKAGE},
        InputKind.OCI_MANIFEST: {ProfileTargetKind.OCI},
        InputKind.OCI_CONFIG: {ProfileTargetKind.OCI},
        InputKind.OCI_INVENTORY: {ProfileTargetKind.OCI},
        InputKind.NETWORK_INVENTORY: {ProfileTargetKind.NETWORK},
        InputKind.TLS_REPORT: {ProfileTargetKind.NETWORK, ProfileTargetKind.WEB},
        InputKind.PROCESS_INVENTORY: {ProfileTargetKind.DESKTOP},
        InputKind.ACCESSIBILITY_TREE: {ProfileTargetKind.DESKTOP},
        InputKind.AGENT_MANIFEST: {ProfileTargetKind.AGENT, ProfileTargetKind.AI_MODEL},
        InputKind.MCP_MANIFEST: {ProfileTargetKind.MCP, ProfileTargetKind.AGENT},
        InputKind.A2A_CARD: {ProfileTargetKind.A2A, ProfileTargetKind.AGENT},
        InputKind.RUNTIME_OBSERVATIONS: set(ProfileTargetKind),
    }
    for kind in kinds:
        supported.update(mapping[kind])
    return supported


def _required_string(value: dict[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str):
        raise FormatError("SOVA-INTAKE-PROFILE-FIELDS", f"{key} must be a string")
    return item


def _optional_string(value: dict[str, Any], key: str) -> str | None:
    item = value.get(key)
    if item is not None and not isinstance(item, str):
        raise FormatError("SOVA-INTAKE-PROFILE-FIELDS", f"{key} must be a string or null")
    return item


def _required_bool(value: dict[str, Any], key: str) -> bool:
    item = value.get(key)
    if not isinstance(item, bool):
        raise FormatError("SOVA-INTAKE-PROFILE-FIELDS", f"{key} must be a boolean")
    return item


def _mapping_list(value: dict[str, Any], key: str) -> list[dict[str, Any]]:
    raw = value.get(key)
    if not isinstance(raw, list) or not all(isinstance(item, dict) for item in raw):
        raise FormatError("SOVA-INTAKE-PROFILE-FIELDS", f"{key} must be an object array")
    return raw


def _object_list(value: dict[str, Any], key: str, *, item_type: type[_T]) -> list[_T]:
    raw = value.get(key)
    if not isinstance(raw, list) or not all(isinstance(item, item_type) for item in raw):
        raise FormatError("SOVA-INTAKE-PROFILE-FIELDS", f"{key} has an invalid array type")
    return raw


__all__ = [
    "PROFILE_SCHEMA_VERSION",
    "CredentialReference",
    "EntryPoint",
    "EntryPointKind",
    "EnvironmentConstraint",
    "InputDescriptor",
    "InputKind",
    "ProfileTargetKind",
    "SourceClass",
    "TargetProfile",
    "target_profile_from_mapping",
    "target_profile_template",
    "validate_target_profile",
]
