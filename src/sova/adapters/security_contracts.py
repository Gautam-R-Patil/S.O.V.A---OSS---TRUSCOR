# SPDX-License-Identifier: Apache-2.0
"""Strict contracts for policy-routed external security-tool adapters.

External tools are evidence producers, never SOVA's authorization, judging, or
finding trust root.  These contracts deliberately keep tool assertions,
infrastructure outcomes, and promoted findings as different types of state.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,127}$")
_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MEDIA_TYPE = re.compile(r"^[a-z0-9][a-z0-9.+-]*/[a-z0-9][a-z0-9.+-]*$")
_PLATFORMS = frozenset({"linux", "macos", "windows"})
_MAX_TIMEOUT_SECONDS = 3600
_MIN_OUTPUT_BYTES = 1024
_MAX_OUTPUT_BYTES = 64 * 1024 * 1024
_MAX_FINDINGS = 100_000
_MAX_PROCESSES = 1024
_MAX_EXIT_CODE = 255


class AdapterAdmission(StrEnum):
    """The highest policy tier granted to an adapter descriptor."""

    PROMOTED = "promoted"
    CONSTRAINED = "constrained"
    LEGAL_HOLD = "legal-hold"


class AdapterTransport(StrEnum):
    """How an adapter reaches the external producer."""

    PROCESS = "process"
    MCP_STDIO = "mcp-stdio"
    HTTP = "http"


class OutputSource(StrEnum):
    """Bounded location from which raw output may be admitted."""

    STDOUT = "stdout"
    WORKSPACE_FILE = "workspace-file"


class ObservationState(StrEnum):
    """State of one normalized assertion without pretending it is a finding."""

    TOOL_ASSERTED_FAILURE = "tool-asserted-failure"
    TOOL_ASSERTED_PASS = "tool-asserted-pass"  # noqa: S105 - observation state, not a secret
    INFORMATIONAL = "informational"
    INCONCLUSIVE = "inconclusive"
    INFRASTRUCTURE_FAILURE = "infrastructure-failure"


class ExternalTrust(StrEnum):
    """Trust assigned to externally supplied schemas, summaries, and evidence."""

    UNTRUSTED = "untrusted"
    SOVA_VALIDATED = "sova-validated"


@dataclass(frozen=True, slots=True)
class ExternalTransferRequest:
    """Exact human-reviewed disclosure proposed to an external destination."""

    target_id: str
    destination: str
    purpose: str
    data_classes: tuple[str, ...]
    authorization_reference: str
    human_reviewed: bool
    retention_reviewed: bool
    contains_unredacted_secrets: bool = False

    def __post_init__(self) -> None:
        required = (
            self.target_id,
            self.destination,
            self.purpose,
            self.authorization_reference,
        )
        if any(not value or "\x00" in value for value in required):
            raise FormatError("SOVA-ADAPTER-DISCLOSURE", "transfer request is incomplete")
        if not self.data_classes or any(not value for value in self.data_classes):
            raise FormatError("SOVA-ADAPTER-DISCLOSURE", "transfer data classes are required")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "targetId": self.target_id,
            "destination": self.destination,
            "purpose": self.purpose,
            "dataClasses": list(self.data_classes),
            "authorizationReference": self.authorization_reference,
            "humanReviewed": self.human_reviewed,
            "retentionReviewed": self.retention_reviewed,
            "containsUnredactedSecrets": self.contains_unredacted_secrets,
        }

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))


@dataclass(frozen=True, slots=True)
class ExternalTransferDecision:
    """Fail-closed decision binding one destination and disclosed data set."""

    identifier: str
    allowed: bool
    request_digest: str
    target_id: str
    destination: str
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.identifier.startswith("sova:disclosure:"):
            raise FormatError("SOVA-ADAPTER-DISCLOSURE", "disclosure decision ID is invalid")
        if _DIGEST.fullmatch(self.request_digest) is None:
            raise FormatError("SOVA-ADAPTER-DISCLOSURE", "disclosure request digest is invalid")
        if self.allowed == bool(self.reasons):
            raise FormatError(
                "SOVA-ADAPTER-DISCLOSURE",
                "allowed decisions have no reasons and denied decisions name reasons",
            )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "id": self.identifier,
            "allowed": self.allowed,
            "requestDigest": self.request_digest,
            "targetId": self.target_id,
            "destination": self.destination,
            "reasons": list(self.reasons),
            "method": "sova.adapter-disclosure-gate/0.1",
        }

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))


class ExternalTransferGate:
    """Review external data transfer separately from target authorization."""

    def assess(self, request: ExternalTransferRequest) -> ExternalTransferDecision:
        reasons: list[str] = []
        if not request.human_reviewed:
            reasons.append("human-transfer-review-required")
        if not request.retention_reviewed:
            reasons.append("destination-retention-review-required")
        if request.contains_unredacted_secrets:
            reasons.append("unredacted-secrets-prohibited")
        return ExternalTransferDecision(
            identifier=f"sova:disclosure:{request.digest[7:31]}",
            allowed=not reasons,
            request_digest=request.digest,
            target_id=request.target_id,
            destination=request.destination,
            reasons=tuple(reasons),
        )


@dataclass(frozen=True, slots=True)
class ResourceBounds:
    """Portable ceilings imposed before an external tool is considered runnable."""

    timeout_seconds: int
    max_output_bytes: int
    max_findings: int
    max_processes: int = 1
    max_network_requests: int = 0

    def __post_init__(self) -> None:
        if not 1 <= self.timeout_seconds <= _MAX_TIMEOUT_SECONDS:
            raise FormatError("SOVA-ADAPTER-BOUNDS", "timeout must be between 1 and 3600 seconds")
        if not _MIN_OUTPUT_BYTES <= self.max_output_bytes <= _MAX_OUTPUT_BYTES:
            raise FormatError(
                "SOVA-ADAPTER-BOUNDS",
                "output limit must be between 1 KiB and 64 MiB",
            )
        if not 1 <= self.max_findings <= _MAX_FINDINGS:
            raise FormatError("SOVA-ADAPTER-BOUNDS", "finding limit is outside the safe range")
        if not 1 <= self.max_processes <= _MAX_PROCESSES or self.max_network_requests < 0:
            raise FormatError("SOVA-ADAPTER-BOUNDS", "process or network bound is invalid")


@dataclass(frozen=True, slots=True)
class PrivacyDefaults:
    """Fail-closed defaults applied to every external integration."""

    telemetry: bool = False
    remote_generation: bool = False
    uploads: bool = False
    implicit_pulls: bool = False
    auto_update: bool = False
    unreviewed_templates: bool = False
    external_transfer_requires_disclosure_gate: bool = True

    def __post_init__(self) -> None:
        if (
            any(
                (
                    self.telemetry,
                    self.remote_generation,
                    self.uploads,
                    self.implicit_pulls,
                    self.auto_update,
                    self.unreviewed_templates,
                )
            )
            or not self.external_transfer_requires_disclosure_gate
        ):
            raise FormatError(
                "SOVA-ADAPTER-PRIVACY",
                "adapter defaults must disable external disclosure and implicit updates",
            )


@dataclass(frozen=True, slots=True)
class AdapterDescriptor:
    """Immutable admission record for one exact external-tool integration."""

    identifier: str
    tool_name: str
    tool_version: str
    executable_names: tuple[str, ...]
    executable_digest_policy: str
    license_expression: str
    source_url: str
    release_url: str
    platforms: tuple[str, ...]
    target_predicates: tuple[str, ...]
    capabilities: tuple[str, ...]
    required_effect: str
    network_requirement: str
    transport: AdapterTransport
    parser_id: str
    parser_version: str
    output_media_types: tuple[str, ...]
    output_source: OutputSource
    argv_template: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    accepted_result_exit_codes: tuple[int, ...]
    bounds: ResourceBounds
    admission: AdapterAdmission
    provenance: tuple[str, ...]
    limitations: tuple[str, ...]
    privacy: PrivacyDefaults = field(default_factory=PrivacyDefaults)
    ruleset_pin: str | None = None
    config_pin: str | None = None
    legal_note: str | None = None

    def __post_init__(self) -> None:  # noqa: PLR0912 - contract checks are intentionally explicit
        if _IDENTIFIER.fullmatch(self.identifier) is None or not self.identifier.startswith(
            "adapter."
        ):
            raise FormatError("SOVA-ADAPTER-ID", "adapter identifier is not valid")
        if not self.tool_name or _VERSION.fullmatch(self.tool_version) is None:
            raise FormatError("SOVA-ADAPTER-TOOL", "tool name or exact version is invalid")
        if not self.executable_names or any(
            not name or "/" in name or "\\" in name for name in self.executable_names
        ):
            raise FormatError("SOVA-ADAPTER-EXECUTABLE", "executable names must be bare names")
        if self.executable_digest_policy != "runtime-sha256-required":
            raise FormatError(
                "SOVA-ADAPTER-DIGEST-POLICY",
                "the exact operator-supplied executable must be SHA-256 bound at runtime",
            )
        if not self.license_expression or not self.source_url.startswith("https://"):
            raise FormatError("SOVA-ADAPTER-PROVENANCE", "licence and HTTPS source are required")
        if not self.release_url.startswith("https://"):
            raise FormatError("SOVA-ADAPTER-PROVENANCE", "an HTTPS release source is required")
        if not self.platforms or not set(self.platforms) <= _PLATFORMS:
            raise FormatError("SOVA-ADAPTER-PLATFORM", "descriptor platforms are invalid")
        required_sequences = (
            self.target_predicates,
            self.capabilities,
            self.output_media_types,
            self.provenance,
            self.limitations,
        )
        if any(not values or any(not value for value in values) for values in required_sequences):
            raise FormatError("SOVA-ADAPTER-DESCRIPTOR", "required descriptor lists are empty")
        if any(_MEDIA_TYPE.fullmatch(value) is None for value in self.output_media_types):
            raise FormatError("SOVA-ADAPTER-MEDIA", "output media type is invalid")
        if self.required_effect not in {"read", "mutate", "external", "destructive"}:
            raise FormatError("SOVA-ADAPTER-EFFECT", "required effect is invalid")
        if self.network_requirement not in {"none", "target-only", "provider", "internet"}:
            raise FormatError("SOVA-ADAPTER-NETWORK", "network requirement is invalid")
        if not self.parser_id or _VERSION.fullmatch(self.parser_version) is None:
            raise FormatError("SOVA-ADAPTER-PARSER", "parser identity is invalid")
        placeholders = {"{executable}", "{target}", "{output}", "{config}", "{ruleset}"}
        if not self.argv_template or self.argv_template[0] != "{executable}":
            raise FormatError("SOVA-ADAPTER-ARGV", "argv template must start with the executable")
        for argument in self.argv_template:
            for token in re.findall(r"\{[^{}]+\}", argument):
                if token not in placeholders:
                    raise FormatError("SOVA-ADAPTER-ARGV", "argv template has an unknown token")
        if self.admission == AdapterAdmission.LEGAL_HOLD and not self.legal_note:
            raise FormatError("SOVA-ADAPTER-LEGAL-HOLD", "legal hold requires a reason")
        if self.ruleset_pin is not None and not self.ruleset_pin:
            raise FormatError("SOVA-ADAPTER-PIN", "ruleset pin cannot be empty")
        if self.config_pin is not None and not self.config_pin:
            raise FormatError("SOVA-ADAPTER-PIN", "configuration pin cannot be empty")
        if len({name for name, _value in self.environment}) != len(self.environment):
            raise FormatError("SOVA-ADAPTER-ENVIRONMENT", "environment keys must be unique")
        if (
            not self.accepted_result_exit_codes
            or 0 not in self.accepted_result_exit_codes
            or any(
                isinstance(code, bool)
                or not isinstance(code, int)
                or not 0 <= code <= _MAX_EXIT_CODE
                for code in self.accepted_result_exit_codes
            )
        ):
            raise FormatError(
                "SOVA-ADAPTER-EXIT-CODE",
                "accepted result exit codes must include zero and be byte-sized integers",
            )

    def to_mapping(self) -> dict[str, Any]:
        """Return the public, schema-valid descriptor mapping."""
        return {
            "artifactType": "sova.adapter-descriptor",
            "schemaVersion": "0.1.0",
            "id": self.identifier,
            "tool": {
                "name": self.tool_name,
                "version": self.tool_version,
                "executableNames": list(self.executable_names),
                "executableDigestPolicy": self.executable_digest_policy,
                "license": self.license_expression,
                "source": self.source_url,
                "release": self.release_url,
            },
            "platforms": list(self.platforms),
            "targetPredicates": list(self.target_predicates),
            "capabilities": list(self.capabilities),
            "requirements": {
                "effect": self.required_effect,
                "network": self.network_requirement,
                "transport": self.transport.value,
            },
            "output": {
                "parserId": self.parser_id,
                "parserVersion": self.parser_version,
                "mediaTypes": list(self.output_media_types),
                "source": self.output_source.value,
            },
            "execution": {
                "argvTemplate": list(self.argv_template),
                "environment": dict(self.environment),
                "acceptedResultExitCodes": list(self.accepted_result_exit_codes),
                "bounds": {
                    "timeoutSeconds": self.bounds.timeout_seconds,
                    "maxOutputBytes": self.bounds.max_output_bytes,
                    "maxFindings": self.bounds.max_findings,
                    "maxProcesses": self.bounds.max_processes,
                    "maxNetworkRequests": self.bounds.max_network_requests,
                },
            },
            "admission": self.admission.value,
            "provenance": list(self.provenance),
            "limitations": list(self.limitations),
            "privacyDefaults": {
                "telemetry": self.privacy.telemetry,
                "remoteGeneration": self.privacy.remote_generation,
                "uploads": self.privacy.uploads,
                "implicitPulls": self.privacy.implicit_pulls,
                "autoUpdate": self.privacy.auto_update,
                "unreviewedTemplates": self.privacy.unreviewed_templates,
                "externalTransferRequiresDisclosureGate": (
                    self.privacy.external_transfer_requires_disclosure_gate
                ),
            },
            "pins": {"ruleset": self.ruleset_pin, "config": self.config_pin},
            "legalNote": self.legal_note,
        }

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))


@dataclass(frozen=True, slots=True)
class AdapterInvocation:
    """Target- and policy-bound values allowed to fill one descriptor template."""

    identifier: str
    descriptor_id: str
    target_id: str
    target: str
    target_predicate: str
    target_profile_digest: str
    target_generation: str
    executable_path: str
    observed_tool_version: str
    version_evidence_digest: str
    output_path: str | None = None
    config_path: str | None = None
    config_digest: str | None = None
    ruleset_path: str | None = None
    ruleset_digest: str | None = None
    disclosure_gate_id: str | None = None
    disclosure_gate_digest: str | None = None

    def __post_init__(self) -> None:
        if _IDENTIFIER.fullmatch(self.identifier) is None:
            raise FormatError("SOVA-ADAPTER-INVOCATION", "invocation identifier is invalid")
        if not all(
            (
                self.descriptor_id,
                self.target_id,
                self.target,
                self.target_predicate,
                self.executable_path,
                self.observed_tool_version,
            )
        ):
            raise FormatError("SOVA-ADAPTER-INVOCATION", "invocation binding is incomplete")
        for digest in (
            self.target_profile_digest,
            self.target_generation,
            self.version_evidence_digest,
            self.config_digest,
            self.ruleset_digest,
            self.disclosure_gate_digest,
        ):
            if digest is not None and _DIGEST.fullmatch(digest) is None:
                raise FormatError("SOVA-ADAPTER-DIGEST", "invocation digest is invalid")
        for path in (self.output_path, self.config_path, self.ruleset_path):
            if path is not None and (not path or "\x00" in path):
                raise FormatError("SOVA-ADAPTER-PATH", "invocation path is invalid")
        if (self.config_path is None) != (self.config_digest is None) or (
            self.ruleset_path is None
        ) != (self.ruleset_digest is None):
            raise FormatError(
                "SOVA-ADAPTER-PIN",
                "configuration and ruleset paths require matching digests",
            )
        if self.disclosure_gate_id is not None and not self.disclosure_gate_id:
            raise FormatError("SOVA-ADAPTER-DISCLOSURE-GATE", "disclosure gate cannot be empty")
        if (self.disclosure_gate_id is None) != (self.disclosure_gate_digest is None):
            raise FormatError(
                "SOVA-ADAPTER-DISCLOSURE-GATE",
                "disclosure gate ID and decision digest must be supplied together",
            )


@dataclass(frozen=True, slots=True)
class RawArtifact:
    """Bounded immutable bytes and their capture status."""

    digest: str
    media_type: str
    size: int
    complete: bool
    source: OutputSource

    def __post_init__(self) -> None:
        if _DIGEST.fullmatch(self.digest) is None or self.size < 0:
            raise FormatError("SOVA-ADAPTER-RAW", "raw artifact identity is invalid")
        if _MEDIA_TYPE.fullmatch(self.media_type) is None:
            raise FormatError("SOVA-ADAPTER-RAW", "raw artifact media type is invalid")


@dataclass(frozen=True, slots=True)
class NormalizedObservation:
    """One tool assertion whose evidence and trust boundaries remain explicit."""

    identifier: str
    adapter_id: str
    adapter_digest: str
    tool_version: str
    executable_digest: str
    parser_id: str
    parser_version: str
    target_id: str
    target_profile_digest: str
    target_generation: str
    raw: RawArtifact
    state: ObservationState
    rule_id: str
    title: str
    severity: str
    confidence: str
    location: str | None
    stable_fingerprint: str
    metadata: dict[str, Any] = field(default_factory=dict)
    config_digest: str | None = None
    ruleset_digest: str | None = None
    finding_confirmed: bool = False
    independently_reproduced: bool = False
    schema_trust: ExternalTrust = ExternalTrust.UNTRUSTED
    summary_trust: ExternalTrust = ExternalTrust.UNTRUSTED
    evidence_trust: ExternalTrust = ExternalTrust.UNTRUSTED

    def __post_init__(self) -> None:
        for digest in (
            self.adapter_digest,
            self.executable_digest,
            self.target_profile_digest,
            self.target_generation,
            self.stable_fingerprint,
            self.config_digest,
            self.ruleset_digest,
        ):
            if digest is not None and _DIGEST.fullmatch(digest) is None:
                raise FormatError("SOVA-ADAPTER-OBSERVATION", "observation digest is invalid")
        if self.finding_confirmed or self.independently_reproduced:
            raise FormatError(
                "SOVA-ADAPTER-TRUST",
                "normalization cannot confirm a finding or independent reproduction",
            )
        if self.severity not in {"unknown", "info", "low", "medium", "high", "critical"}:
            raise FormatError("SOVA-ADAPTER-SEVERITY", "normalized severity is invalid")
        if self.confidence not in {"unknown", "low", "medium", "high"}:
            raise FormatError("SOVA-ADAPTER-CONFIDENCE", "normalized confidence is invalid")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.normalized-observation",
            "schemaVersion": "0.1.0",
            "id": self.identifier,
            "adapter": {
                "id": self.adapter_id,
                "digest": self.adapter_digest,
                "toolVersion": self.tool_version,
                "executableDigest": self.executable_digest,
            },
            "parser": {"id": self.parser_id, "version": self.parser_version},
            "target": {
                "id": self.target_id,
                "profileDigest": self.target_profile_digest,
                "generation": self.target_generation,
            },
            "raw": {
                "digest": self.raw.digest,
                "mediaType": self.raw.media_type,
                "size": self.raw.size,
                "complete": self.raw.complete,
                "source": self.raw.source.value,
            },
            "assertion": {
                "state": self.state.value,
                "ruleId": self.rule_id,
                "title": self.title,
                "severity": self.severity,
                "confidence": self.confidence,
                "location": self.location,
                "metadata": self.metadata,
            },
            "pins": {"configDigest": self.config_digest, "rulesetDigest": self.ruleset_digest},
            "trust": {
                "schema": self.schema_trust.value,
                "summary": self.summary_trust.value,
                "evidence": self.evidence_trust.value,
            },
            "stableFingerprint": self.stable_fingerprint,
            "findingConfirmed": self.finding_confirmed,
            "independentlyReproduced": self.independently_reproduced,
        }


@dataclass(frozen=True, slots=True)
class AdapterRunReport:
    """Terminal runner result with explicit infrastructure and cleanup state."""

    invocation_id: str
    descriptor_id: str
    descriptor_digest: str
    executable_digest: str
    outcome_status: str
    infrastructure_failure: bool
    cleanup_verified: bool
    trace_path: str
    trace_digest: str
    raw_artifact: RawArtifact | None
    observations: tuple[NormalizedObservation, ...]
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for digest in (self.descriptor_digest, self.executable_digest, self.trace_digest):
            if _DIGEST.fullmatch(digest) is None:
                raise FormatError("SOVA-ADAPTER-REPORT", "run report digest is invalid")
        allowed = {"completed", "denied", "infrastructure-failure", "cleanup-failed"}
        if self.outcome_status not in allowed:
            raise FormatError("SOVA-ADAPTER-REPORT", "run report outcome is invalid")
        if self.outcome_status == "completed" and self.infrastructure_failure:
            raise FormatError(
                "SOVA-ADAPTER-REPORT", "completed run cannot be infrastructure failure"
            )
        if not self.cleanup_verified and self.outcome_status != "cleanup-failed":
            raise FormatError("SOVA-ADAPTER-REPORT", "cleanup failure must be terminal")
        if len(set(self.limitations)) != len(self.limitations):
            raise FormatError("SOVA-ADAPTER-REPORT", "report limitations must be unique")
        if any(
            observation.adapter_id != self.descriptor_id
            or observation.adapter_digest != self.descriptor_digest
            or observation.executable_digest != self.executable_digest
            for observation in self.observations
        ):
            raise FormatError("SOVA-ADAPTER-REPORT", "observation bindings do not match the run")

    def to_mapping(self) -> dict[str, Any]:
        raw = None
        if self.raw_artifact is not None:
            raw = {
                "digest": self.raw_artifact.digest,
                "mediaType": self.raw_artifact.media_type,
                "size": self.raw_artifact.size,
                "complete": self.raw_artifact.complete,
                "source": self.raw_artifact.source.value,
            }
        return {
            "artifactType": "sova.adapter-run-report",
            "schemaVersion": "0.1.0",
            "invocationId": self.invocation_id,
            "descriptor": {"id": self.descriptor_id, "digest": self.descriptor_digest},
            "executableDigest": self.executable_digest,
            "outcomeStatus": self.outcome_status,
            "infrastructureFailure": self.infrastructure_failure,
            "cleanupVerified": self.cleanup_verified,
            "trace": {"path": self.trace_path, "digest": self.trace_digest},
            "rawArtifact": raw,
            "observations": [item.to_mapping() for item in self.observations],
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True, slots=True)
class ExternalToolEnvelope:
    """Generic MCP/stdio/HTTP result envelope with no inherited trust."""

    transport: AdapterTransport
    producer: str
    raw_digest: str
    schema: dict[str, Any] | None
    summary: str | None
    evidence_references: tuple[str, ...]
    schema_trust: ExternalTrust = ExternalTrust.UNTRUSTED
    summary_trust: ExternalTrust = ExternalTrust.UNTRUSTED
    evidence_trust: ExternalTrust = ExternalTrust.UNTRUSTED

    def __post_init__(self) -> None:
        if self.transport == AdapterTransport.PROCESS:
            raise FormatError("SOVA-ADAPTER-EXTERNAL", "generic envelope requires stdio or HTTP")
        if not self.producer or _DIGEST.fullmatch(self.raw_digest) is None:
            raise FormatError("SOVA-ADAPTER-EXTERNAL", "generic envelope identity is invalid")
        if any(
            trust != ExternalTrust.UNTRUSTED
            for trust in (self.schema_trust, self.summary_trust, self.evidence_trust)
        ):
            raise FormatError(
                "SOVA-ADAPTER-EXTERNAL-TRUST",
                "external schema, summary, and evidence begin untrusted",
            )


def semantic_fingerprint(
    *,
    adapter_id: str,
    target_id: str,
    rule_id: str,
    state: ObservationState,
    location: str | None,
) -> str:
    """Stable comparison key that excludes run IDs and raw artifact identity."""
    return sha256_digest(
        canonical_json_bytes(
            {
                "adapterId": adapter_id,
                "targetId": target_id,
                "ruleId": rule_id,
                "state": state.value,
                "location": location,
            }
        )
    )


__all__ = [
    "AdapterAdmission",
    "AdapterDescriptor",
    "AdapterInvocation",
    "AdapterRunReport",
    "AdapterTransport",
    "ExternalToolEnvelope",
    "ExternalTransferDecision",
    "ExternalTransferGate",
    "ExternalTransferRequest",
    "ExternalTrust",
    "NormalizedObservation",
    "ObservationState",
    "OutputSource",
    "PrivacyDefaults",
    "RawArtifact",
    "ResourceBounds",
    "semantic_fingerprint",
]
