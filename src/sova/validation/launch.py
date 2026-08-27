# SPDX-License-Identifier: Apache-2.0
"""Signed, exact-candidate P6 launch evidence ingestion and fail-closed dossiering."""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from sova.formats import (
    canonical_json_bytes,
    sha256_digest,
    strict_json_loads,
    validate_document,
)
from sova.formats.errors import FormatError
from sova.trace import sign_dsse_payload, verify_dsse_payload
from sova.trace.integrity import Ed25519Keypair
from sova.validation.contracts import (
    BlindedTarget,
    EvaluationBudget,
    EvaluationLane,
    EvaluationProtocol,
    LaneKind,
    ObservationStatus,
    TargetClass,
)
from sova.validation.gates import (
    OperationalReceipt,
    RegistryBetaPolicy,
    RegistryControl,
    ReleaseCandidate,
    ReviewGate,
    ReviewReceipt,
    evaluate_registry_beta,
    evaluate_release_candidate,
)
from sova.validation.ledger import EvaluationObservation, evaluate_blinded_protocol

if TYPE_CHECKING:
    from collections.abc import Mapping

LAUNCH_EVIDENCE_PAYLOAD_TYPE = "application/vnd.sova.launch-evidence+json"
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_RFC3339_UTC = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_MAX_BUNDLE_BYTES = 32 * 1024 * 1024
_MAX_BUNDLE_ITEMS = 500_000
_RAW_ED25519_KEY_BYTES = 32


class LaunchRole(StrEnum):
    EVALUATION_CUSTODIAN = "evaluation-custodian"
    REGISTRY_OPERATOR = "registry-operator"
    P5_OPERATOR = "p5-isolation-operator"
    RELEASE_OPERATOR = "release-operator"
    FOUNDER = "founder"
    INDEPENDENT_TECHNICAL = "independent-technical"
    INDEPENDENT_ISOLATION = "independent-isolation"
    LEGAL = "legal-license-public-disclosure"
    SECURITY = "security"


class LaunchGate(StrEnum):
    P5_PRODUCTION_ISOLATION = "p5-production-isolation"
    BLINDED_FIELD_VALIDATION = "blinded-field-validation"
    DETERMINISTIC_RELEASE_CHECKS = "deterministic-release-checks"


_ROLE_BY_REVIEW = {
    ReviewGate.FOUNDER: LaunchRole.FOUNDER,
    ReviewGate.INDEPENDENT_TECHNICAL: LaunchRole.INDEPENDENT_TECHNICAL,
    ReviewGate.INDEPENDENT_ISOLATION: LaunchRole.INDEPENDENT_ISOLATION,
    ReviewGate.LEGAL: LaunchRole.LEGAL,
    ReviewGate.SECURITY: LaunchRole.SECURITY,
}
_ROLE_BY_GATE = {
    LaunchGate.P5_PRODUCTION_ISOLATION: LaunchRole.P5_OPERATOR,
    LaunchGate.BLINDED_FIELD_VALIDATION: LaunchRole.EVALUATION_CUSTODIAN,
    LaunchGate.DETERMINISTIC_RELEASE_CHECKS: LaunchRole.RELEASE_OPERATOR,
}
_ENVIRONMENT_BY_GATE = {
    LaunchGate.P5_PRODUCTION_ISOLATION: "dedicated-linux-kvm-worker",
    LaunchGate.BLINDED_FIELD_VALIDATION: "blinded-owned-or-licensed-field-study",
    LaunchGate.DETERMINISTIC_RELEASE_CHECKS: "exact-final-commit-ci",
}
_REQUIRED_CHECKS = {
    LaunchGate.P5_PRODUCTION_ISOLATION: frozenset(
        {
            "dedicated-patched-linux-kvm-host",
            "live-firecracker-microvm",
            "malicious-guest-exact-host-matrix",
            "independent-isolation-review-bound",
            "cleanup-and-evidence-extraction",
        }
    ),
    LaunchGate.BLINDED_FIELD_VALIDATION: frozenset(
        {
            "preregistered-before-results",
            "independent-answer-key-custody",
            "all-eight-target-classes",
            "owned-or-licensed-targets",
            "multiple-provider-families",
            "matched-baseline-execution",
            "complete-run-ledger",
            "negative-results-retained",
        }
    ),
    LaunchGate.DETERMINISTIC_RELEASE_CHECKS: frozenset(
        {
            "full-test-suite",
            "static-analysis",
            "dependency-audit",
            "license-audit",
            "secret-audit",
            "deterministic-build",
            "ci-provenance",
            "package-resource-check",
            "isolated-wheel-smoke",
            "sbom",
            "checksums",
            "public-boundary",
            "staged-path-review",
        }
    ),
}


def _object(value: Any, role: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise FormatError("SOVA-P6-LAUNCH-TYPE", f"{role} must be an object")
    return value


def _array(value: Any, role: str) -> list[Any]:
    if not isinstance(value, list):
        raise FormatError("SOVA-P6-LAUNCH-TYPE", f"{role} must be an array")
    return value


def _string(value: Any, role: str) -> str:
    if not isinstance(value, str):
        raise FormatError("SOVA-P6-LAUNCH-TYPE", f"{role} must be a string")
    return value


def _integer(value: Any, role: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise FormatError("SOVA-P6-LAUNCH-TYPE", f"{role} must be an integer")
    return value


def _boolean(value: Any, role: str) -> bool:
    if not isinstance(value, bool):
        raise FormatError("SOVA-P6-LAUNCH-TYPE", f"{role} must be a boolean")
    return value


def _strings(value: Any, role: str) -> tuple[str, ...]:
    return tuple(_string(item, role) for item in _array(value, role))


def _exact(value: Mapping[str, Any], expected: set[str], role: str) -> None:
    if set(value) != expected:
        raise FormatError("SOVA-P6-LAUNCH-FIELDS", f"{role} fields must be exact")


def _verify_content_digest(document: Mapping[str, Any], role: str) -> str:
    claimed = _string(document.get("contentDigest"), f"{role} content digest")
    unsigned = dict(document)
    unsigned.pop("contentDigest", None)
    observed = sha256_digest(canonical_json_bytes(unsigned))
    if claimed != observed:
        raise FormatError("SOVA-P6-LAUNCH-DIGEST", f"{role} content digest is invalid")
    return claimed


def _decode_public_key(value: str) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise FormatError("SOVA-P6-LAUNCH-KEY", "trusted public key is not base64") from error
    if len(raw) != _RAW_ED25519_KEY_BYTES:
        raise FormatError("SOVA-P6-LAUNCH-KEY", "trusted public key must be raw Ed25519")
    return raw


@dataclass(frozen=True, slots=True)
class TrustedLaunchPrincipal:
    key_id: str
    public_key: bytes
    name: str
    organization: str
    roles: tuple[LaunchRole, ...]

    def __post_init__(self) -> None:
        if self.key_id != sha256_digest(self.public_key):
            raise FormatError("SOVA-P6-LAUNCH-KEY", "trusted key id does not match key bytes")
        if not self.name.strip() or not self.organization.strip() or not self.roles:
            raise FormatError("SOVA-P6-LAUNCH-TRUST", "principal identity and roles are required")
        if len(set(self.roles)) != len(self.roles):
            raise FormatError("SOVA-P6-LAUNCH-TRUST", "principal roles must be unique")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "keyId": self.key_id,
            "publicKey": base64.b64encode(self.public_key).decode("ascii"),
            "name": self.name,
            "organization": self.organization,
            "roles": [role.value for role in self.roles],
        }


@dataclass(frozen=True, slots=True)
class LaunchTrustPolicy:
    release_commit: str
    artifact_manifest_digest: str
    release_candidate_digest: str
    principals: tuple[TrustedLaunchPrincipal, ...]
    content_digest: str

    def __post_init__(self) -> None:
        if (
            not self.release_commit.strip()
            or _SHA256.fullmatch(self.artifact_manifest_digest) is None
            or _SHA256.fullmatch(self.release_candidate_digest) is None
        ):
            raise FormatError("SOVA-P6-LAUNCH-TRUST", "trust policy release binding is invalid")
        if not self.principals or len({item.key_id for item in self.principals}) != len(
            self.principals
        ):
            raise FormatError("SOVA-P6-LAUNCH-TRUST", "trusted principal keys must be unique")
        represented = {role for item in self.principals for role in item.roles}
        if represented != set(LaunchRole):
            raise FormatError("SOVA-P6-LAUNCH-TRUST", "every launch trust role is required")
        if len(self.principals) != len(LaunchRole) or any(
            len(item.roles) != 1 for item in self.principals
        ):
            raise FormatError(
                "SOVA-P6-LAUNCH-TRUST",
                "each launch role requires one distinct trusted principal and key",
            )
        by_role = {item.roles[0]: item for item in self.principals}
        internal_roles = {
            LaunchRole.EVALUATION_CUSTODIAN,
            LaunchRole.REGISTRY_OPERATOR,
            LaunchRole.P5_OPERATOR,
            LaunchRole.RELEASE_OPERATOR,
            LaunchRole.FOUNDER,
        }
        internal_names = {by_role[role].name for role in internal_roles}
        internal_organizations = {by_role[role].organization for role in internal_roles}
        technical = by_role[LaunchRole.INDEPENDENT_TECHNICAL]
        isolation = by_role[LaunchRole.INDEPENDENT_ISOLATION]
        for reviewer in (technical, isolation):
            if reviewer.name in internal_names or reviewer.organization in internal_organizations:
                raise FormatError(
                    "SOVA-P6-LAUNCH-TRUST",
                    "independent reviewer identity must be separate from internal principals",
                )
        if technical.name == isolation.name or technical.organization == isolation.organization:
            raise FormatError(
                "SOVA-P6-LAUNCH-TRUST",
                "independent technical and isolation reviewers must be separate",
            )

    @property
    def digest(self) -> str:
        return self.content_digest

    def principal(self, key_id: str) -> TrustedLaunchPrincipal:
        principal = next((item for item in self.principals if item.key_id == key_id), None)
        if principal is None:
            raise FormatError("SOVA-P6-LAUNCH-TRUST", "evidence signer key is not trusted")
        return principal

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.launch-trust-policy",
            "schemaVersion": "0.1.0",
            "releaseCommit": self.release_commit,
            "artifactManifestDigest": self.artifact_manifest_digest,
            "releaseCandidateDigest": self.release_candidate_digest,
            "principals": [item.to_mapping() for item in self.principals],
            "contentDigest": self.content_digest,
        }


@dataclass(frozen=True, slots=True)
class LaunchGateReceipt:
    gate: LaunchGate
    release_commit: str
    artifact_manifest_digest: str
    subject_digest: str
    environment: str
    issuer: str
    organization: str
    issued_at: str
    result: str
    checks: tuple[str, ...]
    evidence_digest: str
    synthetic: bool

    def __post_init__(self) -> None:
        for value, role in (
            (self.artifact_manifest_digest, "artifact manifest"),
            (self.subject_digest, "gate subject"),
            (self.evidence_digest, "gate evidence"),
        ):
            if _SHA256.fullmatch(value) is None:
                raise FormatError("SOVA-P6-LAUNCH-GATE", f"{role} digest is invalid")
        if any(
            not value.strip()
            for value in (
                self.release_commit,
                self.environment,
                self.issuer,
                self.organization,
                self.issued_at,
            )
        ):
            raise FormatError("SOVA-P6-LAUNCH-GATE", "gate receipt identity is required")
        if self.result not in {"pass", "fail"}:
            raise FormatError("SOVA-P6-LAUNCH-GATE", "gate receipt result is invalid")
        if _RFC3339_UTC.fullmatch(self.issued_at) is None:
            raise FormatError("SOVA-P6-LAUNCH-GATE", "gate receipt time must be RFC 3339 UTC")
        if (
            len(set(self.checks)) != len(self.checks)
            or set(self.checks) != _REQUIRED_CHECKS[self.gate]
        ):
            raise FormatError("SOVA-P6-LAUNCH-GATE", "gate receipt checks are incomplete")
        if self.environment != _ENVIRONMENT_BY_GATE[self.gate]:
            raise FormatError("SOVA-P6-LAUNCH-GATE", "gate receipt environment is invalid")

    @property
    def passed(self) -> bool:
        return self.result == "pass" and not self.synthetic

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.launch-gate-receipt",
            "schemaVersion": "0.1.0",
            "gate": self.gate.value,
            "releaseCommit": self.release_commit,
            "artifactManifestDigest": self.artifact_manifest_digest,
            "subjectDigest": self.subject_digest,
            "environment": self.environment,
            "issuer": self.issuer,
            "organization": self.organization,
            "issuedAt": self.issued_at,
            "result": self.result,
            "checks": list(self.checks),
            "evidenceDigest": self.evidence_digest,
            "synthetic": self.synthetic,
        }


@dataclass(frozen=True, slots=True)
class LaunchEvidenceBundle:
    trust_policy: LaunchTrustPolicy
    protocol: EvaluationProtocol
    observation_envelope: dict[str, Any]
    registry_policy: RegistryBetaPolicy
    operational_envelopes: tuple[dict[str, Any], ...]
    candidate: ReleaseCandidate
    review_envelopes: tuple[dict[str, Any], ...]
    gate_envelopes: tuple[dict[str, Any], ...]
    content_digest: str


def trust_policy_from_mapping(document: Mapping[str, Any]) -> LaunchTrustPolicy:
    validate_document(dict(document), "sova.launch-trust-policy")
    _exact(
        document,
        {
            "artifactType",
            "schemaVersion",
            "releaseCommit",
            "artifactManifestDigest",
            "releaseCandidateDigest",
            "principals",
            "contentDigest",
        },
        "launch trust policy",
    )
    content_digest = _verify_content_digest(document, "launch trust policy")
    principals: list[TrustedLaunchPrincipal] = []
    for raw in _array(document.get("principals"), "trusted principals"):
        item = _object(raw, "trusted principal")
        _exact(item, {"keyId", "publicKey", "name", "organization", "roles"}, "principal")
        roles = tuple(LaunchRole(value) for value in _strings(item.get("roles"), "roles"))
        principals.append(
            TrustedLaunchPrincipal(
                key_id=_string(item.get("keyId"), "principal key id"),
                public_key=_decode_public_key(_string(item.get("publicKey"), "public key")),
                name=_string(item.get("name"), "principal name"),
                organization=_string(item.get("organization"), "principal organization"),
                roles=roles,
            )
        )
    return LaunchTrustPolicy(
        release_commit=_string(document.get("releaseCommit"), "release commit"),
        artifact_manifest_digest=_string(
            document.get("artifactManifestDigest"), "artifact manifest digest"
        ),
        release_candidate_digest=_string(
            document.get("releaseCandidateDigest"), "release candidate digest"
        ),
        principals=tuple(principals),
        content_digest=content_digest,
    )


def protocol_from_mapping(document: Mapping[str, Any]) -> EvaluationProtocol:
    mapped = dict(document)
    validate_document(mapped, "sova.blinded-evaluation-protocol")
    targets = tuple(
        BlindedTarget(
            identifier=_string(item.get("id"), "target id"),
            target_class=TargetClass(_string(item.get("targetClass"), "target class")),
            input_digest=_string(item.get("inputDigest"), "target input digest"),
            answer_key_commitment=_string(item.get("answerKeyCommitment"), "answer-key commitment"),
            authorization_receipt_digest=_string(
                item.get("authorizationReceiptDigest"), "authorization receipt digest"
            ),
            source_revision=_string(item.get("sourceRevision"), "source revision"),
            license_identifier=_string(item.get("licenseIdentifier"), "license identifier"),
            containment_backend=_string(item.get("containmentBackend"), "containment backend"),
            blinded=_boolean(item.get("blinded"), "blinded marker"),
            owned_or_licensed=_boolean(item.get("ownedOrLicensed"), "authority marker"),
        )
        for item in (
            _object(value, "blinded target") for value in _array(mapped.get("targets"), "targets")
        )
    )
    lanes = tuple(
        EvaluationLane(
            identifier=_string(item.get("id"), "lane id"),
            kind=LaneKind(_string(item.get("kind"), "lane kind")),
            provider=_string(item.get("provider"), "lane provider"),
            model=_string(item.get("model"), "lane model"),
            harness=_string(item.get("harness"), "lane harness"),
            configuration_digest=_string(
                item.get("configurationDigest"), "lane configuration digest"
            ),
        )
        for item in (
            _object(value, "evaluation lane") for value in _array(mapped.get("lanes"), "lanes")
        )
    )
    budget = _object(mapped.get("budgetPerRun"), "evaluation budget")
    protocol = EvaluationProtocol(
        identifier=_string(mapped.get("id"), "protocol id"),
        registered_at=_string(mapped.get("registeredAt"), "registration time"),
        release_commit=_string(mapped.get("releaseCommit"), "release commit"),
        targets=targets,
        lanes=lanes,
        repetitions=_integer(mapped.get("repetitions"), "repetitions"),
        seed=_integer(mapped.get("seed"), "seed"),
        budget=EvaluationBudget(
            maximum_actions=_integer(budget.get("maximumActions"), "maximum actions"),
            maximum_wall_seconds=_integer(budget.get("maximumWallSeconds"), "maximum wall seconds"),
            maximum_input_bytes=_integer(budget.get("maximumInputBytes"), "maximum input bytes"),
            maximum_output_bytes=_integer(budget.get("maximumOutputBytes"), "maximum output bytes"),
            maximum_cost_microusd=_integer(budget.get("maximumCostMicrousd"), "maximum cost"),
        ),
        scoring_rules_digest=_string(mapped.get("scoringRulesDigest"), "scoring rules digest"),
        metrics=_strings(mapped.get("metrics"), "metrics"),
        exclusions=_strings(mapped.get("exclusions"), "exclusions"),
        failure_rules=_strings(mapped.get("failureRules"), "failure rules"),
        answer_key_custodian=_string(mapped.get("answerKeyCustodian"), "answer-key custodian"),
    )
    if protocol.to_mapping() != mapped:
        raise FormatError(
            "SOVA-P6-LAUNCH-PROTOCOL", "protocol contains inconsistent derived fields"
        )
    return protocol


def _observation_from_mapping(
    item: Mapping[str, Any], protocol_digest: str
) -> EvaluationObservation:
    _exact(
        item,
        {
            "laneId",
            "targetId",
            "repetition",
            "status",
            "workflowCoverage",
            "surfaceCoverage",
            "findings",
            "infrastructureFailures",
            "actionsUsed",
            "inputBytes",
            "outputBytes",
            "durationMilliseconds",
            "costMicrousd",
            "containmentPassed",
            "evidenceDigest",
            "limitations",
        },
        "evaluation observation",
    )
    workflow = _object(item.get("workflowCoverage"), "workflow coverage")
    surface = _object(item.get("surfaceCoverage"), "surface coverage")
    findings = _object(item.get("findings"), "findings")
    _exact(workflow, {"observed", "total"}, "workflow coverage")
    _exact(surface, {"exercised", "total"}, "surface coverage")
    _exact(findings, {"reported", "confirmed", "reproduced", "falsePositives"}, "findings")
    containment = item.get("containmentPassed")
    if containment is not None and not isinstance(containment, bool):
        raise FormatError("SOVA-P6-LAUNCH-TYPE", "containment result must be boolean or null")
    status = ObservationStatus(_string(item.get("status"), "observation status"))
    return EvaluationObservation(
        protocol_digest=protocol_digest,
        lane_id=_string(item.get("laneId"), "lane id"),
        target_id=_string(item.get("targetId"), "target id"),
        repetition=_integer(item.get("repetition"), "repetition"),
        status=status,
        workflows_observed=_integer(workflow.get("observed"), "observed workflows"),
        workflows_total=_integer(workflow.get("total"), "total workflows"),
        surfaces_exercised=_integer(surface.get("exercised"), "exercised surfaces"),
        surfaces_total=_integer(surface.get("total"), "total surfaces"),
        findings_reported=_integer(findings.get("reported"), "reported findings"),
        findings_confirmed=_integer(findings.get("confirmed"), "confirmed findings"),
        findings_reproduced=_integer(findings.get("reproduced"), "reproduced findings"),
        false_positives=_integer(findings.get("falsePositives"), "false positives"),
        infrastructure_failures=_integer(
            item.get("infrastructureFailures"), "infrastructure failures"
        ),
        actions_used=_integer(item.get("actionsUsed"), "actions used"),
        input_bytes=_integer(item.get("inputBytes"), "input bytes"),
        output_bytes=_integer(item.get("outputBytes"), "output bytes"),
        duration_ms=_integer(item.get("durationMilliseconds"), "duration"),
        cost_microusd=_integer(item.get("costMicrousd"), "cost"),
        containment_passed=containment,
        evidence_digest=_string(item.get("evidenceDigest"), "evidence digest"),
        limitations=_strings(item.get("limitations"), "limitations"),
    )


def observation_ledger_from_mapping(
    document: Mapping[str, Any],
) -> tuple[str, tuple[EvaluationObservation, ...], str]:
    validate_document(dict(document), "sova.evaluation-observation-ledger")
    _exact(
        document,
        {"artifactType", "schemaVersion", "protocolDigest", "observations", "contentDigest"},
        "observation ledger",
    )
    content_digest = _verify_content_digest(document, "observation ledger")
    protocol_digest = _string(document.get("protocolDigest"), "protocol digest")
    if _SHA256.fullmatch(protocol_digest) is None:
        raise FormatError("SOVA-P6-LAUNCH-OBSERVATION", "protocol digest is invalid")
    observations = tuple(
        _observation_from_mapping(_object(raw, "observation"), protocol_digest)
        for raw in _array(document.get("observations"), "observations")
    )
    return protocol_digest, observations, content_digest


def registry_policy_from_mapping(document: Mapping[str, Any]) -> RegistryBetaPolicy:
    _exact(
        document,
        {
            "releaseCommit",
            "releaseArtifactDigest",
            "images",
            "identity",
            "moderatorRoles",
            "malware",
            "backup",
            "rollbackImageDigest",
            "incidentRunbookDigest",
            "incidentOwner",
            "requestsPerMinute",
            "secretScreeningRequired",
            "operatorModerationRequired",
        },
        "Registry beta policy",
    )
    images = _object(document.get("images"), "Registry images")
    identity = _object(document.get("identity"), "Registry identity")
    malware = _object(document.get("malware"), "Registry malware policy")
    backup = _object(document.get("backup"), "Registry backup policy")
    _exact(images, {"sova", "edge"}, "Registry images")
    _exact(identity, {"issuer", "audience", "receiptIssuers"}, "Registry identity")
    _exact(malware, {"engine", "version", "signaturesDigest"}, "Registry malware policy")
    _exact(
        backup,
        {"destination", "encrypted", "retentionDays", "rpoMinutes", "rtoMinutes"},
        "Registry backup policy",
    )
    policy = RegistryBetaPolicy(
        release_commit=_string(document.get("releaseCommit"), "release commit"),
        release_artifact_digest=_string(
            document.get("releaseArtifactDigest"), "release artifact digest"
        ),
        sova_image=_string(images.get("sova"), "SOVA image"),
        edge_image=_string(images.get("edge"), "edge image"),
        identity_issuer=_string(identity.get("issuer"), "identity issuer"),
        identity_audience=_string(identity.get("audience"), "identity audience"),
        authorized_receipt_issuers=_strings(identity.get("receiptIssuers"), "receipt issuers"),
        moderator_roles=_strings(document.get("moderatorRoles"), "moderator roles"),
        malware_engine=_string(malware.get("engine"), "malware engine"),
        malware_engine_version=_string(malware.get("version"), "malware engine version"),
        malware_signatures_digest=_string(
            malware.get("signaturesDigest"), "malware signatures digest"
        ),
        backup_destination=_string(backup.get("destination"), "backup destination"),
        backup_encrypted=_boolean(backup.get("encrypted"), "backup encryption"),
        backup_retention_days=_integer(backup.get("retentionDays"), "backup retention"),
        rpo_minutes=_integer(backup.get("rpoMinutes"), "RPO"),
        rto_minutes=_integer(backup.get("rtoMinutes"), "RTO"),
        rollback_image_digest=_string(document.get("rollbackImageDigest"), "rollback image digest"),
        incident_runbook_digest=_string(
            document.get("incidentRunbookDigest"), "incident runbook digest"
        ),
        incident_owner=_string(document.get("incidentOwner"), "incident owner"),
        requests_per_minute=_integer(document.get("requestsPerMinute"), "requests per minute"),
    )
    if policy.to_mapping() != dict(document):
        raise FormatError("SOVA-P6-LAUNCH-REGISTRY", "Registry policy is not canonical")
    return policy


def operational_receipt_from_mapping(document: Mapping[str, Any]) -> OperationalReceipt:
    validate_document(dict(document), "sova.registry-operational-receipt")
    expected = {
        "artifactType",
        "schemaVersion",
        "control",
        "policyDigest",
        "releaseArtifactDigest",
        "environment",
        "issuer",
        "issuedAt",
        "result",
        "evidenceDigest",
        "synthetic",
    }
    _exact(document, expected, "Registry operational receipt")
    control = RegistryControl(_string(document.get("control"), "Registry control"))
    return OperationalReceipt(
        control=control,
        policy_digest=_string(document.get("policyDigest"), "Registry policy digest"),
        release_artifact_digest=_string(
            document.get("releaseArtifactDigest"), "release artifact digest"
        ),
        environment=_string(document.get("environment"), "environment"),
        issuer=_string(document.get("issuer"), "issuer"),
        issued_at=_string(document.get("issuedAt"), "issue time"),
        result=_string(document.get("result"), "result"),
        evidence_digest=_string(document.get("evidenceDigest"), "evidence digest"),
        synthetic=_boolean(document.get("synthetic"), "synthetic marker"),
    )


def release_candidate_from_mapping(document: Mapping[str, Any]) -> ReleaseCandidate:
    validate_document(dict(document), "sova.release-candidate")
    _exact(
        document,
        {
            "artifactType",
            "schemaVersion",
            "releaseCommit",
            "artifactManifestDigest",
            "evaluationReportDigest",
            "registryReadinessDigest",
            "claimsRegisterDigest",
            "rollbackTestDigest",
            "incidentTestDigest",
            "blindedResultsPublic",
            "limitationsPublic",
        },
        "release candidate",
    )
    return ReleaseCandidate(
        release_commit=_string(document.get("releaseCommit"), "release commit"),
        artifact_manifest_digest=_string(
            document.get("artifactManifestDigest"), "artifact manifest digest"
        ),
        evaluation_report_digest=_string(
            document.get("evaluationReportDigest"), "evaluation report digest"
        ),
        registry_readiness_digest=_string(
            document.get("registryReadinessDigest"), "Registry readiness digest"
        ),
        claims_register_digest=_string(
            document.get("claimsRegisterDigest"), "claims register digest"
        ),
        rollback_test_digest=_string(document.get("rollbackTestDigest"), "rollback digest"),
        incident_test_digest=_string(document.get("incidentTestDigest"), "incident digest"),
        blinded_results_public=_boolean(
            document.get("blindedResultsPublic"), "blinded-results publication marker"
        ),
        limitations_public=_boolean(
            document.get("limitationsPublic"), "limitations publication marker"
        ),
    )


def review_receipt_from_mapping(document: Mapping[str, Any]) -> ReviewReceipt:
    validate_document(dict(document), "sova.release-review-receipt")
    _exact(
        document,
        {
            "artifactType",
            "schemaVersion",
            "gate",
            "releaseCommit",
            "artifactManifestDigest",
            "reviewer",
            "organization",
            "issuedAt",
            "result",
            "independent",
            "evidenceDigest",
            "synthetic",
        },
        "release review receipt",
    )
    gate = ReviewGate(_string(document.get("gate"), "review gate"))
    return ReviewReceipt(
        gate=gate,
        release_commit=_string(document.get("releaseCommit"), "release commit"),
        artifact_manifest_digest=_string(
            document.get("artifactManifestDigest"), "artifact manifest digest"
        ),
        reviewer=_string(document.get("reviewer"), "reviewer"),
        organization=_string(document.get("organization"), "review organization"),
        issued_at=_string(document.get("issuedAt"), "review issue time"),
        result=_string(document.get("result"), "review result"),
        independent=_boolean(document.get("independent"), "independence marker"),
        evidence_digest=_string(document.get("evidenceDigest"), "review evidence digest"),
        synthetic=_boolean(document.get("synthetic"), "synthetic marker"),
    )


def launch_gate_receipt_from_mapping(document: Mapping[str, Any]) -> LaunchGateReceipt:
    validate_document(dict(document), "sova.launch-gate-receipt")
    _exact(
        document,
        {
            "artifactType",
            "schemaVersion",
            "gate",
            "releaseCommit",
            "artifactManifestDigest",
            "subjectDigest",
            "environment",
            "issuer",
            "organization",
            "issuedAt",
            "result",
            "checks",
            "evidenceDigest",
            "synthetic",
        },
        "launch gate receipt",
    )
    gate = LaunchGate(_string(document.get("gate"), "launch gate"))
    return LaunchGateReceipt(
        gate=gate,
        release_commit=_string(document.get("releaseCommit"), "release commit"),
        artifact_manifest_digest=_string(
            document.get("artifactManifestDigest"), "artifact manifest digest"
        ),
        subject_digest=_string(document.get("subjectDigest"), "gate subject digest"),
        environment=_string(document.get("environment"), "gate environment"),
        issuer=_string(document.get("issuer"), "gate issuer"),
        organization=_string(document.get("organization"), "gate organization"),
        issued_at=_string(document.get("issuedAt"), "gate issue time"),
        result=_string(document.get("result"), "gate result"),
        checks=_strings(document.get("checks"), "gate checks"),
        evidence_digest=_string(document.get("evidenceDigest"), "gate evidence digest"),
        synthetic=_boolean(document.get("synthetic"), "synthetic marker"),
    )


def _envelope(value: Any, role: str) -> dict[str, Any]:
    envelope = _object(value, role)
    _exact(envelope, {"payloadType", "payload", "signatures"}, role)
    return envelope


def launch_bundle_from_mapping(document: Mapping[str, Any]) -> LaunchEvidenceBundle:
    validate_document(dict(document), "sova.launch-evidence-bundle")
    _exact(
        document,
        {
            "artifactType",
            "schemaVersion",
            "trustPolicy",
            "protocol",
            "observationLedger",
            "registryPolicy",
            "operationalReceipts",
            "candidate",
            "reviewReceipts",
            "gateReceipts",
            "contentDigest",
        },
        "launch evidence bundle",
    )
    content_digest = _verify_content_digest(document, "launch evidence bundle")
    return LaunchEvidenceBundle(
        trust_policy=trust_policy_from_mapping(
            _object(document.get("trustPolicy"), "trust policy")
        ),
        protocol=protocol_from_mapping(_object(document.get("protocol"), "protocol")),
        observation_envelope=_envelope(document.get("observationLedger"), "observation envelope"),
        registry_policy=registry_policy_from_mapping(
            _object(document.get("registryPolicy"), "Registry policy")
        ),
        operational_envelopes=tuple(
            _envelope(item, "operational receipt envelope")
            for item in _array(document.get("operationalReceipts"), "operational receipts")
        ),
        candidate=release_candidate_from_mapping(
            _object(document.get("candidate"), "release candidate")
        ),
        review_envelopes=tuple(
            _envelope(item, "review receipt envelope")
            for item in _array(document.get("reviewReceipts"), "review receipts")
        ),
        gate_envelopes=tuple(
            _envelope(item, "gate receipt envelope")
            for item in _array(document.get("gateReceipts"), "gate receipts")
        ),
        content_digest=content_digest,
    )


def assemble_launch_bundle(  # noqa: PLR0913 - each evidence class remains explicit
    *,
    trust_policy: Mapping[str, Any],
    protocol: Mapping[str, Any],
    observation_envelope: Mapping[str, Any],
    registry_policy: Mapping[str, Any],
    operational_envelopes: tuple[Mapping[str, Any], ...],
    candidate: Mapping[str, Any],
    review_envelopes: tuple[Mapping[str, Any], ...],
    gate_envelopes: tuple[Mapping[str, Any], ...],
) -> dict[str, Any]:
    """Assemble and strictly validate one deterministic launch-evidence bundle."""
    document: dict[str, Any] = {
        "artifactType": "sova.launch-evidence-bundle",
        "schemaVersion": "0.1.0",
        "trustPolicy": dict(trust_policy),
        "protocol": dict(protocol),
        "observationLedger": dict(observation_envelope),
        "registryPolicy": dict(registry_policy),
        "operationalReceipts": [dict(item) for item in operational_envelopes],
        "candidate": dict(candidate),
        "reviewReceipts": [dict(item) for item in review_envelopes],
        "gateReceipts": [dict(item) for item in gate_envelopes],
    }
    document["contentDigest"] = sha256_digest(canonical_json_bytes(document))
    launch_bundle_from_mapping(document)
    return document


def read_launch_bundle(raw: bytes) -> LaunchEvidenceBundle:
    document = strict_json_loads(
        raw,
        max_bytes=_MAX_BUNDLE_BYTES,
        max_items=_MAX_BUNDLE_ITEMS,
        max_depth=64,
    )
    return launch_bundle_from_mapping(_object(document, "launch bundle"))


def _signed_document(
    envelope: dict[str, Any], policy: LaunchTrustPolicy
) -> tuple[dict[str, Any], TrustedLaunchPrincipal]:
    signatures = _array(envelope.get("signatures"), "evidence signatures")
    if len(signatures) != 1:
        raise FormatError("SOVA-P6-LAUNCH-SIGNATURE", "exactly one evidence signature is required")
    signature = _object(signatures[0], "evidence signature")
    key_id = _string(signature.get("keyid"), "evidence signer key id")
    principal = policy.principal(key_id)
    payload = verify_dsse_payload(
        envelope,
        principal.public_key,
        expected_payload_type=LAUNCH_EVIDENCE_PAYLOAD_TYPE,
    )
    parsed = strict_json_loads(payload, max_bytes=8 * 1024 * 1024, max_items=100_000)
    document = _object(parsed, "signed launch evidence")
    if payload != canonical_json_bytes(document):
        raise FormatError("SOVA-P6-LAUNCH-SIGNATURE", "signed evidence must be canonical JSON")
    return document, principal


def _require_role(principal: TrustedLaunchPrincipal, role: LaunchRole) -> None:
    if role not in principal.roles:
        raise FormatError("SOVA-P6-LAUNCH-TRUST", f"signer is not trusted for role {role.value}")


def sign_launch_evidence(
    document: Mapping[str, Any], private_key: bytes, public_key: bytes
) -> dict[str, Any]:
    """Sign one strict launch evidence payload; key identity remains out-of-band policy."""
    artifact_type = document.get("artifactType")
    mapped = dict(document)
    if artifact_type == "sova.evaluation-observation-ledger":
        observation_ledger_from_mapping(mapped)
    elif artifact_type == "sova.registry-operational-receipt":
        operational_receipt_from_mapping(mapped)
    elif artifact_type == "sova.release-review-receipt":
        review_receipt_from_mapping(mapped)
    elif artifact_type == "sova.launch-gate-receipt":
        launch_gate_receipt_from_mapping(mapped)
    else:
        raise FormatError("SOVA-P6-LAUNCH-SIGNATURE", "launch evidence type cannot be signed")
    if len(private_key) != _RAW_ED25519_KEY_BYTES or len(public_key) != _RAW_ED25519_KEY_BYTES:
        raise FormatError("SOVA-P6-LAUNCH-KEY", "launch signing keys must be raw Ed25519")
    keypair = Ed25519Keypair(private_key, public_key, sha256_digest(public_key))
    return sign_dsse_payload(LAUNCH_EVIDENCE_PAYLOAD_TYPE, canonical_json_bytes(mapped), keypair)


def _bind_release(
    bundle: LaunchEvidenceBundle, expected_commit: str, expected_trust_policy_digest: str
) -> None:
    commits = {
        bundle.trust_policy.release_commit,
        bundle.protocol.release_commit,
        bundle.registry_policy.release_commit,
        bundle.candidate.release_commit,
        expected_commit,
    }
    if len(commits) != 1:
        raise FormatError("SOVA-P6-LAUNCH-BINDING", "release commit binding drifted")
    if (
        _SHA256.fullmatch(expected_trust_policy_digest) is None
        or bundle.trust_policy.digest != expected_trust_policy_digest
    ):
        raise FormatError("SOVA-P6-LAUNCH-BINDING", "launch trust policy is not externally pinned")
    if bundle.trust_policy.release_candidate_digest != bundle.candidate.digest:
        raise FormatError("SOVA-P6-LAUNCH-BINDING", "trust policy binds another release candidate")


def _verify_observations(
    bundle: LaunchEvidenceBundle,
) -> tuple[tuple[EvaluationObservation, ...], str, str]:
    document, principal = _signed_document(bundle.observation_envelope, bundle.trust_policy)
    _require_role(principal, LaunchRole.EVALUATION_CUSTODIAN)
    protocol_digest, observations, ledger_digest = observation_ledger_from_mapping(document)
    if protocol_digest != bundle.protocol.digest:
        raise FormatError("SOVA-P6-LAUNCH-BINDING", "observation ledger binds another protocol")
    return observations, ledger_digest, principal.key_id


def _verify_operations(
    bundle: LaunchEvidenceBundle,
) -> tuple[tuple[OperationalReceipt, ...], tuple[str, ...]]:
    receipts: list[OperationalReceipt] = []
    keys: list[str] = []
    for envelope in bundle.operational_envelopes:
        document, principal = _signed_document(envelope, bundle.trust_policy)
        _require_role(principal, LaunchRole.REGISTRY_OPERATOR)
        receipt = operational_receipt_from_mapping(document)
        if receipt.issuer != principal.name:
            raise FormatError("SOVA-P6-LAUNCH-TRUST", "operational issuer does not match signer")
        receipts.append(receipt)
        keys.append(principal.key_id)
    return tuple(receipts), tuple(keys)


def _verify_reviews(
    bundle: LaunchEvidenceBundle,
) -> tuple[tuple[ReviewReceipt, ...], tuple[str, ...]]:
    receipts: list[ReviewReceipt] = []
    keys: list[str] = []
    for envelope in bundle.review_envelopes:
        document, principal = _signed_document(envelope, bundle.trust_policy)
        receipt = review_receipt_from_mapping(document)
        _require_role(principal, _ROLE_BY_REVIEW[receipt.gate])
        if receipt.reviewer != principal.name or receipt.organization != principal.organization:
            raise FormatError("SOVA-P6-LAUNCH-TRUST", "review identity does not match signer")
        receipts.append(receipt)
        keys.append(principal.key_id)
    return tuple(receipts), tuple(keys)


def _verify_launch_gates(
    bundle: LaunchEvidenceBundle,
    *,
    evaluation_digest: str,
) -> tuple[dict[LaunchGate, LaunchGateReceipt], tuple[str, ...]]:
    receipts: dict[LaunchGate, LaunchGateReceipt] = {}
    keys: list[str] = []
    for envelope in bundle.gate_envelopes:
        document, principal = _signed_document(envelope, bundle.trust_policy)
        receipt = launch_gate_receipt_from_mapping(document)
        _require_role(principal, _ROLE_BY_GATE[receipt.gate])
        if receipt.gate in receipts:
            raise FormatError("SOVA-P6-LAUNCH-GATE", "launch gate receipt is duplicated")
        if receipt.issuer != principal.name or receipt.organization != principal.organization:
            raise FormatError("SOVA-P6-LAUNCH-TRUST", "launch gate identity does not match signer")
        if (
            receipt.release_commit != bundle.candidate.release_commit
            or receipt.artifact_manifest_digest != bundle.candidate.artifact_manifest_digest
        ):
            raise FormatError("SOVA-P6-LAUNCH-BINDING", "launch gate binds another release")
        expected_subject = (
            evaluation_digest
            if receipt.gate is LaunchGate.BLINDED_FIELD_VALIDATION
            else bundle.candidate.artifact_manifest_digest
        )
        if receipt.subject_digest != expected_subject:
            raise FormatError("SOVA-P6-LAUNCH-BINDING", "launch gate binds another subject")
        receipts[receipt.gate] = receipt
        keys.append(principal.key_id)
    return receipts, tuple(keys)


def evaluate_launch_bundle(
    bundle: LaunchEvidenceBundle,
    *,
    artifact_manifest: bytes,
    claims_register: bytes,
    expected_commit: str,
    expected_trust_policy_digest: str,
) -> dict[str, Any]:
    """Recompute every P6 report and issue one inert exact-candidate launch verdict."""
    _bind_release(bundle, expected_commit, expected_trust_policy_digest)
    manifest_digest = sha256_digest(artifact_manifest)
    claims_digest = sha256_digest(claims_register)
    if (
        bundle.candidate.artifact_manifest_digest != manifest_digest
        or bundle.trust_policy.artifact_manifest_digest != manifest_digest
    ):
        raise FormatError("SOVA-P6-LAUNCH-BINDING", "artifact manifest bytes do not match release")
    if bundle.candidate.claims_register_digest != claims_digest:
        raise FormatError("SOVA-P6-LAUNCH-BINDING", "claims register bytes do not match release")

    observations, observation_ledger_digest, observation_key = _verify_observations(bundle)
    evaluation = evaluate_blinded_protocol(bundle.protocol, observations)
    validate_document(evaluation, "sova.blinded-evaluation-report")
    if bundle.candidate.evaluation_report_digest != evaluation["contentDigest"]:
        raise FormatError("SOVA-P6-LAUNCH-BINDING", "candidate evaluation report digest drifted")

    operations, operation_keys = _verify_operations(bundle)
    registry = evaluate_registry_beta(bundle.registry_policy, operations)
    validate_document(registry, "sova.registry-beta-readiness")
    if bundle.candidate.registry_readiness_digest != registry["contentDigest"]:
        raise FormatError("SOVA-P6-LAUNCH-BINDING", "candidate Registry readiness digest drifted")
    operation_by_control = {item.control: item for item in operations}
    rollback = operation_by_control.get(RegistryControl.ROLLBACK)
    incident = operation_by_control.get(RegistryControl.INCIDENT_RESPONSE)
    if rollback is not None and rollback.evidence_digest != bundle.candidate.rollback_test_digest:
        raise FormatError("SOVA-P6-LAUNCH-BINDING", "rollback receipt digest drifted")
    if incident is not None and incident.evidence_digest != bundle.candidate.incident_test_digest:
        raise FormatError("SOVA-P6-LAUNCH-BINDING", "incident receipt digest drifted")

    reviews, review_keys = _verify_reviews(bundle)
    gates, gate_keys = _verify_launch_gates(
        bundle, evaluation_digest=_string(evaluation["contentDigest"], "evaluation digest")
    )
    p5_passed = gates.get(LaunchGate.P5_PRODUCTION_ISOLATION)
    blinded_passed = gates.get(LaunchGate.BLINDED_FIELD_VALIDATION)
    checks_passed = gates.get(LaunchGate.DETERMINISTIC_RELEASE_CHECKS)
    evaluation_conclusive = evaluation["status"] == "conclusive"
    release = evaluate_release_candidate(
        bundle.candidate,
        reviews,
        p5_exit_passed=p5_passed is not None and p5_passed.passed,
        blinded_field_validation_passed=(
            blinded_passed is not None and blinded_passed.passed and evaluation_conclusive
        ),
        registry_live_ready=bool(registry["liveBetaReady"]),
        deterministic_release_checks_passed=checks_passed is not None and checks_passed.passed,
    )
    validate_document(release, "sova.release-gate-ledger")
    signer_keys = tuple(sorted({observation_key, *operation_keys, *review_keys, *gate_keys}))
    dossier: dict[str, Any] = {
        "artifactType": "sova.launch-dossier",
        "schemaVersion": "0.1.0",
        "releaseCommit": bundle.candidate.release_commit,
        "artifactManifestDigest": manifest_digest,
        "claimsRegisterDigest": claims_digest,
        "bundleDigest": bundle.content_digest,
        "trustPolicyDigest": bundle.trust_policy.digest,
        "protocolDigest": bundle.protocol.digest,
        "observationLedgerDigest": observation_ledger_digest,
        "evaluationReportDigest": evaluation["contentDigest"],
        "registryPolicyDigest": bundle.registry_policy.digest,
        "registryReadinessDigest": registry["contentDigest"],
        "releaseCandidateDigest": bundle.candidate.digest,
        "releaseGateLedgerDigest": release["contentDigest"],
        "trustedSignerKeyIds": list(signer_keys),
        "receiptCounts": {
            "operational": len(operations),
            "reviews": len(reviews),
            "launchGates": len(gates),
        },
        "sourceBindings": {
            "expectedCommit": True,
            "artifactManifest": True,
            "claimsRegister": True,
            "trustPolicyPinned": True,
            "protocol": True,
            "evaluationReport": True,
            "registryReadiness": True,
            "signedEvidence": True,
        },
        "gateReceipts": {
            gate.value: {
                "present": gate in gates,
                "passed": gate in gates and gates[gate].passed,
                "receiptDigest": gates[gate].digest if gate in gates else None,
            }
            for gate in LaunchGate
        },
        "status": release["status"],
        "tagOrPublishAllowed": release["tagOrPublishAllowed"],
        "automaticPublishPerformed": False,
        "claims": {
            "allEvidenceRecomputed": True,
            "signaturesProveTrustedKeyPossession": True,
            "reviewerIdentityLegallyVerifiedBySova": False,
            "universalSecurityEstablished": False,
            "allVulnerabilitiesFound": False,
            "perfectIsolationEstablished": False,
        },
    }
    dossier["contentDigest"] = sha256_digest(canonical_json_bytes(dossier))
    validate_document(dossier, "sova.launch-dossier")
    return dossier


__all__ = [
    "LAUNCH_EVIDENCE_PAYLOAD_TYPE",
    "LaunchEvidenceBundle",
    "LaunchGate",
    "LaunchGateReceipt",
    "LaunchRole",
    "LaunchTrustPolicy",
    "TrustedLaunchPrincipal",
    "assemble_launch_bundle",
    "evaluate_launch_bundle",
    "launch_bundle_from_mapping",
    "launch_gate_receipt_from_mapping",
    "observation_ledger_from_mapping",
    "operational_receipt_from_mapping",
    "protocol_from_mapping",
    "read_launch_bundle",
    "registry_policy_from_mapping",
    "release_candidate_from_mapping",
    "review_receipt_from_mapping",
    "sign_launch_evidence",
    "trust_policy_from_mapping",
]
