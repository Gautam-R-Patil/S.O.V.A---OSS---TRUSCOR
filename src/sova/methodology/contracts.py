# SPDX-License-Identifier: Apache-2.0
"""Strict native contracts for security playbooks and methodology policy."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache
from typing import Any, TypeVar
from urllib.parse import urlparse

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.intake import InputKind, ProfileTargetKind  # noqa: TC001 - parsed at runtime

PLAYBOOK_SCHEMA_VERSION = "0.1.0"
POLICY_SCHEMA_VERSION = "0.1.0"
OBSERVATION_SCHEMA_VERSION = "0.1.0"
PLAN_SCHEMA_VERSION = "0.1.0"
LIBRARY_SCHEMA_VERSION = "0.1.0"
SUBMISSION_SCHEMA_VERSION = "0.1.0"

_PLAYBOOK_ID = re.compile(r"^sova\.playbook\.[a-z0-9][a-z0-9.-]{0,150}$")
_SAFE_ID = re.compile(r"^[a-z0-9][a-z0-9._:/-]{0,190}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SECRET_VALUE = re.compile(
    r"(?:-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|"
    r"\b(?:Bearer|Basic)\s+[A-Za-z0-9+/_.=-]{8,}|"
    r"\bsk-[A-Za-z0-9_-]{20,}|\bgh[pousr]_[A-Za-z0-9_]{20,}|"
    r"\bxox[baprs]-[A-Za-z0-9-]{20,}|\bAKIA[A-Z0-9]{16}\b)",
    re.IGNORECASE,
)
_MAX_TEXT = 4096
_CONTROL_CHARACTER_LIMIT = 0x20
_MAX_EVIDENCE_ITEMS = 1000
_MAX_RISK_SCORE = 5
_MAX_BUDGET_UNITS = 10_000_000
_T = TypeVar("_T")
_E = TypeVar("_E", bound=StrEnum)


class MethodologyDomain(StrEnum):
    WEB = "web"
    API = "api"
    NETWORK_HOST_CLOUD = "network-host-cloud"
    SOURCE_PACKAGE_BINARY = "source-package-binary"
    AI_MODEL = "ai-model"
    AGENTIC = "agentic"


class MethodologyPhase(StrEnum):
    DISCOVERY = "discovery"
    HYPOTHESIS = "hypothesis"
    CONFIRMATION = "confirmation"
    REPRODUCTION = "reproduction"
    REMEDIATION_VALIDATION = "remediation-validation"
    REPORTING = "reporting"


PHASE_ORDER = tuple(MethodologyPhase)


class EffectClass(StrEnum):
    OBSERVE = "observe"
    READ_TARGET = "read-target"
    AUTHENTICATE = "authenticate"
    MUTATE_REVERSIBLE = "mutate-reversible"
    CONSUME_BOUNDED_RESOURCE = "consume-bounded-resource"
    EXECUTE_CONTAINED_CODE = "execute-contained-code"
    INTERACT_THIRD_PARTY = "interact-third-party"
    WRITE_TARGET = "write-target"
    DESTRUCTIVE = "destructive"


class OracleKind(StrEnum):
    SPECIFICATION = "specification"
    INVARIANT = "invariant"
    DIFFERENTIAL = "differential"
    METAMORPHIC = "metamorphic"
    STATE_EFFECT = "state-effect"
    LOG = "log"
    HUMAN_ACCEPTANCE = "human-acceptance"
    NO_RELIABLE_ORACLE = "no-reliable-oracle"


class SchedulerKind(StrEnum):
    IDENTIFIER_BASELINE = "identifier-baseline"
    RISK_FIRST_BASELINE = "risk-first-baseline"
    EVIDENCE_GAP_BALANCED = "evidence-gap-balanced"


class ObservationOutcome(StrEnum):
    OBSERVED = "observed"
    NOT_OBSERVED = "not-observed"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"
    INFRASTRUCTURE_FAILURE = "infrastructure-failure"


def _text(value: str, *, role: str, allow_empty: bool = False) -> str:
    if (
        (not value and not allow_empty)
        or len(value) > _MAX_TEXT
        or any(ord(character) < _CONTROL_CHARACTER_LIMIT for character in value)
    ):
        raise FormatError("SOVA-PLAYBOOK-TEXT", f"{role} is invalid")
    if _SECRET_VALUE.search(value):
        raise FormatError("SOVA-PLAYBOOK-SECRET", f"{role} contains secret-shaped material")
    return value


def _identifier(value: str, *, role: str) -> str:
    if _SAFE_ID.fullmatch(value) is None:
        raise FormatError("SOVA-PLAYBOOK-ID", f"{role} identifier is invalid")
    return value


def _digest(value: str, *, role: str) -> str:
    if _DIGEST.fullmatch(value) is None:
        raise FormatError("SOVA-METHODOLOGY-DIGEST", f"{role} must use SHA-256")
    return value


def _unique(values: tuple[_T, ...], *, role: str, allow_empty: bool = False) -> None:
    if (not values and not allow_empty) or len(values) != len(set(values)):
        raise FormatError("SOVA-PLAYBOOK-SET", f"{role} must be unique and non-empty")


@dataclass(frozen=True, slots=True)
class TargetPredicate:
    any_target_kinds: tuple[ProfileTargetKind, ...]
    required_surface_kinds: tuple[str, ...] = ()
    required_input_kinds: tuple[InputKind, ...] = ()

    def __post_init__(self) -> None:
        _unique(self.any_target_kinds, role="target kinds")
        _unique(self.required_surface_kinds, role="surface kinds", allow_empty=True)
        _unique(self.required_input_kinds, role="input kinds", allow_empty=True)
        for item in self.required_surface_kinds:
            _identifier(item, role="surface kind")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "anyTargetKinds": [item.value for item in self.any_target_kinds],
            "requiredSurfaceKinds": list(self.required_surface_kinds),
            "requiredInputKinds": [item.value for item in self.required_input_kinds],
        }


@dataclass(frozen=True, slots=True)
class Prerequisite:
    identifier: str
    description: str
    kind: str
    required: bool = True

    def __post_init__(self) -> None:
        _identifier(self.identifier, role="prerequisite")
        _identifier(self.kind, role="prerequisite kind")
        _text(self.description, role="prerequisite description")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "id": self.identifier,
            "description": self.description,
            "kind": self.kind,
            "required": self.required,
        }


@dataclass(frozen=True, slots=True)
class Technique:
    summary: str
    procedure: tuple[str, ...]
    safety_notes: tuple[str, ...]

    def __post_init__(self) -> None:
        _text(self.summary, role="technique summary")
        _unique(self.procedure, role="technique procedure")
        _unique(self.safety_notes, role="technique safety notes")
        for item in (*self.procedure, *self.safety_notes):
            _text(item, role="technique step")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "procedure": list(self.procedure),
            "safetyNotes": list(self.safety_notes),
        }


@dataclass(frozen=True, slots=True)
class ToolRequirement:
    capability: str
    optional: bool
    candidate_adapters: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _identifier(self.capability, role="tool capability")
        _unique(self.candidate_adapters, role="candidate adapters", allow_empty=True)
        for item in self.candidate_adapters:
            _identifier(item, role="candidate adapter")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "capability": self.capability,
            "optional": self.optional,
            "candidateAdapters": list(self.candidate_adapters),
        }


@dataclass(frozen=True, slots=True)
class PlaybookVariant:
    identifier: str
    condition: str
    procedure_delta: tuple[str, ...]
    additional_effects: tuple[EffectClass, ...] = ()

    def __post_init__(self) -> None:
        _identifier(self.identifier, role="variant")
        _text(self.condition, role="variant condition")
        _unique(self.procedure_delta, role="variant procedure")
        _unique(self.additional_effects, role="variant effects", allow_empty=True)
        for item in self.procedure_delta:
            _text(item, role="variant procedure")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "id": self.identifier,
            "condition": self.condition,
            "procedureDelta": list(self.procedure_delta),
            "additionalEffects": [item.value for item in self.additional_effects],
        }


@dataclass(frozen=True, slots=True)
class OracleProposal:
    kind: OracleKind
    statement: str
    positive_signal: str
    negative_signal: str
    ambiguous_state: str
    calibration_status: str = "unvalidated-proposal"

    def __post_init__(self) -> None:
        for role, value in (
            ("oracle statement", self.statement),
            ("oracle positive signal", self.positive_signal),
            ("oracle negative signal", self.negative_signal),
            ("oracle ambiguous state", self.ambiguous_state),
        ):
            _text(value, role=role)
        if self.calibration_status != "unvalidated-proposal":
            raise FormatError(
                "SOVA-PLAYBOOK-ORACLE",
                "P2 playbooks can contain only unvalidated oracle proposals",
            )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "statement": self.statement,
            "positiveSignal": self.positive_signal,
            "negativeSignal": self.negative_signal,
            "ambiguousState": self.ambiguous_state,
            "calibrationStatus": self.calibration_status,
        }


@dataclass(frozen=True, slots=True)
class EvidenceRequirement:
    kind: str
    minimum: int
    independent: bool
    decisive: bool

    def __post_init__(self) -> None:
        _identifier(self.kind, role="evidence kind")
        if self.minimum < 1 or self.minimum > _MAX_EVIDENCE_ITEMS:
            raise FormatError("SOVA-PLAYBOOK-EVIDENCE", "evidence minimum is invalid")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "minimum": self.minimum,
            "independent": self.independent,
            "decisive": self.decisive,
        }


@dataclass(frozen=True, slots=True)
class StopRule:
    condition: str
    action: str

    def __post_init__(self) -> None:
        _text(self.condition, role="stop condition")
        _text(self.action, role="stop action")

    def to_mapping(self) -> dict[str, str]:
        return {"condition": self.condition, "action": self.action}


@dataclass(frozen=True, slots=True)
class CleanupStep:
    action: str
    verification: str
    required: bool

    def __post_init__(self) -> None:
        _text(self.action, role="cleanup action")
        _text(self.verification, role="cleanup verification")

    def to_mapping(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "verification": self.verification,
            "required": self.required,
        }


@dataclass(frozen=True, slots=True)
class FrameworkMapping:
    framework: str
    catalog_version: str
    identifier: str
    title: str
    relationship: str
    url: str
    license_expression: str

    def __post_init__(self) -> None:
        for role, value in (
            ("framework", self.framework),
            ("catalog version", self.catalog_version),
            ("mapping identifier", self.identifier),
            ("mapping title", self.title),
            ("mapping license", self.license_expression),
        ):
            _text(value, role=role)
        if self.relationship not in {"equivalent", "broader", "narrower", "related"}:
            raise FormatError("SOVA-PLAYBOOK-MAPPING", "mapping relationship is invalid")
        parsed = urlparse(self.url)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username is not None:
            raise FormatError("SOVA-PLAYBOOK-MAPPING", "mapping requires an HTTPS URL")

    def to_mapping(self) -> dict[str, str]:
        return {
            "framework": self.framework,
            "catalogVersion": self.catalog_version,
            "identifier": self.identifier,
            "title": self.title,
            "relationship": self.relationship,
            "url": self.url,
            "license": self.license_expression,
        }


@dataclass(frozen=True, slots=True)
class EvidenceLimits:
    limitations: tuple[str, ...]
    false_positive_risks: tuple[str, ...]
    false_negative_risks: tuple[str, ...]

    def __post_init__(self) -> None:
        for role, values in (
            ("evidence limitations", self.limitations),
            ("false-positive risks", self.false_positive_risks),
            ("false-negative risks", self.false_negative_risks),
        ):
            _unique(values, role=role)
            for item in values:
                _text(item, role=role)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "limitations": list(self.limitations),
            "falsePositiveRisks": list(self.false_positive_risks),
            "falseNegativeRisks": list(self.false_negative_risks),
        }


@dataclass(frozen=True, slots=True)
class PlaybookProvenance:
    origin: str
    authors: tuple[str, ...]
    license_expression: str
    third_party_prose_copied: bool = False
    third_party_dataset_included: bool = False

    def __post_init__(self) -> None:
        if self.origin not in {"sova-native", "community"}:
            raise FormatError("SOVA-PLAYBOOK-PROVENANCE", "playbook origin is unsupported")
        _unique(self.authors, role="playbook authors")
        for author in self.authors:
            _text(author, role="playbook author")
        _text(self.license_expression, role="playbook license")
        if self.third_party_prose_copied or self.third_party_dataset_included:
            raise FormatError(
                "SOVA-PLAYBOOK-LICENSE-BOUNDARY",
                "portable native playbooks cannot embed third-party prose or datasets",
            )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "origin": self.origin,
            "authors": list(self.authors),
            "license": self.license_expression,
            "thirdPartyProseCopied": self.third_party_prose_copied,
            "thirdPartyDatasetIncluded": self.third_party_dataset_included,
        }


@dataclass(frozen=True, slots=True)
class Playbook:
    identifier: str
    version: str
    domain: MethodologyDomain
    title: str
    objective: str
    target_predicate: TargetPredicate
    depends_on: tuple[str, ...]
    prerequisites: tuple[Prerequisite, ...]
    discovery_inputs: tuple[InputKind, ...]
    technique: Technique
    allowed_effects: tuple[EffectClass, ...]
    tool_requirements: tuple[ToolRequirement, ...]
    variants: tuple[PlaybookVariant, ...]
    oracle_proposal: OracleProposal
    required_evidence: tuple[EvidenceRequirement, ...]
    stop_rules: tuple[StopRule, ...]
    cleanup: tuple[CleanupStep, ...]
    mappings: tuple[FrameworkMapping, ...]
    evidence_limits: EvidenceLimits
    severity: int
    likelihood: int
    base_cost: int
    tags: tuple[str, ...]
    provenance: PlaybookProvenance

    def __post_init__(self) -> None:
        if _PLAYBOOK_ID.fullmatch(self.identifier) is None:
            raise FormatError("SOVA-PLAYBOOK-ID", "playbook identifier is invalid")
        if _VERSION.fullmatch(self.version) is None:
            raise FormatError("SOVA-PLAYBOOK-VERSION", "playbook version is invalid")
        _text(self.title, role="playbook title")
        _text(self.objective, role="playbook objective")
        for role, values in (
            ("playbook dependencies", self.depends_on),
            ("playbook prerequisites", self.prerequisites),
            ("discovery inputs", self.discovery_inputs),
            ("allowed effects", self.allowed_effects),
            ("tool requirements", self.tool_requirements),
            ("variants", self.variants),
            ("required evidence", self.required_evidence),
            ("stop rules", self.stop_rules),
            ("cleanup", self.cleanup),
            ("mappings", self.mappings),
            ("tags", self.tags),
        ):
            _unique(values, role=role, allow_empty=role in {"playbook dependencies", "variants"})
        if self.identifier in self.depends_on:
            raise FormatError("SOVA-PLAYBOOK-DEPENDENCY", "playbook cannot depend on itself")
        if not set(self.discovery_inputs).issuperset(self.target_predicate.required_input_kinds):
            raise FormatError(
                "SOVA-PLAYBOOK-DISCOVERY",
                "required predicate inputs must be listed as discovery inputs",
            )
        if not 1 <= self.severity <= _MAX_RISK_SCORE or not 1 <= self.likelihood <= _MAX_RISK_SCORE:
            raise FormatError("SOVA-PLAYBOOK-RISK", "risk scores must be integers in [1, 5]")
        if self.base_cost < 1 or self.base_cost > _MAX_EVIDENCE_ITEMS:
            raise FormatError("SOVA-PLAYBOOK-COST", "base cost is outside the supported range")
        for tag in self.tags:
            _identifier(tag, role="playbook tag")

    @property
    def digest(self) -> str:
        return _playbook_digest(self)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.playbook",
            "schemaVersion": PLAYBOOK_SCHEMA_VERSION,
            "id": self.identifier,
            "version": self.version,
            "domain": self.domain.value,
            "title": self.title,
            "objective": self.objective,
            "targetPredicates": self.target_predicate.to_mapping(),
            "dependsOn": list(self.depends_on),
            "prerequisites": [item.to_mapping() for item in self.prerequisites],
            "discoveryInputs": [item.value for item in self.discovery_inputs],
            "technique": self.technique.to_mapping(),
            "allowedEffects": [item.value for item in self.allowed_effects],
            "toolRequirements": [item.to_mapping() for item in self.tool_requirements],
            "variants": [item.to_mapping() for item in self.variants],
            "oracleProposal": self.oracle_proposal.to_mapping(),
            "requiredEvidence": [item.to_mapping() for item in self.required_evidence],
            "stopRules": [item.to_mapping() for item in self.stop_rules],
            "cleanup": [item.to_mapping() for item in self.cleanup],
            "mappings": [item.to_mapping() for item in self.mappings],
            "evidenceLimits": self.evidence_limits.to_mapping(),
            "risk": {
                "severity": self.severity,
                "likelihood": self.likelihood,
                "baseCost": self.base_cost,
            },
            "tags": list(self.tags),
            "provenance": self.provenance.to_mapping(),
        }


@lru_cache(maxsize=4096)
def _playbook_digest(playbook: Playbook) -> str:
    return sha256_digest(canonical_json_bytes(playbook.to_mapping()))


@dataclass(frozen=True, slots=True)
class MethodologyPolicy:
    target_profile_digest: str
    max_budget_units: int
    phase_budgets: dict[MethodologyPhase, int]
    scheduler: SchedulerKind
    allowed_effects: tuple[EffectClass, ...]
    denied_playbooks: tuple[str, ...] = ()
    required_playbooks: tuple[str, ...] = ()
    human_approval_required: bool = True

    def __post_init__(self) -> None:
        _digest(self.target_profile_digest, role="target profile digest")
        if (
            self.max_budget_units < len(MethodologyPhase)
            or self.max_budget_units > _MAX_BUDGET_UNITS
        ):
            raise FormatError("SOVA-METHODOLOGY-BUDGET", "total budget is outside bounds")
        if set(self.phase_budgets) != set(MethodologyPhase):
            raise FormatError("SOVA-METHODOLOGY-BUDGET", "every phase requires a budget")
        if any(value < 0 or value > self.max_budget_units for value in self.phase_budgets.values()):
            raise FormatError("SOVA-METHODOLOGY-BUDGET", "phase budget is outside bounds")
        _unique(self.allowed_effects, role="policy effects")
        _unique(self.denied_playbooks, role="denied playbooks", allow_empty=True)
        _unique(self.required_playbooks, role="required playbooks", allow_empty=True)
        if set(self.denied_playbooks) & set(self.required_playbooks):
            raise FormatError("SOVA-METHODOLOGY-POLICY", "a playbook cannot be required and denied")
        if not self.human_approval_required:
            raise FormatError(
                "SOVA-METHODOLOGY-AUTHORITY", "effectful methodology requires human approval"
            )

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.methodology-policy",
            "schemaVersion": POLICY_SCHEMA_VERSION,
            "targetProfileDigest": self.target_profile_digest,
            "maxBudgetUnits": self.max_budget_units,
            "phaseBudgets": {phase.value: self.phase_budgets[phase] for phase in MethodologyPhase},
            "scheduler": self.scheduler.value,
            "allowedEffects": [item.value for item in self.allowed_effects],
            "deniedPlaybooks": list(self.denied_playbooks),
            "requiredPlaybooks": list(self.required_playbooks),
            "humanApprovalRequired": self.human_approval_required,
            "claims": {
                "executionAuthorized": False,
                "modelMayExpandAuthority": False,
                "policyMayExpandTargetScope": False,
            },
        }


@dataclass(frozen=True, slots=True)
class MethodologyObservation:
    playbook_id: str
    phase: MethodologyPhase
    outcome: ObservationOutcome
    evidence_digest: str
    target_generation_digest: str

    def __post_init__(self) -> None:
        if _PLAYBOOK_ID.fullmatch(self.playbook_id) is None:
            raise FormatError("SOVA-METHODOLOGY-OBSERVATION", "playbook ID is invalid")
        _digest(self.evidence_digest, role="observation evidence")
        _digest(self.target_generation_digest, role="target generation")

    def to_mapping(self) -> dict[str, str]:
        return {
            "playbookId": self.playbook_id,
            "phase": self.phase.value,
            "outcome": self.outcome.value,
            "evidenceDigest": self.evidence_digest,
            "targetGenerationDigest": self.target_generation_digest,
        }


@dataclass(frozen=True, slots=True)
class MethodologyObservationSet:
    target_profile_digest: str
    previous_plan_digest: str
    source_artifact_digests: tuple[str, ...]
    observations: tuple[MethodologyObservation, ...]

    def __post_init__(self) -> None:
        _digest(self.target_profile_digest, role="target profile")
        _digest(self.previous_plan_digest, role="previous plan")
        _unique(self.source_artifact_digests, role="source artifacts")
        for item in self.source_artifact_digests:
            _digest(item, role="source artifact")
        _unique(
            tuple((item.playbook_id, item.phase) for item in self.observations),
            role="observation identities",
            allow_empty=True,
        )

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.methodology-observations",
            "schemaVersion": OBSERVATION_SCHEMA_VERSION,
            "targetProfileDigest": self.target_profile_digest,
            "previousPlanDigest": self.previous_plan_digest,
            "sourceArtifactDigests": list(self.source_artifact_digests),
            "observations": [item.to_mapping() for item in self.observations],
            "claims": {"authorityGranted": False, "trustedContractsMutated": False},
        }


def methodology_policy_template(
    target_profile_digest: str,
    *,
    max_budget_units: int = 100_000,
    scheduler: SchedulerKind = SchedulerKind.EVIDENCE_GAP_BALANCED,
    allowed_effects: tuple[EffectClass, ...] = (
        EffectClass.OBSERVE,
        EffectClass.READ_TARGET,
        EffectClass.AUTHENTICATE,
        EffectClass.MUTATE_REVERSIBLE,
        EffectClass.CONSUME_BOUNDED_RESOURCE,
        EffectClass.EXECUTE_CONTAINED_CODE,
    ),
) -> MethodologyPolicy:
    per_phase = max_budget_units // len(MethodologyPhase)
    phase_budgets = dict.fromkeys(MethodologyPhase, per_phase)
    phase_budgets[MethodologyPhase.DISCOVERY] += max_budget_units - sum(phase_budgets.values())
    return MethodologyPolicy(
        target_profile_digest=target_profile_digest,
        max_budget_units=max_budget_units,
        phase_budgets=phase_budgets,
        scheduler=scheduler,
        allowed_effects=allowed_effects,
    )


def methodology_policy_from_mapping(value: dict[str, Any]) -> MethodologyPolicy:
    required = {
        "artifactType",
        "schemaVersion",
        "targetProfileDigest",
        "maxBudgetUnits",
        "phaseBudgets",
        "scheduler",
        "allowedEffects",
        "deniedPlaybooks",
        "requiredPlaybooks",
        "humanApprovalRequired",
        "claims",
    }
    if set(value) != required:
        raise FormatError("SOVA-METHODOLOGY-POLICY", "policy fields are missing or unknown")
    if (
        value.get("artifactType") != "sova.methodology-policy"
        or value.get("schemaVersion") != POLICY_SCHEMA_VERSION
    ):
        raise FormatError("SOVA-METHODOLOGY-POLICY", "policy version is unsupported")
    claims = value.get("claims")
    if claims != {
        "executionAuthorized": False,
        "modelMayExpandAuthority": False,
        "policyMayExpandTargetScope": False,
    }:
        raise FormatError("SOVA-METHODOLOGY-AUTHORITY", "policy claims are unsafe")
    phase_budgets = _required_mapping(value, "phaseBudgets")
    return MethodologyPolicy(
        target_profile_digest=_required_string(value, "targetProfileDigest"),
        max_budget_units=_required_int(value, "maxBudgetUnits"),
        phase_budgets={
            phase: _required_int(phase_budgets, phase.value) for phase in MethodologyPhase
        },
        scheduler=_enum_value(SchedulerKind, _required_string(value, "scheduler"), "scheduler"),
        allowed_effects=tuple(
            _enum_value(EffectClass, item, "effect")
            for item in _string_list(value, "allowedEffects")
        ),
        denied_playbooks=tuple(_string_list(value, "deniedPlaybooks")),
        required_playbooks=tuple(_string_list(value, "requiredPlaybooks")),
        human_approval_required=_required_bool(value, "humanApprovalRequired"),
    )


def observation_set_from_mapping(value: dict[str, Any]) -> MethodologyObservationSet:
    required = {
        "artifactType",
        "schemaVersion",
        "targetProfileDigest",
        "previousPlanDigest",
        "sourceArtifactDigests",
        "observations",
        "claims",
    }
    if set(value) != required:
        raise FormatError("SOVA-METHODOLOGY-OBSERVATION", "observation fields are invalid")
    if (
        value.get("artifactType") != "sova.methodology-observations"
        or value.get("schemaVersion") != OBSERVATION_SCHEMA_VERSION
        or value.get("claims") != {"authorityGranted": False, "trustedContractsMutated": False}
    ):
        raise FormatError("SOVA-METHODOLOGY-OBSERVATION", "observation contract is unsafe")
    rows = _mapping_list(value, "observations")
    observations = tuple(
        MethodologyObservation(
            playbook_id=_required_string(row, "playbookId"),
            phase=_enum_value(
                MethodologyPhase, _required_string(row, "phase"), "observation phase"
            ),
            outcome=_enum_value(
                ObservationOutcome, _required_string(row, "outcome"), "observation outcome"
            ),
            evidence_digest=_required_string(row, "evidenceDigest"),
            target_generation_digest=_required_string(row, "targetGenerationDigest"),
        )
        for row in rows
    )
    return MethodologyObservationSet(
        target_profile_digest=_required_string(value, "targetProfileDigest"),
        previous_plan_digest=_required_string(value, "previousPlanDigest"),
        source_artifact_digests=tuple(_string_list(value, "sourceArtifactDigests")),
        observations=observations,
    )


def _enum_value(enum_type: type[_E], value: str, role: str) -> _E:
    try:
        return enum_type(value)
    except ValueError as error:
        raise FormatError("SOVA-PLAYBOOK-ENUM", f"{role} is unsupported") from error


def _required_string(value: dict[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str):
        raise FormatError("SOVA-PLAYBOOK-FIELDS", f"{key} must be a string")
    return item


def _required_int(value: dict[str, Any], key: str) -> int:
    item = value.get(key)
    if not isinstance(item, int) or isinstance(item, bool):
        raise FormatError("SOVA-PLAYBOOK-FIELDS", f"{key} must be an integer")
    return item


def _required_bool(value: dict[str, Any], key: str) -> bool:
    item = value.get(key)
    if not isinstance(item, bool):
        raise FormatError("SOVA-PLAYBOOK-FIELDS", f"{key} must be a boolean")
    return item


def _required_mapping(value: dict[str, Any], key: str) -> dict[str, Any]:
    item = value.get(key)
    if not isinstance(item, dict):
        raise FormatError("SOVA-PLAYBOOK-FIELDS", f"{key} must be an object")
    return item


def _string_list(value: dict[str, Any], key: str) -> list[str]:
    item = value.get(key)
    if not isinstance(item, list) or any(not isinstance(child, str) for child in item):
        raise FormatError("SOVA-PLAYBOOK-FIELDS", f"{key} must be a string array")
    return item


def _mapping_list(value: dict[str, Any], key: str) -> list[dict[str, Any]]:
    item = value.get(key)
    if not isinstance(item, list) or any(not isinstance(child, dict) for child in item):
        raise FormatError("SOVA-PLAYBOOK-FIELDS", f"{key} must be an object array")
    return item


__all__ = [
    "LIBRARY_SCHEMA_VERSION",
    "OBSERVATION_SCHEMA_VERSION",
    "PHASE_ORDER",
    "PLAN_SCHEMA_VERSION",
    "PLAYBOOK_SCHEMA_VERSION",
    "POLICY_SCHEMA_VERSION",
    "SUBMISSION_SCHEMA_VERSION",
    "CleanupStep",
    "EffectClass",
    "EvidenceLimits",
    "EvidenceRequirement",
    "FrameworkMapping",
    "MethodologyDomain",
    "MethodologyObservation",
    "MethodologyObservationSet",
    "MethodologyPhase",
    "MethodologyPolicy",
    "ObservationOutcome",
    "OracleKind",
    "OracleProposal",
    "Playbook",
    "PlaybookProvenance",
    "PlaybookVariant",
    "Prerequisite",
    "SchedulerKind",
    "StopRule",
    "TargetPredicate",
    "Technique",
    "ToolRequirement",
    "methodology_policy_from_mapping",
    "methodology_policy_template",
    "observation_set_from_mapping",
]
