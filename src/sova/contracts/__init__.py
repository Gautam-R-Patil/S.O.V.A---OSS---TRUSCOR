# SPDX-License-Identifier: Apache-2.0
"""Versioned public domain contracts for SOVA OSS."""

from sova.contracts.coverage import (
    BudgetLimit,
    BudgetUnit,
    CoverageDimension,
    DimensionCoverage,
    ExplorationRecord,
    ObservedCoverage,
    StoppingReason,
)
from sova.contracts.errors import ContractError
from sova.contracts.identifiers import (
    ExternalReference,
    IdentifierKind,
    ReferenceRelationship,
    StableIdentifier,
    new_stable_identifier,
)
from sova.contracts.lifecycle import (
    AdjudicationState,
    DisclosureState,
    EvidenceState,
    LifecycleAxis,
    RecordState,
    RemediationState,
    allowed_transitions,
    require_transition,
)
from sova.contracts.taxonomy import (
    AttackTaxonomy,
    ExternalMapping,
    MappingRelationship,
    Taxon,
    TaxonStatus,
    load_attack_taxonomy,
)
from sova.contracts.versions import (
    AbsenceReason,
    ContentDigest,
    ExplicitAbsence,
    FingerprintedReference,
    InterpretationContext,
    ModelReference,
    SemanticVersion,
    VersionedReference,
)
from sova.contracts.vocabulary import AssertionBasis, ComponentKind, ProfileKind, SeverityBand

__contract_version__ = "0.1.0"

__all__ = [
    "AbsenceReason",
    "AdjudicationState",
    "AssertionBasis",
    "AttackTaxonomy",
    "BudgetLimit",
    "BudgetUnit",
    "ComponentKind",
    "ContentDigest",
    "ContractError",
    "CoverageDimension",
    "DimensionCoverage",
    "DisclosureState",
    "EvidenceState",
    "ExplicitAbsence",
    "ExplorationRecord",
    "ExternalMapping",
    "ExternalReference",
    "FingerprintedReference",
    "IdentifierKind",
    "InterpretationContext",
    "LifecycleAxis",
    "MappingRelationship",
    "ModelReference",
    "ObservedCoverage",
    "ProfileKind",
    "RecordState",
    "ReferenceRelationship",
    "RemediationState",
    "SemanticVersion",
    "SeverityBand",
    "StableIdentifier",
    "StoppingReason",
    "Taxon",
    "TaxonStatus",
    "VersionedReference",
    "__contract_version__",
    "allowed_transitions",
    "load_attack_taxonomy",
    "new_stable_identifier",
    "require_transition",
]
